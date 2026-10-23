"""Activation, supersession, rollback, revocation and tenant pinning: the OPA bundle lifecycle for packs.

OPA activates a bundle only after it verifies and *keeps the previous valid bundle* when activation
fails; the research makes that "atomic activation; last-known-good rollback; status evidence" and
gate 6 asks for "atomic install, activation, supersession, revocation, rollback and tenant pinning".
Installation (``registry``) verifies; this ledger records which installed version is ACTIVE for a
pack id, supersedes the previous one, rolls back to it, revokes a version (with automatic fallback
to the last non-revoked activation), and pins a tenant to a version. Every activation has an id
that decision receipts carry (gate 9), so an auditor can tell which activation authorized a release.

This class is the local in-memory implementation. ``lifecycle_pg.PostgresActivationLedger``
persists the same transitions for managed, multi-instance deployments.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any

from regulated_core.governance_guard import GovernanceGuard

STATES = ("active", "superseded", "rolled-back", "revoked")


class LifecycleError(RuntimeError):
    """An activation, rollback, revocation or pin was refused; the message says why."""


GovernanceReceipt = tuple[str, str, str, str]


def governance_receipt_key(receipt: GovernanceReceipt) -> GovernanceReceipt:
    if (not isinstance(receipt, (tuple, list)) or len(receipt) != 4
            or any(not isinstance(part, str) or not part for part in receipt)
            or re.fullmatch(r"[0-9a-f]{64}", receipt[3]) is None):
        raise LifecycleError("governance receipt must bind tenant, operation, nonce and SHA256 change digest")
    return receipt[0], receipt[1], receipt[2], receipt[3]


DependencyRequirements = tuple[tuple[str, str], ...]


def dependency_requirements(pack_id: str, requirements: DependencyRequirements) -> DependencyRequirements:
    """Freeze an unambiguous dependency set before locking or reading authority."""
    seen: set[str] = {pack_id}
    out: list[tuple[str, str]] = []
    for item in requirements:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise LifecycleError("dependency must name an exact reference and digest")
        reference, digest = item
        if not isinstance(reference, str) or reference.count("#") != 1:
            raise LifecycleError("dependency must name an exact reference")
        ident, version = reference.split("#")
        if not ident or not version or ident in seen:
            raise LifecycleError("dependency identities must be nonempty, unique and exclude the target")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LifecycleError("dependency must pin a SHA256 digest")
        seen.add(ident)
        out.append((reference, digest))
    return tuple(sorted(out))


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    activation_id: str
    pack_id: str
    version: str
    pack_digest: str
    state: str
    activated_at: str
    previous_activation_id: str = ""
    reason: str = ""

    @property
    def reference(self) -> str:
        return f"{self.pack_id}#{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {"activation_id": self.activation_id, "pack": self.reference, "pack_digest": self.pack_digest,
                "state": self.state, "activated_at": self.activated_at, "previous_activation_id": self.previous_activation_id,
                "reason": self.reason}


class ActivationLedger:
    durable = False

    def __init__(self, *, guard: GovernanceGuard | None = None) -> None:
        self._governance_guard = guard
        self._lock = RLock()
        self._records: dict[str, ActivationRecord] = {}
        self._history: dict[str, list[str]] = {}
        self._active: dict[str, str] = {}
        self._revoked: set[str] = set()
        self._pins: dict[tuple[str, str], str] = {}
        self._governance_receipts: dict[str, set[GovernanceReceipt]] = {}

    @property
    def governance_guard(self) -> GovernanceGuard | None:
        """The receiving authority installed by trusted host composition, never by a request."""
        return self._governance_guard

    def _require_governance(self, pack_id: str) -> None:
        if self._governance_guard is not None:
            self._governance_guard.require("pack-activation", pack_id)

    # -- reads ------------------------------------------------------------------------------------------

    def pack_ids(self) -> tuple[str, ...]:
        """Every pack this ledger holds any lifecycle or pin state for, whether or not it is still deployed."""
        with self._lock:
            return tuple(sorted(set(self._history) | set(self._active) | {pack for (_, pack) in self._pins}))

    def active(self, pack_id: str) -> ActivationRecord | None:
        with self._lock:
            ident = self._active.get(pack_id)
            return None if ident is None else self._records[ident]

    def governance_receipt(self, pack_id: str, receipt: GovernanceReceipt) -> bool:
        key = governance_receipt_key(receipt)
        with self._lock:
            return key in self._governance_receipts.get(pack_id, set())

    def history(self, pack_id: str) -> tuple[ActivationRecord, ...]:
        with self._lock:
            return tuple(self._records[i] for i in self._history.get(pack_id, ()))

    def is_revoked(self, pack_id: str, version: str) -> bool:
        with self._lock:
            return f"{pack_id}#{version}" in self._revoked

    def pinned(self, tenant_id: str, pack_id: str) -> str | None:
        with self._lock:
            return self._pins.get((tenant_id, pack_id))

    def resolve(self, tenant_id: str, pack_id: str) -> str | None:
        """The version a tenant runs: its pin if it has one and that version is not revoked, else the active."""
        with self._lock:
            pin = self._pins.get((tenant_id, pack_id))
            if pin is not None:
                return None if self.is_revoked(pack_id, pin) else pin
            active = self.active(pack_id)
            return None if active is None else active.version

    def resolve_record(self, tenant_id: str, pack_id: str) -> ActivationRecord | None:
        """Resolve the exact tenant activation under one lock, so receipt pins cannot mix versions."""
        with self._lock:
            version = self.resolve(tenant_id, pack_id)
            if version is None:
                return None
            for ident in reversed(self._history.get(pack_id, ())):
                record = self._records[ident]
                if record.version == version and not self.is_revoked(pack_id, version):
                    return record
            return None

    @contextmanager
    def resolution_guard(self, tenant_id: str, pack_id: str, *, required_base_reference: str | None = None,
                         required_dependencies: DependencyRequirements = ()) -> Iterator[ActivationRecord | None]:
        """Hold activation stable while a short local authority operation executes."""
        dependencies = dependency_requirements(pack_id, required_dependencies)
        with self._lock:
            valid = self._base_matches(required_base_reference) and self._dependencies_match(dependencies, tenant_id)
            yield self.resolve_record(tenant_id, pack_id) if valid else None

    def _dependencies_match(self, dependencies: DependencyRequirements, tenant_id: str | None = None) -> bool:
        for reference, digest in dependencies:
            ident = reference.partition("#")[0]
            record = self.active(ident) if tenant_id is None else self.resolve_record(tenant_id, ident)
            if record is None or record.reference != reference or record.pack_digest != digest:
                return False
        return True

    def _base_matches(self, reference: str | None) -> bool:
        if reference is None:
            return True
        base = self.active(reference.partition("#")[0])
        return base is not None and base.reference == reference

    # -- writes -----------------------------------------------------------------------------------------

    def _record(self, pack_id: str, version: str, digest: str, at: str, previous: str, reason: str) -> ActivationRecord:
        ordinal = len(self._history.get(pack_id, ()))
        ident = hashlib.sha256(f"{pack_id}#{version}|{digest}|{previous}|{ordinal}".encode()).hexdigest()[:24]
        record = ActivationRecord(ident, pack_id, version, digest, "active", at, previous, reason)
        self._records[ident] = record
        self._history.setdefault(pack_id, []).append(ident)
        self._active[pack_id] = ident
        return record

    def _retire(self, pack_id: str, state: str) -> ActivationRecord | None:
        current = self.active(pack_id)
        if current is None:
            return None
        retired = replace(current, state=state)
        self._records[current.activation_id] = retired
        self._active.pop(pack_id, None)
        return retired

    def activate(self, pack_id: str, version: str, pack_digest: str, *, at: str, reason: str = "",
                 expected_activation_id: str | None = None, required_base_reference: str | None = None,
                 required_dependencies: DependencyRequirements = (), approved_prior: str | None = None,
                 before_commit: Callable[[], None] | None = None,
                 receipt: GovernanceReceipt | None = None, first_state_only: bool = False) -> ActivationRecord:
        """Apply the approved prior and final authority check under the receiving lock.

        `first_state_only` (a signed bootstrap) refuses unless the pack has NO activation history at all, checked here
        under the lock against durable history, never current availability: a revoked pack has history.

        The callback is supplied by trusted composition, never deserialized from
        a change request. Legacy offline callers may omit both governance inputs.
        """
        self._require_governance(pack_id)
        dependencies = dependency_requirements(pack_id, required_dependencies)
        key = None if receipt is None else governance_receipt_key(receipt)
        with self._lock:
            if key is not None and any(existing[:3] == key[:3]
                                       for existing in self._governance_receipts.get(pack_id, set())):
                raise LifecycleError("governance operation already received; recover its exact receipt")
            if not self._base_matches(required_base_reference):
                raise LifecycleError("required base is not active")
            if not self._dependencies_match(dependencies):
                raise LifecycleError("required dependency is not active at its pinned digest")
            if self.is_revoked(pack_id, version):
                raise LifecycleError(f"{pack_id}#{version} is revoked and cannot be activated")
            if any(r.version == version and r.pack_digest != pack_digest for r in self.history(pack_id)):
                raise LifecycleError(f"{pack_id}#{version}: a version cannot change its digest")
            if first_state_only and self._history.get(pack_id):
                raise LifecycleError(f"{pack_id} has activation history; a bootstrap installs only a first-ever state")
            current = self.active(pack_id)
            self._check_expected(current, expected_activation_id, self.history(pack_id))
            if approved_prior is not None and approved_prior != ("absent" if current is None else current.reference):
                raise LifecycleError("activation differs from approved prior state")
            if before_commit is not None:
                before_commit()
            if current is not None and current.version == version and current.pack_digest == pack_digest:
                result = current
            else:
                previous = "" if current is None else current.activation_id
                self._retire(pack_id, "superseded")
                result = self._record(pack_id, version, pack_digest, at, previous, reason)
            if key is not None:
                self._governance_receipts.setdefault(pack_id, set()).add(key)
            return result

    def _governed_prior(self, pack_id: str, prior: str, approved_prior: str | None,
                        receipt: GovernanceReceipt | None) -> GovernanceReceipt | None:
        """Validate a receiving transition while its lifecycle lock is held."""
        key = None if receipt is None else governance_receipt_key(receipt)
        if key is not None and any(existing[:3] == key[:3]
                                  for existing in self._governance_receipts.get(pack_id, set())):
            raise LifecycleError("governance operation already received; recover its exact receipt")
        if approved_prior is not None and approved_prior != prior:
            raise LifecycleError("lifecycle differs from approved prior state")
        return key

    def _received(self, pack_id: str, key: GovernanceReceipt | None) -> None:
        if key is not None:
            self._governance_receipts.setdefault(pack_id, set()).add(key)

    def rollback(self, pack_id: str, *, at: str, reason: str, expected_activation_id: str | None = None,
                 expected_target_reference: str | None = None, approved_prior: str | None = None,
                 before_commit: Callable[[], None] | None = None,
                 receipt: GovernanceReceipt | None = None) -> ActivationRecord:
        """Re-activate the last non-revoked activation under the exact reviewed prior and target."""
        self._require_governance(pack_id)
        with self._lock:
            current = self.active(pack_id)
            self._check_expected(current, expected_activation_id, self.history(pack_id))
            if current is None:
                raise LifecycleError(f"{pack_id}: nothing is active to roll back from")
            target = self._last_good_before(pack_id, current.activation_id)
            if target is None:
                raise LifecycleError(f"{pack_id}: no earlier non-revoked activation to roll back to")
            if expected_target_reference is not None and target.reference != expected_target_reference:
                raise LifecycleError("rollback target changed; revalidate collection compatibility")
            key = self._governed_prior(pack_id, current.reference, approved_prior, receipt)
            if before_commit is not None:
                before_commit()
            self._retire(pack_id, "rolled-back")
            result = self._record(pack_id, target.version, target.pack_digest, at, current.activation_id, reason)
            self._received(pack_id, key)
            return result

    def revoke(self, pack_id: str, version: str, *, at: str, reason: str,
               fallback_reference: str | None = None, expected_activation_id: str | None = None,
               approved_prior: str | None = None, before_commit: Callable[[], None] | None = None,
               receipt: GovernanceReceipt | None = None) -> tuple[ActivationRecord | None, ActivationRecord | None]:
        """Withdraw a version and record its receiving receipt in the same critical section."""
        self._require_governance(pack_id)
        with self._lock:
            current = self.active(pack_id)
            target = None if current is None else self._last_good_before(
                pack_id, current.activation_id, excluding_version=version)
            key = self._governed_prior(pack_id, "absent" if current is None else current.reference,
                                       approved_prior, receipt)
            if before_commit is not None:
                before_commit()
            self._revoked.add(f"{pack_id}#{version}")
            if current is None or current.version != version:
                self._received(pack_id, key)
                return None, current
            revoked = self._retire(pack_id, "revoked")
            if revoked is not None:
                revoked = replace(revoked, reason=reason)
                self._records[revoked.activation_id] = revoked
            if (target is None or (fallback_reference is not None and target.reference != fallback_reference)
                    or (expected_activation_id is not None and current.activation_id != expected_activation_id)):
                self._received(pack_id, key)
                return revoked, None
            result = self._record(pack_id, target.version, target.pack_digest, at, current.activation_id,
                                  f"fallback after revocation: {reason}")
            self._received(pack_id, key)
            return revoked, result

    def _last_good_before(self, pack_id: str, activation_id: str, *,
                          excluding_version: str | None = None) -> ActivationRecord | None:
        ids = self._history.get(pack_id, [])
        for ident in reversed(ids[: ids.index(activation_id)] if activation_id in ids else ids):
            record = self._records[ident]
            if record.version != excluding_version and not self.is_revoked(pack_id, record.version):
                return record
        return None

    @staticmethod
    def _check_expected(current: ActivationRecord | None, expected: str | None,
                        history: tuple[ActivationRecord, ...] = ()) -> None:
        actual = "" if current is None else current.activation_id
        if current is None and expected is not None and expected.startswith("inactive:"):
            actual = "inactive:" + (history[-1].activation_id if history else "")
        if expected is not None and expected != actual:
            raise LifecycleError("active pack changed; revalidate collection compatibility")

    def pin(self, tenant_id: str, pack_id: str, version: str, *, expected_activation_id: str | None = None,
            approved_prior: str | None = None, before_commit: Callable[[], None] | None = None,
            receipt: GovernanceReceipt | None = None) -> None:
        self._require_governance(pack_id)
        with self._lock:
            self._check_expected(self.active(pack_id), expected_activation_id, self.history(pack_id))
            if self.is_revoked(pack_id, version):
                raise LifecycleError(f"{pack_id}#{version} is revoked; a tenant cannot be pinned to it")
            resolved = self.resolve_record(tenant_id, pack_id)
            prior = f"{tenant_id}:{resolved.reference if resolved is not None else 'absent'}"
            key = self._governed_prior(pack_id, prior, approved_prior, receipt)
            if before_commit is not None:
                before_commit()
            self._pins[(tenant_id, pack_id)] = version
            self._received(pack_id, key)

    def unpin(self, tenant_id: str, pack_id: str) -> None:
        self._require_governance(pack_id)
        with self._lock:
            self._pins.pop((tenant_id, pack_id), None)


__all__ = ["STATES", "ActivationLedger", "ActivationRecord", "LifecycleError"]
