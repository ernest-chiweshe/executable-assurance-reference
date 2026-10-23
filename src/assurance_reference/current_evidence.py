"""Re-read host evidence for each contextual check (v12 X-24).

Derived from the pinned original demonstration_surfaces custody wrapper; the
host supplies the allowed use identifiers instead of application demonstrations.
This check does not lock source custody through a later release.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from factory.packs.demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome


class EvidenceUnavailable(ValueError):
    """Host evidence is unavailable; request fields cannot supply a replacement."""


class HostEvidence(Protocol):
    def current(self, tenant: str, use: str, case_id: str) -> EvidenceSnapshot: ...


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


class CurrentSnapshotVerifier:
    """Read the configured host on every check, without caching accepted evidence.

    The source and allowed uses are trusted host composition inputs. Authentication
    must supply the EmissionContext; this wrapper does not authenticate callers.
    """

    def __init__(self, source: HostEvidence, use: str, *, allowed_uses: frozenset[str]) -> None:
        if (not isinstance(allowed_uses, frozenset) or not allowed_uses
                or any(not _identifier(item) for item in allowed_uses)
                or not _identifier(use) or use not in allowed_uses):
            raise ValueError("An explicitly allowed host evidence use is required")
        if not callable(getattr(source, "current", None)):
            raise ValueError("An explicit host evidence reader is required")
        self._source, self._use = source, use

    def _current(self, tenant: str, case_id: object) -> EvidenceSnapshot:
        if not _identifier(tenant) or not _identifier(case_id):
            raise EvidenceUnavailable("A tenant and existing reviewed case are required")
        try:
            snapshot = self._source.current(tenant, self._use, case_id)
        except Exception as exc:
            raise EvidenceUnavailable("The host-reviewed case is unavailable") from exc
        if (not isinstance(snapshot, EvidenceSnapshot)
                or (snapshot.tenant, snapshot.case_id) != (tenant, case_id)):
            raise EvidenceUnavailable("Host evidence does not match this tenant and case")
        return snapshot

    def __call__(self, draft: str, contract: Mapping[str, object]) -> tuple[Outcome, tuple[str, ...]]:
        return SnapshotVerifier(())(draft, contract)

    def verify_context(self, draft: str, contract: Mapping[str, object],
                       context: EmissionContext | None) -> tuple[Outcome, tuple[str, ...]]:
        if context is None:
            return self(draft, contract)
        try:
            snapshot = self._current(context.tenant, contract.get("case_id"))
        except EvidenceUnavailable:
            return SnapshotVerifier(()).verify_context(draft, contract, context)
        return SnapshotVerifier((snapshot,)).verify_context(draft, contract, context)
