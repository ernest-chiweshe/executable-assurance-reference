"""Who may govern: the governance roster, itself governance state (Paper A A09; owner ruling, ledger 3277).

Governance changes need two governance approvers from different reporting lines and an independent monitor's clearance
(regulated_core/tier4.py). Those facts must come from somewhere the approvers cannot quietly rewrite. The roster is
that source, and it is governed like everything else:

* its FIRST state is installed only by the deployment's signed first-state bootstrap (owner ruling option B: a genuine
  first state of a fresh installation, never a later change);
* every later change is a tier-4 governance change reviewed by the approvers of the CURRENT roster (option A), applied
  through the same receiving transaction, prior-state compare and receipt as any governance target;
* it names each member's governance roles and reporting line, and the monitor service's signing key ids;
* it carries an explicit `simulated` label. Test and rehearsal rosters say so, and a production composition refuses a
  simulated roster, fewer than two approvers on distinct reporting lines, or a monitor key that is unknown to the
  trust directory or shared with any signer the host itself holds: two accounts of one person, or a monitor the host
  can impersonate, are not independence.

From the roster the host derives the tier-4 reporting-line directory (`RosterDirectory`) and the credential authority
for governance reviewers (`RosterCredentials`), which signs a receipt only for an enrolled member actually holding the
requested role, bound to the exact roster it read.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Protocol

from .canonical import canonical_bytes
from .governance_guard import GovernanceGuard
from .governance_targets import (
    GOVERNANCE_ROLE, WITHDRAWAL_ROLE, FinalCheckRefused, GovernanceLog, GovernanceTarget, GovernedChange, change_bytes,
)
from .identity_provider import CredentialError, CredentialReceipt
from .permit import EmissionError, PermitUseStore
from .signing import Signature, Signer, TrustDirectory
from .target import ABSENT, Outcome, TargetAuthority

ROSTER_KIND = "governance-roster"
ROSTER_OPERATION = "governance:change-roster"
ROLES = frozenset({GOVERNANCE_ROLE, WITHDRAWAL_ROLE})
RECEIPT_TTL_US = 3_600 * 1_000_000


ATTESTATION_SCHEMA = "regulated/governance-enrolment-attestation/v1"


@dataclass(frozen=True, slots=True)
class RosterMember:
    subject_id: str
    roles: frozenset[str]
    reporting_line: str
    # Trusted enrolment evidence (source review 3282): a recognised identity issuer's signature over exactly this member's
    # subject, roles and reporting line for this installation. Optional in the data; REQUIRED of every approver by the
    # production check, so a reporting line is never merely a string someone typed into a roster.
    attestation: Signature | None = None


def attestation_body(installation: str, member: RosterMember) -> dict[str, Any]:
    """What an identity issuer attests for one member: the exact subject, roles and reporting line, per installation."""
    return {"schema": ATTESTATION_SCHEMA, "installation": installation, "subject_id": member.subject_id,
            "roles": sorted(member.roles), "reporting_line": member.reporting_line}


def attest_member(issuer: Signer, installation: str, member: RosterMember) -> RosterMember:
    """The member with an identity issuer's attestation of exactly its entry."""
    return RosterMember(member.subject_id, member.roles, member.reporting_line,
                        issuer.sign(attestation_body(installation, member)))


@dataclass(frozen=True, slots=True)
class GovernanceRoster:
    installation: str
    version: int
    members: tuple[RosterMember, ...]
    monitor_key_ids: frozenset[str]
    simulated: bool

    def as_fields(self) -> dict[str, Any]:
        return {"installation": self.installation, "version": self.version, "simulated": self.simulated,
                "monitor_key_ids": sorted(self.monitor_key_ids),
                "members": [_member_fields(m) for m in sorted(self.members, key=lambda m: m.subject_id)]}

    def digest(self) -> str:
        return sha256(canonical_bytes(self.as_fields())).hexdigest()

    def member(self, subject_id: str) -> RosterMember | None:
        return next((m for m in self.members if m.subject_id == subject_id), None)

    def approvers(self) -> tuple[RosterMember, ...]:
        return tuple(m for m in self.members if GOVERNANCE_ROLE in m.roles)


def _member_fields(member: RosterMember) -> dict[str, Any]:
    fields: dict[str, Any] = {"subject_id": member.subject_id, "roles": sorted(member.roles),
                              "reporting_line": member.reporting_line}
    if member.attestation is not None:
        fields["attestation"] = {"key_id": member.attestation.key_id, "value": member.attestation.value,
                                 "alg": member.attestation.alg}
    return fields


def _text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise EmissionError(f"a roster names every {what} explicitly")
    return value


def roster_from_fields(named: object) -> GovernanceRoster:
    """Parse a roster, refusing any unnamed field, unknown role, duplicate member or empty value."""
    keys = {"installation", "version", "simulated", "monitor_key_ids", "members"}
    if not isinstance(named, Mapping) or set(named) != keys:
        raise EmissionError("a roster names exactly installation, version, simulated, monitor_key_ids and members")
    if type(named["version"]) is not int or named["version"] < 1 or type(named["simulated"]) is not bool:
        raise EmissionError("a roster has a positive version and an explicit simulated label")
    monitors = named["monitor_key_ids"]
    rows = named["members"]
    if not isinstance(monitors, list) or not isinstance(rows, list) or not rows:
        raise EmissionError("a roster lists its members and monitor keys")
    members = []
    for row in rows:
        base = {"subject_id", "roles", "reporting_line"}
        if not isinstance(row, Mapping) or set(row) not in (base, base | {"attestation"}):
            raise EmissionError("a roster member names exactly subject_id, roles, reporting_line and an optional "
                                "attestation")
        attestation = None
        if "attestation" in row:
            raw = row["attestation"]
            if not isinstance(raw, Mapping) or set(raw) != {"key_id", "value", "alg"}:
                raise EmissionError("an enrolment attestation names exactly key_id, value and alg")
            attestation = Signature(_text(raw["key_id"], "attestation key"), _text(raw["value"], "attestation"),
                                    _text(raw["alg"], "attestation algorithm"))
        roles = row["roles"]
        if not isinstance(roles, list) or not roles or not set(roles) <= ROLES or len(set(roles)) != len(roles):
            raise EmissionError("a roster member holds one or more known governance roles")
        members.append(RosterMember(_text(row["subject_id"], "member"), frozenset(roles),
                                    _text(row["reporting_line"], "reporting line"), attestation))
    if len({m.subject_id for m in members}) != len(members):
        raise EmissionError("a roster names each member once")
    keys_named = frozenset(_text(k, "monitor key") for k in monitors)
    if len(keys_named) != len(monitors):
        raise EmissionError("a roster names each monitor key once")
    return GovernanceRoster(_text(named["installation"], "installation"), named["version"], tuple(members),
                            keys_named, named["simulated"])


def roster_change_bytes(roster: GovernanceRoster) -> bytes:
    """The exact bytes a roster change is approved and applied as."""
    return change_bytes(ROSTER_KIND, roster.installation, {"roster": roster.as_fields()})


def _roster_change_check(installation: str) -> Callable[[Mapping[str, Any]], None]:
    def check(change: Mapping[str, Any]) -> None:
        if set(change) != {"roster"}:
            raise EmissionError("a roster change carries exactly the new roster")
        if roster_from_fields(change["roster"]).installation != installation:
            raise EmissionError("the roster is for another installation")
    return check


def require_production_roster(roster: GovernanceRoster, *, trust: TrustDirectory, host_key_ids: Sequence[str],
                              identity_issuers: frozenset[str] = frozenset()) -> None:
    """Refuse a roster that cannot establish independent governance in production (owner ruling, ledger 3277).

    Beyond the label and the counts, every approver's entry must carry an attestation, verified here, from one of the
    deployment's recognised identity issuers (a registered key the host does not hold) over exactly that entry: the
    reporting lines that make approvers independent are attested facts, not strings in a document (source review 3282)."""
    if roster.simulated:
        raise ValueError("a simulated governance roster cannot govern a production installation")
    approvers = roster.approvers()
    if len(approvers) < 2 or len({m.reporting_line for m in approvers}) < 2:
        raise ValueError("production governance needs two approvers on distinct reporting lines")
    if not roster.monitor_key_ids or not all(trust.is_known(k) for k in roster.monitor_key_ids):
        raise ValueError("the monitor service needs its own registered signing key")
    if roster.monitor_key_ids & set(host_key_ids):
        raise ValueError("the monitor key must not be one the host itself signs with")
    held = set(host_key_ids)
    issuers = {k for k in identity_issuers if trust.is_known(k) and k not in held}
    if not issuers:
        raise ValueError("production governance needs a recognised identity issuer the host does not hold")
    for member in approvers:
        seal = member.attestation
        if (seal is None or seal.key_id not in issuers
                or not trust.verify(attestation_body(roster.installation, member), seal)):
            raise ValueError(f"approver {member.subject_id!r} has no valid enrolment attestation from a recognised "
                             "identity issuer")


class RosterStore(Protocol):
    """The host's durable roster. `apply` follows the GovernedChange contract: under its own lock, refuse unless the
    current roster digest (or "absent") is `approved_prior`, call `final_check()`, then write the roster and a receipt
    keyed (tenant, operation, nonce, change digest) atomically."""

    def current(self, installation: str) -> GovernanceRoster | None: ...

    def apply(self, change: GovernedChange) -> None: ...

    def receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Outcome: ...


class InMemoryRosterStore:
    """One process's roster store, honouring the same contract as a durable one."""

    def __init__(self, guard: GovernanceGuard | None = None) -> None:
        self._rosters: dict[str, GovernanceRoster] = {}
        self._receipts: set[tuple[str, str, str, str]] = set()
        # Reentrant: the host's final check runs inside `apply` and may read the current roster (source review 3285).
        self._lock = threading.RLock()
        self._guard = guard

    def current(self, installation: str) -> GovernanceRoster | None:
        with self._lock:
            return self._rosters.get(installation)

    def apply(self, change: GovernedChange) -> None:
        roster = roster_from_fields(change.change["roster"])
        with self._lock:
            if self._guard is not None:
                self._guard.require(ROSTER_KIND, change.subject)
            existing = self._rosters.get(change.subject)
            if (existing.digest() if existing else ABSENT) != change.approved_prior:
                raise FinalCheckRefused("the roster changed since this change was approved; nothing written")
            if roster.version != (existing.version + 1 if existing else 1):
                raise FinalCheckRefused("a roster change must advance the version by exactly one")
            change.final_check()
            self._rosters[change.subject] = roster
            self._receipts.add((change.tenant_id, change.operation, change.nonce, change.change_digest))

    def receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Outcome:
        with self._lock:
            return (Outcome.COMMITTED if (tenant_id, operation, nonce, change_digest) in self._receipts
                    else Outcome.UNKNOWN)


def roster_target(store: RosterStore, installation: str, *, tenant_id: str, authority: TargetAuthority,
                  uses: PermitUseStore, log: GovernanceLog, guard: GovernanceGuard | None = None,
                  bootstrap_trust: TrustDirectory | None = None,
                  bootstrap_key_ids: frozenset[str] = frozenset(), scope: str | None = None,
                  receiving_check: Any = None) -> GovernanceTarget:
    """The only writer of the roster: a first state by signed bootstrap, every later state by a tier-4 change.
    `scope` lets a host serialise roster changes with every other governance change it governs (governance_host)."""

    def state() -> str:
        current = store.current(installation)
        return current.digest() if current is not None else ABSENT

    def direct(change: Mapping[str, Any]) -> None:
        raise EmissionError("the roster applies only through its store's own transaction")

    return GovernanceTarget(tenant_id=tenant_id, kind=ROSTER_KIND, subject=installation, authority=authority,
                            uses=uses, state=state, apply=direct, log=log, operation_name=ROSTER_OPERATION,
                            guard=guard, transact=store.apply, receipt=store.receipt,
                            expect=lambda change, prior: roster_from_fields(change["roster"]).digest(),
                            validate=_roster_change_check(installation),
                            bootstrap_trust=bootstrap_trust, bootstrap_key_ids=bootstrap_key_ids, scope=scope,
                            receiving_check=receiving_check)


class RosterDirectory:
    """The tier-4 reporting-line directory, read from the current roster. An unenrolled subject has no line, so the
    tier-4 controls refuse rather than count them as independent."""

    def __init__(self, store: RosterStore, installation: str) -> None:
        self._store, self._installation = store, installation

    def reporting_line(self, tenant_id: str, subject_id: str) -> str | None:
        roster = self._store.current(self._installation)
        member = roster.member(subject_id) if roster is not None else None
        return member.reporting_line if member is not None else None


class RosterCredentials:
    """The governance reviewers' credential authority: a signed receipt only for an enrolled member holding the role.

    The receipt binds the exact roster it read (its digest, in the receipt licence field) and lives one hour. The
    host passes the AUTHENTICATED reviewer; the roster never makes someone who they are, only what they may do."""

    def __init__(self, store: RosterStore, installation: str, signer: Signer | None = None,
                 *, provider_signers: Mapping[str, Signer] | None = None) -> None:
        if (signer is None) == (provider_signers is None):
            raise ValueError("choose one roster credential signing configuration")
        if provider_signers is not None and not provider_signers:
            raise ValueError("roster credential provider signers cannot be empty")
        self._store, self._installation, self._signer = store, installation, signer
        self._provider_signers = None if provider_signers is None else MappingProxyType(dict(provider_signers))

    def __call__(self, reviewer_id: str, tenant_id: str, role: str, now_us: int) -> CredentialReceipt:
        roster = self._store.current(self._installation)
        if roster is None:
            raise CredentialError("no governance roster is enrolled; governance cannot be reviewed")
        member = roster.member(reviewer_id)
        if member is None or role not in member.roles:
            raise CredentialError(f"{reviewer_id!r} holds no {role!r} role in the governance roster")
        licence = "governance-roster:" + roster.digest()   # "@" is the approval qualifier separator
        jurisdiction = "installation:" + roster.installation
        expires = now_us + RECEIPT_TTL_US
        provider = "governance-roster" + (":simulated" if roster.simulated else "")
        signer = self._signer if self._provider_signers is None else self._provider_signers.get(provider)
        if signer is None:
            raise CredentialError("the roster credential provider is not configured")
        body = {"schema": "regulated/credential-receipt/v1", "subject_id": reviewer_id, "tenant": tenant_id,
                "role": role, "licence_type": licence, "jurisdiction": jurisdiction, "status": "active",
                "expires_at_us": expires, "verified_at_us": now_us, "provider": provider}
        return CredentialReceipt(reviewer_id, tenant_id, role, licence, jurisdiction, "active", expires, now_us,
                                 provider, signer.sign(body))


__all__ = ["ATTESTATION_SCHEMA", "GovernanceRoster", "InMemoryRosterStore", "attest_member", "attestation_body", "ROLES", "ROSTER_KIND", "ROSTER_OPERATION", "RosterCredentials",
           "RosterDirectory", "RosterMember", "RosterStore", "require_production_roster", "roster_change_bytes",
           "roster_from_fields", "roster_target"]
