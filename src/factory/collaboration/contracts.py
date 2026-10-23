"""Immutable, canonical domain records for governed collaboration.

Every record here is data, not behavior: nothing in this module can commit,
push, approve, promote, release, spend, or execute (WO-CD-0 law 17). Authority
lives in digests and validation, so a ticket that changes is a DIFFERENT
ticket (stale bindings fail closed), a wake signal cannot smuggle content, and
no event payload can masquerade as another event type.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import Enum
from types import MappingProxyType
from typing import ClassVar

from factory.tenant import TenantContext  # the ONLY admitted platform type (WO-CD-0 §3.5)


class ContractViolation(ValueError):
    """A record violated the collaboration contract at construction or parse."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _require_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractViolation(f"{name} must be a non-blank string")
    return value


def _require_digest(value: str, name: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ContractViolation(f"{name} must be a 64-char lowercase sha256 hex digest")
    return value


# A full object id only: an abbreviated prefix is ambiguous and cannot be an
# EXACT approval binding (fix-cycle clarification, 2026-07-19).
_COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")


def _require_commit_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not _COMMIT_ID.fullmatch(value):
        raise ContractViolation(f"{name} must be a full lowercase 40-hex git object id")
    return value


def _require_enum(value: object, enum_cls: type[Enum], name: str) -> None:
    # A string that spells an enum value is a substitute, not the fact itself.
    if not isinstance(value, enum_cls):
        raise ContractViolation(f"{name} must be a {enum_cls.__name__} instance")


def _require_tuple(value: object, name: str) -> None:
    # A mutable list retained by the caller could mutate the "frozen" record.
    if not isinstance(value, tuple):
        raise ContractViolation(f"{name} must be an immutable tuple")


def _require_int(value: int, name: str, *, minimum: int) -> int:
    # bool is an int subclass; an authority fact must be an ACTUAL integer.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractViolation(f"{name} must be an integer")
    if value < minimum:
        raise ContractViolation(f"{name} must be >= {minimum}")
    return value


def _require_money(value: float, name: str) -> float:
    # Refuse bool-as-number, non-numbers, NaN and infinities: a ceiling that is
    # not a real finite amount is not a ceiling.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractViolation(f"{name} must be a number")
    if not math.isfinite(value) or value < 0:
        raise ContractViolation(f"{name} must be finite and non-negative")
    return float(value)


def _require_unique(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    for item in values:
        _require_text(item, f"{name} entry")  # element type first: no incidental TypeError
    if len(set(values)) != len(values):
        raise ContractViolation(f"{name} must not contain duplicates")
    return values


def canonical_digest(payload: Mapping[str, object]) -> str:
    """SHA-256 of the sorted-compact JSON form — the one canonical serialization.

    Sorted keys + compact separators so semantically identical payloads always
    digest identically regardless of construction order (the F11 law).
    allow_nan=False keeps the form standard JSON: a payload that cannot be
    expressed canonically is a contract violation, not a quiet extension.
    """
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except ValueError as exc:
        raise ContractViolation(f"payload is not canonically serializable: {exc}") from exc
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ParticipantRole(str, Enum):
    """A seat's function on one ticket. Roles are bound per ticket, never inferred."""

    AUTHOR = "author"
    REVIEWER = "reviewer"
    APPROVER = "approver"


class TrustClass(str, Enum):
    """Where an instruction came from. Only OWNER may authorize consequence."""

    OWNER = "owner"
    AUTHENTICATED_OPERATOR = "authenticated_operator"
    AUTHENTICATED_CUSTOMER = "authenticated_customer"
    SYSTEM_ROLE = "system_role"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class EffectClass(str, Enum):
    """What a command may change. CONSEQUENTIAL always needs fresh owner approval."""

    READ_ONLY = "read_only"
    ROUTINE = "routine"
    CONSEQUENTIAL = "consequential"


class VisibilityPhase(str, Enum):
    """Peer-visibility rule for a ticket's outputs (blind-round law as data)."""

    BLIND = "blind"
    SEALED = "sealed"
    OPEN = "open"


class NetworkMode(str, Enum):
    """Network reach a ticket permits its executor. Governed work defaults to NONE."""

    NONE = "none"
    LOOPBACK = "loopback"


class RemoteTaskState(str, Enum):
    """Internal projection of an A2A 1.0 task state — a LOSSY remote lifecycle.

    These never rename or replace internal events (ACK, stranded, transfer,
    review, approval, ruling stay explicit). Unknown wire states fail closed
    at the mapping layer.
    """

    UNSPECIFIED = "unspecified"
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input_required"
    AUTH_REQUIRED = "auth_required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    REJECTED = "rejected"


class WakeKind(str, Enum):
    """Why a wake fired. A wake is a doorbell, never a package."""

    STATUS_CHANGED = "status_changed"
    MESSAGE_AVAILABLE = "message_available"


class ReviewVerdict(str, Enum):
    """The CLOSED verdict vocabulary: a review outcome is one of these, never
    free text — 'self-approved' is unrepresentable, not merely refused."""

    ACCEPTED = "accepted"
    APPROVED_PENDING_FIXES = "approved_pending_fixes"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class RoleBinding:
    """One participant bound to one role on one ticket."""

    role: ParticipantRole
    participant_id: str

    def __post_init__(self) -> None:
        _require_enum(self.role, ParticipantRole, "role")
        _require_text(self.participant_id, "participant_id")


@dataclass(frozen=True, slots=True)
class LeasePolicy:
    """Liveness bounds: how long silence may last before the ticket strands."""

    ack_deadline_s: int
    lease_s: int
    max_retries: int
    reassignment: str

    _REASSIGNMENTS: ClassVar[frozenset[str]] = frozenset({"reassign", "takeover", "halt"})

    def __post_init__(self) -> None:
        _require_int(self.ack_deadline_s, "ack_deadline_s", minimum=1)
        _require_int(self.lease_s, "lease_s", minimum=1)
        _require_int(self.max_retries, "max_retries", minimum=0)
        if self.reassignment not in self._REASSIGNMENTS:
            raise ContractViolation(f"reassignment must be one of {sorted(self._REASSIGNMENTS)}")


@dataclass(frozen=True, slots=True)
class WorkTicket:
    """One owner-approved unit of governed work, canonically digested.

    The digest covers every authority-bearing field, so any mutation yields a
    new digest and stale approvals/dispatches bound to the old digest fail
    closed. Role validation enforces no-self-review and no reviewer/approver
    overlap AT CONSTRUCTION — an invalid ticket cannot exist.
    """

    ticket_id: str
    tenant_id: str
    project_ref: str
    source_snapshot_digest: str
    roles: tuple[RoleBinding, ...]
    protocol_phase: str
    visibility: VisibilityPhase
    allowed_tools: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    network_mode: NetworkMode
    effect_class: EffectClass
    reservation_id: str
    ceiling_usd: float
    expected_artifact: str
    lease: LeasePolicy
    dependencies: tuple[str, ...]
    acceptance_gate: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for name in ("ticket_id", "tenant_id", "project_ref", "protocol_phase",
                     "reservation_id", "expected_artifact", "acceptance_gate",
                     "idempotency_key"):
            _require_text(getattr(self, name), name)
        _require_digest(self.source_snapshot_digest, "source_snapshot_digest")
        _require_enum(self.visibility, VisibilityPhase, "visibility")
        _require_enum(self.network_mode, NetworkMode, "network_mode")
        _require_enum(self.effect_class, EffectClass, "effect_class")
        for name in ("roles", "allowed_tools", "allowed_paths", "dependencies"):
            _require_tuple(getattr(self, name), name)
        if not isinstance(self.lease, LeasePolicy):
            raise ContractViolation("lease must be a LeasePolicy")
        _require_unique(self.allowed_tools, "allowed_tools")
        _require_unique(self.allowed_paths, "allowed_paths")
        _require_unique(self.dependencies, "dependencies")
        _require_money(self.ceiling_usd, "ceiling_usd")
        self._validate_roles()

    def _validate_roles(self) -> None:
        by_role: dict[ParticipantRole, str] = {}
        for binding in self.roles:
            if not isinstance(binding, RoleBinding):
                raise ContractViolation("roles must contain only RoleBinding records")
            if binding.role in by_role:
                raise ContractViolation(f"duplicate role binding: {binding.role.value}")
            by_role[binding.role] = binding.participant_id
        author = by_role.get(ParticipantRole.AUTHOR)
        reviewer = by_role.get(ParticipantRole.REVIEWER)
        if author is None or reviewer is None:
            raise ContractViolation("a ticket requires both an author and a reviewer")
        if author == reviewer:
            raise ContractViolation("self-review refused: author and reviewer must differ")
        approver = by_role.get(ParticipantRole.APPROVER)
        if approver is not None and approver in (author, reviewer):
            raise ContractViolation("approver must not overlap author or reviewer")

    @classmethod
    def create(cls, tenant: TenantContext, **kwargs: object) -> "WorkTicket":
        """Build a ticket for a tenant, taking identity from the platform context."""
        return cls(tenant_id=tenant.tenant_id, **kwargs)  # type: ignore[arg-type]

    def canonical_payload(self) -> dict[str, object]:
        """Every authority-bearing field, in canonically serializable form."""
        return {
            "ticket_id": self.ticket_id,
            "tenant_id": self.tenant_id,
            "project_ref": self.project_ref,
            "source_snapshot_digest": self.source_snapshot_digest,
            "roles": [{"role": b.role.value, "participant_id": b.participant_id}
                      for b in self.roles],
            "protocol_phase": self.protocol_phase,
            "visibility": self.visibility.value,
            "allowed_tools": list(self.allowed_tools),
            "allowed_paths": list(self.allowed_paths),
            "network_mode": self.network_mode.value,
            "effect_class": self.effect_class.value,
            "reservation_id": self.reservation_id,
            "ceiling_usd": self.ceiling_usd,
            "expected_artifact": self.expected_artifact,
            "lease": {
                "ack_deadline_s": self.lease.ack_deadline_s,
                "lease_s": self.lease.lease_s,
                "max_retries": self.lease.max_retries,
                "reassignment": self.lease.reassignment,
            },
            "dependencies": list(self.dependencies),
            "acceptance_gate": self.acceptance_gate,
            "idempotency_key": self.idempotency_key,
        }

    @property
    def ticket_digest(self) -> str:
        return canonical_digest(self.canonical_payload())

    def participant_for(self, role: ParticipantRole) -> str | None:
        for binding in self.roles:
            if binding.role is role:
                return binding.participant_id
        return None


@dataclass(frozen=True, slots=True)
class ParticipantCapability:
    """One discoverable capability, backed by a content-addressed receipt."""

    capability_id: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_text(self.capability_id, "capability_id")
        _require_digest(self.receipt_digest, "receipt_digest")


@dataclass(frozen=True, slots=True)
class ParticipantCard:
    """A participant's discoverable identity: capabilities plus qualification proof.

    Deliberately carries NO runtime, product, or company field — a card cannot
    grant advantage by naming who made the participant (WO-CD-0 law 4).
    """

    participant_id: str
    capabilities: tuple[ParticipantCapability, ...]
    qualification_digest: str

    def __post_init__(self) -> None:
        _require_text(self.participant_id, "participant_id")
        _require_digest(self.qualification_digest, "qualification_digest")
        _require_tuple(self.capabilities, "capabilities")
        for capability in self.capabilities:
            if not isinstance(capability, ParticipantCapability):
                raise ContractViolation("capabilities must contain only ParticipantCapability")
        seen = {c.capability_id for c in self.capabilities}
        if len(seen) != len(self.capabilities):
            raise ContractViolation("capabilities must not contain duplicates")


@dataclass(frozen=True, slots=True)
class DispatchReceipt:
    """What a transport returns for a delivery attempt. Delivery is a hint, not truth."""

    ticket_id: str
    ticket_digest: str
    participant_id: str
    accepted: bool
    idempotency_key: str
    correlation: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.ticket_id, "ticket_id")
        _require_digest(self.ticket_digest, "ticket_digest")
        _require_text(self.participant_id, "participant_id")
        _require_text(self.idempotency_key, "idempotency_key")


@dataclass(frozen=True, slots=True)
class WakeSignal:
    """A signal-only wake: correlation, source, kind, freshness — NO content.

    The type has no content-bearing field by construction (A3.3); anything a
    participant needs to know arrives through an authenticated reconciliation
    read, never through the wake itself.
    """

    correlation: str
    source_participant_id: str
    kind: WakeKind
    freshness: int
    idempotency_key: str

    def __post_init__(self) -> None:
        _require_text(self.correlation, "correlation")
        _require_text(self.source_participant_id, "source_participant_id")
        _require_enum(self.kind, WakeKind, "kind")
        _require_text(self.idempotency_key, "idempotency_key")
        _require_int(self.freshness, "freshness", minimum=0)


_WAKE_KEYS = frozenset({"correlation", "source_participant_id", "kind",
                        "freshness", "idempotency_key"})


def parse_wake_signal(payload: Mapping[str, object]) -> WakeSignal:
    """Parse an inbound wake, refusing ANY undeclared key (WO-CD-0 law 10).

    A wake carrying instructions, artifact bytes, snapshot text, credentials,
    or any other undeclared data is rejected wholesale — not filtered.
    """
    extra = set(payload) - _WAKE_KEYS
    if extra:
        raise ContractViolation(f"wake signal carries undeclared data: {sorted(extra)}")
    missing = _WAKE_KEYS - set(payload)
    if missing:
        raise ContractViolation(f"wake signal missing required keys: {sorted(missing)}")
    kind_raw = payload["kind"]
    if not isinstance(kind_raw, str):
        raise ContractViolation("wake kind must be a string")
    try:
        kind = WakeKind(kind_raw)
    except ValueError as exc:
        raise ContractViolation(f"unknown wake kind: {kind_raw!r}") from exc
    freshness = payload["freshness"]
    if isinstance(freshness, bool) or not isinstance(freshness, int):
        raise ContractViolation("freshness must be an integer")
    correlation = payload["correlation"]
    source = payload["source_participant_id"]
    idempotency = payload["idempotency_key"]
    if not all(isinstance(v, str) for v in (correlation, source, idempotency)):
        raise ContractViolation("wake identity fields must be strings")
    return WakeSignal(
        correlation=str(correlation),
        source_participant_id=str(source),
        kind=kind,
        freshness=freshness,
        idempotency_key=str(idempotency),
    )


@dataclass(frozen=True, slots=True)
class RemoteTaskProjection:
    """A remote task seen from inside: internal identity + opaque remote correlation.

    Internal identity (ticket_id/ticket_digest) comes ONLY from the local
    ticket; remote ids are correlation data and can never overwrite it
    (WO-CD-0 law 7).
    """

    ticket_id: str
    ticket_digest: str
    remote_task_id: str
    remote_context_id: str
    state: RemoteTaskState

    def __post_init__(self) -> None:
        _require_text(self.ticket_id, "ticket_id")
        _require_digest(self.ticket_digest, "ticket_digest")
        _require_text(self.remote_task_id, "remote_task_id")
        _require_text(self.remote_context_id, "remote_context_id")
        _require_enum(self.state, RemoteTaskState, "state")


class CollaborationEventType(str, Enum):
    """The kernel event vocabulary (proposal §3.1) — explicit, never projected away."""

    RUN_PROPOSED = "run_proposed"
    RUN_APPROVED = "run_approved"
    TICKET_QUEUED = "ticket_queued"
    TICKET_DISPATCHED = "ticket_dispatched"
    TICKET_ACKNOWLEDGED = "ticket_acknowledged"
    TICKET_PROGRESSED = "ticket_progressed"
    TICKET_STRANDED = "ticket_stranded"
    AUTHORSHIP_TRANSFERRED = "authorship_transferred"
    ARTIFACT_SUBMITTED = "artifact_submitted"
    REVIEW_REQUESTED = "review_requested"
    REVIEW_RECORDED = "review_recorded"
    REVISION_REQUESTED = "revision_requested"
    TICKET_COMPLETED = "ticket_completed"
    TICKET_FAILED = "ticket_failed"
    COMMIT_PROPOSED = "commit_proposed"
    COMMIT_APPROVED = "commit_approved"
    PUSH_PROPOSED = "push_proposed"
    PUSH_APPROVED = "push_approved"


@dataclass(frozen=True, slots=True)
class _EventPayload:
    """Base for event payloads: every string fact validates at construction.

    Fields ending in ``_digest`` must be sha256 hex; ``commit_id`` must be a
    git commit id; everything else must be non-blank text. Malformed authority
    facts are impossible to record, not merely impolite (F2/F3).
    """

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name.endswith("_digest"):
                _require_digest(value, f.name)
            elif f.name == "commit_id":
                _require_commit_id(value, f.name)
            elif f.name == "verdict":
                _require_enum(value, ReviewVerdict, f.name)
            else:
                _require_text(value, f.name)


@dataclass(frozen=True, slots=True)
class RunProposed(_EventPayload):
    run_id: str
    tenant_id: str
    goal_digest: str


@dataclass(frozen=True, slots=True)
class RunApproved(_EventPayload):
    run_id: str
    actor: str


@dataclass(frozen=True, slots=True)
class TicketQueued(_EventPayload):
    ticket_id: str
    ticket_digest: str


@dataclass(frozen=True, slots=True)
class TicketDispatched(_EventPayload):
    ticket_id: str
    ticket_digest: str
    participant_id: str


@dataclass(frozen=True, slots=True)
class TicketAcknowledged(_EventPayload):
    """ACK is receipt of the ticket, never acceptance of its content."""

    ticket_id: str
    participant_id: str


@dataclass(frozen=True, slots=True)
class TicketProgressed(_EventPayload):
    ticket_id: str
    participant_id: str
    note_digest: str


@dataclass(frozen=True, slots=True)
class TicketStranded(_EventPayload):
    ticket_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class AuthorshipTransferred(_EventPayload):
    ticket_id: str
    from_participant_id: str
    to_participant_id: str


@dataclass(frozen=True, slots=True)
class ArtifactSubmitted(_EventPayload):
    ticket_id: str
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class ReviewRequested(_EventPayload):
    ticket_id: str
    reviewer_id: str


@dataclass(frozen=True, slots=True)
class ReviewRecorded(_EventPayload):
    """A review verdict is evidence for the record, never an owner ruling."""

    ticket_id: str
    reviewer_id: str
    verdict: ReviewVerdict


@dataclass(frozen=True, slots=True)
class RevisionRequested(_EventPayload):
    ticket_id: str
    reviewer_id: str
    findings_digest: str


@dataclass(frozen=True, slots=True)
class TicketCompleted(_EventPayload):
    ticket_id: str


@dataclass(frozen=True, slots=True)
class TicketFailed(_EventPayload):
    ticket_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class CommitProposed(_EventPayload):
    ticket_id: str
    tree_digest: str
    message_digest: str


@dataclass(frozen=True, slots=True)
class CommitApproved(_EventPayload):
    """Exact-content owner approval: stale the moment the bound tree changes."""

    tree_digest: str
    message_digest: str
    actor: str


@dataclass(frozen=True, slots=True)
class PushProposed(_EventPayload):
    ticket_id: str
    commit_id: str
    remote: str
    branch: str


@dataclass(frozen=True, slots=True)
class PushApproved(_EventPayload):
    """Exact-destination owner approval, bound to one commit id."""

    commit_id: str
    remote: str
    branch: str
    actor: str


# Immutable by construction: runtime code cannot swap a payload type to defeat
# the masquerade law (F3).
EVENT_PAYLOADS: Mapping[CollaborationEventType, type] = MappingProxyType({
    CollaborationEventType.RUN_PROPOSED: RunProposed,
    CollaborationEventType.RUN_APPROVED: RunApproved,
    CollaborationEventType.TICKET_QUEUED: TicketQueued,
    CollaborationEventType.TICKET_DISPATCHED: TicketDispatched,
    CollaborationEventType.TICKET_ACKNOWLEDGED: TicketAcknowledged,
    CollaborationEventType.TICKET_PROGRESSED: TicketProgressed,
    CollaborationEventType.TICKET_STRANDED: TicketStranded,
    CollaborationEventType.AUTHORSHIP_TRANSFERRED: AuthorshipTransferred,
    CollaborationEventType.ARTIFACT_SUBMITTED: ArtifactSubmitted,
    CollaborationEventType.REVIEW_REQUESTED: ReviewRequested,
    CollaborationEventType.REVIEW_RECORDED: ReviewRecorded,
    CollaborationEventType.REVISION_REQUESTED: RevisionRequested,
    CollaborationEventType.TICKET_COMPLETED: TicketCompleted,
    CollaborationEventType.TICKET_FAILED: TicketFailed,
    CollaborationEventType.COMMIT_PROPOSED: CommitProposed,
    CollaborationEventType.COMMIT_APPROVED: CommitApproved,
    CollaborationEventType.PUSH_PROPOSED: PushProposed,
    CollaborationEventType.PUSH_APPROVED: PushApproved,
})


@dataclass(frozen=True, slots=True)
class CollaborationEventRecord:
    """An event with its payload, type-checked so one kind cannot masquerade
    as another (WO-CD-0 law: ACK / artifact / review / approval are distinct
    signed types)."""

    event_type: CollaborationEventType
    payload: object

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, CollaborationEventType):
            raise ContractViolation("event_type must be a CollaborationEventType")
        expected = EVENT_PAYLOADS[self.event_type]
        if type(self.payload) is not expected:
            raise ContractViolation(
                f"payload {type(self.payload).__name__} cannot masquerade as "
                f"{self.event_type.value}")

    def canonical_payload(self) -> dict[str, object]:
        payload_fields = fields(self.payload)  # type: ignore[arg-type]
        body = {
            f.name: (value.value if isinstance(value := getattr(self.payload, f.name), Enum)
                     else value)
            for f in payload_fields
        }
        return {"event_type": self.event_type.value, "payload": body}

    @property
    def event_digest(self) -> str:
        return canonical_digest(self.canonical_payload())
