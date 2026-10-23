"""The care contracts: records, vocabularies, the transition table, the chained digest.

Every record is a frozen dataclass that validates itself on construction, serialises to a
canonical JSON object and reads back to an equal value, so the memory twin and the Postgres store
hold the same bytes. The laws the records carry (synthesis section 4, deliberation 04):

- a case belongs to exactly one authenticated workspace and names the principal who opened it;
- references attach only with their source system, an immutable source identity or digest and the
  instant they were verified (A4); a reference the server could not prove never attaches;
- the event ledger is append-only and hash-chained per case: every event carries the digest of the
  previous event and its own canonical digest (A2), so a dispute is settled by the record (law 8);
- public and internal statements are different write kinds, never a flag toggled later (10.B);
- a remedy is a link to a governed operation elsewhere plus its receipt reference (A6): nothing in
  this package can grant, apply, refund, reinstate, approve or delete;
- `closed` is not `resolved`; a reopen keeps lineage (10.A).

The routing policy here is the S1 value object: a validated, declared configuration the
composition root supplies. S2 wraps it in a signed document behind the `VerifiedDocumentLoader`
protocol (A8); the shape does not change, the provenance does.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

# --- errors ------------------------------------------------------------------------------------------


class CareContractError(ValueError):
    """A record does not satisfy its own contract; nothing is stored."""


class CareConflict(RuntimeError):
    """A write raced another: the revision moved, or an idempotency key was reused for a different request."""


class CareRefused(RuntimeError):
    """A command refused for a stated reason the customer may read (the reason is customer-safe)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CareUnavailable(RuntimeError):
    """A truth reader or store could not answer; retryable, never treated as `not owned` (A4)."""


# --- vocabularies --------------------------------------------------------------------------------------


class CaseState(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    WAITING_ON_US = "waiting_on_us"
    WAITING_ON_CUSTOMER = "waiting_on_customer"
    WAITING_ON_EXTERNAL = "waiting_on_external"
    REMEDY_PROPOSED = "remedy_proposed"
    RESOLVED = "resolved"
    CLOSED = "closed"


OPEN_STATES: frozenset[CaseState] = frozenset(
    {CaseState.NEW, CaseState.TRIAGED, CaseState.WAITING_ON_US, CaseState.WAITING_ON_CUSTOMER,
     CaseState.WAITING_ON_EXTERNAL, CaseState.REMEDY_PROPOSED})


class IssueClass(str, Enum):
    """The closed intake vocabulary (owner decision 7 names the escalation categories)."""

    BILLING_ACCESS = "billing_access"
    SECURITY_PRIVACY = "security_privacy"
    EDUCATION = "education"
    HEALTH = "health"
    TECHNICAL = "technical"
    GENERAL = "general"


#: Regulated-domain classes: resolved as authoritative only once a specialist is assigned (decision 7).
REGULATED_CLASSES: frozenset[IssueClass] = frozenset({IssueClass.EDUCATION, IssueClass.HEALTH})


class Impact(str, Enum):
    ONE_USER = "one_user"
    WORKSPACE = "workspace"
    MANY_TENANTS = "many_tenants"
    PLATFORM = "platform"


class Urgency(str, Enum):
    BLOCKED_DEADLINE = "blocked_deadline"
    DEGRADED = "degraded"
    QUESTION = "question"


class ReferenceKind(str, Enum):
    """The closed reference vocabulary (A4, decision 8): each id is proven to belong to the workspace."""

    RUN = "run"
    CORRELATION = "correlation"
    RECEIPT = "receipt"
    INVOICE = "invoice"
    PAYMENT = "payment"
    RESERVATION = "reservation"
    PROJECT = "project"
    EMISSION = "emission"
    INCIDENT = "incident"
    COMMERCIAL_CODE = "commercial_code"
    FILE = "file"


class OwnerClass(str, Enum):
    """What the customer is told about who holds the case (law 5; decision 2)."""

    UNASSIGNED = "unassigned"
    CUSTOMER_CARE = "customer_care"
    SPECIALIST_REQUIRED = "specialist_required"


class EventVisibility(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"


class EventKind(str, Enum):
    CREATED = "created"
    REFERENCE_REFUSED = "reference_refused"
    CUSTOMER_STATEMENT = "customer_statement"
    OPERATOR_STATEMENT = "operator_statement"
    INTERNAL_NOTE = "internal_note"
    ASSIGNED = "assigned"
    TRANSITION = "transition"
    REMEDY_LINKED = "remedy_linked"
    RESOLVED = "resolved"
    CLOSED = "closed"
    REOPENED = "reopened"
    TARGET_BREACHED = "target_breached"
    ESCALATED = "escalated"


#: Kinds that are internal by construction; a public projection never carries them (10.B).
INTERNAL_KINDS: frozenset[EventKind] = frozenset({EventKind.INTERNAL_NOTE})


class Role(str, Enum):
    CUSTOMER = "customer"
    OPERATOR = "operator"
    SYSTEM = "system"


# --- the transition table (10.A), data not code ---------------------------------------------------------

#: (from state, action, role) -> to state. Anything absent is refused with the current state named.
TRANSITIONS: Mapping[tuple[CaseState, str, Role], CaseState] = {
    (CaseState.NEW, "triage", Role.OPERATOR): CaseState.TRIAGED,
    (CaseState.NEW, "reply", Role.OPERATOR): CaseState.WAITING_ON_CUSTOMER,
    (CaseState.TRIAGED, "reply", Role.OPERATOR): CaseState.WAITING_ON_CUSTOMER,
    (CaseState.TRIAGED, "wait_external", Role.OPERATOR): CaseState.WAITING_ON_EXTERNAL,
    (CaseState.WAITING_ON_US, "reply", Role.OPERATOR): CaseState.WAITING_ON_CUSTOMER,
    (CaseState.WAITING_ON_US, "wait_external", Role.OPERATOR): CaseState.WAITING_ON_EXTERNAL,
    (CaseState.WAITING_ON_CUSTOMER, "reply", Role.CUSTOMER): CaseState.WAITING_ON_US,
    (CaseState.WAITING_ON_EXTERNAL, "reply", Role.OPERATOR): CaseState.WAITING_ON_CUSTOMER,
    (CaseState.WAITING_ON_EXTERNAL, "external_answered", Role.OPERATOR): CaseState.WAITING_ON_US,
    (CaseState.TRIAGED, "propose_remedy", Role.OPERATOR): CaseState.REMEDY_PROPOSED,
    (CaseState.WAITING_ON_US, "propose_remedy", Role.OPERATOR): CaseState.REMEDY_PROPOSED,
    (CaseState.WAITING_ON_CUSTOMER, "propose_remedy", Role.OPERATOR): CaseState.REMEDY_PROPOSED,
    (CaseState.REMEDY_PROPOSED, "resolve", Role.OPERATOR): CaseState.RESOLVED,
    (CaseState.TRIAGED, "resolve", Role.OPERATOR): CaseState.RESOLVED,
    (CaseState.WAITING_ON_US, "resolve", Role.OPERATOR): CaseState.RESOLVED,
    (CaseState.WAITING_ON_CUSTOMER, "resolve", Role.OPERATOR): CaseState.RESOLVED,
    (CaseState.RESOLVED, "close", Role.OPERATOR): CaseState.CLOSED,
    (CaseState.RESOLVED, "close", Role.SYSTEM): CaseState.CLOSED,
    (CaseState.RESOLVED, "reopen", Role.CUSTOMER): CaseState.WAITING_ON_US,
    (CaseState.RESOLVED, "reopen", Role.OPERATOR): CaseState.WAITING_ON_US,
    (CaseState.CLOSED, "reopen", Role.CUSTOMER): CaseState.WAITING_ON_US,
    (CaseState.CLOSED, "reopen", Role.OPERATOR): CaseState.WAITING_ON_US,
}


def transition(state: CaseState, action: str, role: Role) -> CaseState:
    """The next state, or CareRefused naming the current state and the action (never a silent no-op)."""
    try:
        return TRANSITIONS[(state, action, role)]
    except KeyError:
        raise CareRefused("TRANSITION_REFUSED", f"a {role.value} cannot {action} a case that is {state.value}") from None


# --- canonical digest (the one serialisation; mirrors the collaboration law without importing it) -------


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=_json_default)


def canonical_digest(payload: Mapping[str, Any]) -> str:
    """SHA-256 of the sorted, compact JSON form: identical payloads digest identically."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"not canonically serialisable: {type(value).__name__}")


# --- validation helpers ---------------------------------------------------------------------------------

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")
_HANDLE = re.compile(r"^(operator|customer|system):[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")
#: One customer command attempt: the Idempotency-Key the surface RECEIVED (never a body field). Its
#: shape is the retained contract's opaque value (openapi_contract._OPAQUE_VALUE_SCHEMA), so the
#: browser, the key identity and the retained /v1 path all carry the same thing.
_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def check_action_id(value: object) -> str:
    """The idempotency key of a customer command, or a refusal that says what is missing."""
    if not isinstance(value, str) or not _ACTION_ID.fullmatch(value):
        raise CareRefused("INVALID_REQUEST", "an Idempotency-Key is required: one stable key per attempt, "
                          "1 to 128 characters of letters, digits, '.', '_', ':' or '-'")
    return value
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_TEXT = 4000
MAX_REFERENCES = 24


def _identifier(value: str, what: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise CareContractError(f"{what} must be a short identifier, got {value!r}")
    return value


def _optional_identifier(value: str, what: str) -> str:
    return "" if value == "" else _identifier(value, what)


def _text(value: str, what: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CareContractError(f"{what} must be text")
    if not allow_empty and not value.strip():
        raise CareContractError(f"{what} must not be empty")
    if len(value) > MAX_TEXT:
        raise CareContractError(f"{what} exceeds {MAX_TEXT} characters")
    return value


def _time(value: datetime, what: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CareContractError(f"{what} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _optional_time(value: datetime | None, what: str) -> datetime | None:
    return None if value is None else _time(value, what)


def _actor(value: str) -> str:
    if not isinstance(value, str) or not _HANDLE.fullmatch(value):
        raise CareContractError(f"actor must be role:handle, got {value!r}")
    return value


def _parse_time(value: Any) -> datetime:
    return datetime.fromisoformat(str(value)).astimezone(timezone.utc)


# --- references (A4) --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CaseReference:
    """A safe reference the server proved belongs to the workspace before it attached."""

    kind: ReferenceKind
    id: str
    source_system: str
    source_digest: str            # the source's immutable identity, digest or revision at verification
    verified_at: datetime
    note: str = ""                # customer-safe words (a refusal code's sentence, an invoice period)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ReferenceKind):
            raise CareContractError("reference kind must be a ReferenceKind")
        _identifier(self.id, "reference id")
        _identifier(self.source_system, "reference source_system")
        if not isinstance(self.source_digest, str) or not self.source_digest.strip():
            raise CareContractError("reference source_digest must name the source's identity or digest")
        object.__setattr__(self, "verified_at", _time(self.verified_at, "reference verified_at"))
        _text(self.note, "reference note", allow_empty=True)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "id": self.id, "source_system": self.source_system,
                "source_digest": self.source_digest, "verified_at": self.verified_at.isoformat(), "note": self.note}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CaseReference":
        return cls(ReferenceKind(str(data["kind"])), str(data["id"]), str(data["source_system"]),
                   str(data["source_digest"]), _parse_time(data["verified_at"]), str(data.get("note", "")))


@dataclass(frozen=True, slots=True)
class RemedyLink:
    """A reference to a governed operation elsewhere and the receipt it produced (A6). Care records
    it; care never invokes it."""

    operation_id: str
    resource_ref: str
    receipt_ref: str = ""         # empty while proposed; required for an authoritative resolution
    note: str = ""

    def __post_init__(self) -> None:
        _identifier(self.operation_id, "remedy operation_id")
        _identifier(self.resource_ref, "remedy resource_ref")
        _optional_identifier(self.receipt_ref, "remedy receipt_ref")
        _text(self.note, "remedy note", allow_empty=True)

    def to_dict(self) -> dict[str, Any]:
        return {"operation_id": self.operation_id, "resource_ref": self.resource_ref,
                "receipt_ref": self.receipt_ref, "note": self.note}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RemedyLink":
        return cls(str(data["operation_id"]), str(data["resource_ref"]), str(data.get("receipt_ref", "")),
                   str(data.get("note", "")))


# --- the routing policy (S1 value object; S2 signs it) ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class Targets:
    """Response targets for one support level, in business hours of the policy's calendar
    (owner decision 1). A zero resolution target means no resolution promise (Free)."""

    first_response_hours: int
    next_update_hours: int
    resolution_hours: int

    def __post_init__(self) -> None:
        for name in ("first_response_hours", "next_update_hours", "resolution_hours"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CareContractError(f"targets.{name} must be a non-negative integer of business hours")
        if self.first_response_hours == 0:
            raise CareContractError("a support level promises at least one business hour to first response")

    def to_dict(self) -> dict[str, int]:
        return {"first_response_hours": self.first_response_hours, "next_update_hours": self.next_update_hours,
                "resolution_hours": self.resolution_hours}


@dataclass(frozen=True, slots=True)
class Queue:
    """A queue needs a real owner; a queue with none is refused unless it is the last resort (A7)."""

    queue_id: str
    owner: str                     # operator handle, e.g. operator:care-partner
    display_name: str              # customer-facing, never a person's name (decision 2)
    last_resort: bool = False

    def __post_init__(self) -> None:
        _identifier(self.queue_id, "queue_id")
        _actor(self.owner)
        _text(self.display_name, "queue display_name")

    def to_dict(self) -> dict[str, Any]:
        return {"queue_id": self.queue_id, "owner": self.owner, "display_name": self.display_name,
                "last_resort": self.last_resort}


@dataclass(frozen=True, slots=True)
class RoutingPolicy:
    """Declared care configuration: hours, targets per support level, queues, routes per issue
    class, retention, region and courier, pilot authorities. Validated completely on construction
    (every problem, not the first) so a wrong policy never composes."""

    policy_id: str
    version: str
    timezone: str
    business_days: tuple[int, ...]              # ISO weekdays, 1 = Monday
    business_start_hour: int
    business_end_hour: int
    targets: Mapping[str, Targets]              # support level -> targets
    queues: Mapping[str, Queue]
    routes: Mapping[IssueClass, str]            # issue class -> queue id
    retention_months_after_close: int
    region: str
    courier: str
    pilot_authorities: Mapping[str, str] = field(default_factory=dict)   # domain -> role (never a name)
    default_support_level: str = "free"

    def __post_init__(self) -> None:
        problems = self.problems()
        if problems:
            raise CareContractError("; ".join(problems))

    def problems(self) -> list[str]:
        out: list[str] = []
        for name in ("policy_id", "version", "timezone", "region", "courier"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                out.append(f"{name} is required")
        if not self.business_days or any(not isinstance(d, int) or d < 1 or d > 7 for d in self.business_days):
            out.append("business_days must be ISO weekdays 1..7")
        if not (0 <= self.business_start_hour < self.business_end_hour <= 24):
            out.append("business hours must satisfy 0 <= start < end <= 24")
        if not self.targets:
            out.append("at least one support level with targets is required")
        if self.default_support_level not in self.targets:
            out.append(f"default_support_level {self.default_support_level!r} has no targets")
        if not self.queues:
            out.append("at least one queue is required")
        last_resort = [q for q in self.queues.values() if q.last_resort]
        if len(last_resort) != 1:
            out.append("exactly one queue must be the last resort")
        for issue in IssueClass:
            if issue not in self.routes:
                out.append(f"no route for issue class {issue.value}")
            elif self.routes[issue] not in self.queues:
                out.append(f"route for {issue.value} names unknown queue {self.routes[issue]!r}")
        if isinstance(self.retention_months_after_close, bool) or not isinstance(self.retention_months_after_close, int) \
                or self.retention_months_after_close < 1:
            out.append("retention_months_after_close must be a positive integer")
        return out

    def queue_for(self, issue: IssueClass) -> Queue:
        return self.queues[self.routes[issue]]

    def targets_for(self, support_level: str) -> Targets:
        return self.targets.get(support_level) or self.targets[self.default_support_level]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id, "version": self.version, "timezone": self.timezone,
            "business_days": list(self.business_days), "business_start_hour": self.business_start_hour,
            "business_end_hour": self.business_end_hour,
            "targets": {level: t.to_dict() for level, t in sorted(self.targets.items())},
            "queues": {qid: q.to_dict() for qid, q in sorted(self.queues.items())},
            "routes": {issue.value: qid for issue, qid in sorted(self.routes.items(), key=lambda kv: kv[0].value)},
            "retention_months_after_close": self.retention_months_after_close, "region": self.region,
            "courier": self.courier, "pilot_authorities": dict(sorted(self.pilot_authorities.items())),
            "default_support_level": self.default_support_level,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RoutingPolicy":
        return cls(
            policy_id=str(data["policy_id"]), version=str(data["version"]), timezone=str(data["timezone"]),
            business_days=tuple(int(d) for d in data["business_days"]),
            business_start_hour=int(data["business_start_hour"]), business_end_hour=int(data["business_end_hour"]),
            targets={str(k): Targets(**{n: int(v[n]) for n in ("first_response_hours", "next_update_hours", "resolution_hours")})
                     for k, v in dict(data["targets"]).items()},
            queues={str(k): Queue(str(v["queue_id"]), str(v["owner"]), str(v["display_name"]), bool(v.get("last_resort", False)))
                    for k, v in dict(data["queues"]).items()},
            routes={IssueClass(str(k)): str(v) for k, v in dict(data["routes"]).items()},
            retention_months_after_close=int(data["retention_months_after_close"]),
            region=str(data["region"]), courier=str(data["courier"]),
            pilot_authorities={str(k): str(v) for k, v in dict(data.get("pilot_authorities", {})).items()},
            default_support_level=str(data.get("default_support_level", "free")),
        )


def business_deadline(start: datetime, hours: int, policy: RoutingPolicy) -> datetime:
    """The instant `hours` business hours after `start` under the policy's calendar (decision 1),
    counted only inside business days and hours in the policy's timezone; deterministic and
    computed once at intake, then stored (A9). Daylight saving is handled by the zone itself."""
    from zoneinfo import ZoneInfo

    zone = ZoneInfo(policy.timezone)
    cursor = start.astimezone(zone)
    remaining = timedelta(hours=hours)
    if hours <= 0:
        return start.astimezone(timezone.utc)
    for _ in range(10_000):                     # bounded: 10k iterations covers years of holidays
        day_ok = cursor.isoweekday() in policy.business_days
        day_start = cursor.replace(hour=policy.business_start_hour, minute=0, second=0, microsecond=0)
        day_end = cursor.replace(hour=policy.business_end_hour, minute=0, second=0, microsecond=0) \
            if policy.business_end_hour < 24 else (cursor.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
        if not day_ok or cursor >= day_end:
            cursor = (cursor + timedelta(days=1)).replace(hour=policy.business_start_hour, minute=0, second=0, microsecond=0)
            continue
        if cursor < day_start:
            cursor = day_start
        available = day_end - cursor
        if remaining <= available:
            return (cursor + remaining).astimezone(timezone.utc)
        remaining -= available
        cursor = (cursor + timedelta(days=1)).replace(hour=policy.business_start_hour, minute=0, second=0, microsecond=0)
    raise CareContractError("business_deadline did not converge")


# --- the case and its events ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    workspace_id: str
    subscription_id: str
    account_id: str
    principal: str                              # the customer principal who opened it
    issue_class: IssueClass
    impact: Impact
    urgency: Urgency
    description: str                            # customer-safe, scanned
    references: tuple[CaseReference, ...]
    state: CaseState
    public_reason: str                          # the state in the customer's words
    queue_id: str
    owner_class: OwnerClass
    assigned_to: str                            # operator handle or ""
    support_level: str
    first_response_due_at: datetime | None
    next_update_due_at: datetime | None
    resolution_due_at: datetime | None
    policy_digest: str                          # the routing policy that decided the targets (A8)
    data_class: str
    retention_months_after_close: int
    legal_hold: bool
    created_at: datetime
    updated_at: datetime
    action_id: str                              # the creation idempotency key (10.A)
    revision: int = 1
    head_digest: str = ""                       # digest of the last event (the chain head)
    duplicate_of: str = ""
    incident_id: str = ""
    remedy: RemedyLink | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    reopened_from: str = ""                     # the event id of the resolution or close it reopened

    def __post_init__(self) -> None:
        for name in ("case_id", "workspace_id", "subscription_id", "account_id", "principal", "queue_id",
                     "support_level", "action_id"):
            _identifier(getattr(self, name), name)
        for name in ("duplicate_of", "incident_id", "assigned_to", "reopened_from"):
            _optional_identifier(getattr(self, name), name)
        if not isinstance(self.issue_class, IssueClass) or not isinstance(self.impact, Impact) \
                or not isinstance(self.urgency, Urgency) or not isinstance(self.state, CaseState) \
                or not isinstance(self.owner_class, OwnerClass):
            raise CareContractError("issue_class, impact, urgency, state and owner_class must be their enums")
        _text(self.description, "description")
        _text(self.public_reason, "public_reason")
        if not isinstance(self.references, tuple) or len(self.references) > MAX_REFERENCES \
                or any(not isinstance(r, CaseReference) for r in self.references):
            raise CareContractError(f"references must be a tuple of at most {MAX_REFERENCES} CaseReference")
        if not _SHA256.fullmatch(self.policy_digest):
            raise CareContractError("policy_digest must be the routing policy's SHA-256")
        if self.head_digest and not _SHA256.fullmatch(self.head_digest):
            raise CareContractError("head_digest must be a SHA-256 or empty")
        if self.data_class not in ("pii", "confidential", "public"):
            raise CareContractError("data_class must be pii, confidential or public")
        if isinstance(self.retention_months_after_close, bool) or self.retention_months_after_close < 1:
            raise CareContractError("retention_months_after_close must be positive")
        if isinstance(self.revision, bool) or self.revision < 1:
            raise CareContractError("revision starts at 1")
        if self.remedy is not None and not isinstance(self.remedy, RemedyLink):
            raise CareContractError("remedy must be a RemedyLink")
        if self.state is CaseState.RESOLVED and self.resolved_at is None:
            raise CareContractError("a resolved case carries resolved_at")
        if self.state is CaseState.CLOSED and self.closed_at is None:
            raise CareContractError("a closed case carries closed_at")
        for name in ("created_at", "updated_at"):
            object.__setattr__(self, name, _time(getattr(self, name), name))
        for name in ("first_response_due_at", "next_update_due_at", "resolution_due_at", "resolved_at", "closed_at"):
            object.__setattr__(self, name, _optional_time(getattr(self, name), name))

    @property
    def open(self) -> bool:
        return self.state in OPEN_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "workspace_id": self.workspace_id, "subscription_id": self.subscription_id,
            "account_id": self.account_id, "principal": self.principal, "issue_class": self.issue_class.value,
            "impact": self.impact.value, "urgency": self.urgency.value, "description": self.description,
            "references": [r.to_dict() for r in self.references], "state": self.state.value,
            "public_reason": self.public_reason, "queue_id": self.queue_id, "owner_class": self.owner_class.value,
            "assigned_to": self.assigned_to, "support_level": self.support_level,
            "first_response_due_at": _iso(self.first_response_due_at), "next_update_due_at": _iso(self.next_update_due_at),
            "resolution_due_at": _iso(self.resolution_due_at), "policy_digest": self.policy_digest,
            "data_class": self.data_class, "retention_months_after_close": self.retention_months_after_close,
            "legal_hold": self.legal_hold, "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
            "action_id": self.action_id, "revision": self.revision, "head_digest": self.head_digest,
            "duplicate_of": self.duplicate_of, "incident_id": self.incident_id,
            "remedy": None if self.remedy is None else self.remedy.to_dict(),
            "resolved_at": _iso(self.resolved_at), "closed_at": _iso(self.closed_at), "reopened_from": self.reopened_from,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Case":
        return cls(
            case_id=str(data["case_id"]), workspace_id=str(data["workspace_id"]), subscription_id=str(data["subscription_id"]),
            account_id=str(data["account_id"]), principal=str(data["principal"]), issue_class=IssueClass(str(data["issue_class"])),
            impact=Impact(str(data["impact"])), urgency=Urgency(str(data["urgency"])), description=str(data["description"]),
            references=tuple(CaseReference.from_dict(r) for r in data.get("references", ())), state=CaseState(str(data["state"])),
            public_reason=str(data["public_reason"]), queue_id=str(data["queue_id"]), owner_class=OwnerClass(str(data["owner_class"])),
            assigned_to=str(data.get("assigned_to", "")), support_level=str(data["support_level"]),
            first_response_due_at=_opt_parse(data.get("first_response_due_at")), next_update_due_at=_opt_parse(data.get("next_update_due_at")),
            resolution_due_at=_opt_parse(data.get("resolution_due_at")), policy_digest=str(data["policy_digest"]),
            data_class=str(data["data_class"]), retention_months_after_close=int(data["retention_months_after_close"]),
            legal_hold=bool(data.get("legal_hold", False)), created_at=_parse_time(data["created_at"]),
            updated_at=_parse_time(data["updated_at"]), action_id=str(data["action_id"]), revision=int(data.get("revision", 1)),
            head_digest=str(data.get("head_digest", "")), duplicate_of=str(data.get("duplicate_of", "")),
            incident_id=str(data.get("incident_id", "")),
            remedy=None if data.get("remedy") is None else RemedyLink.from_dict(data["remedy"]),
            resolved_at=_opt_parse(data.get("resolved_at")), closed_at=_opt_parse(data.get("closed_at")),
            reopened_from=str(data.get("reopened_from", "")),
        )


@dataclass(frozen=True, slots=True)
class CaseEvent:
    """One append-only, chained statement about a case. `digest` covers everything but itself."""

    event_id: str
    case_id: str
    seq: int
    kind: EventKind
    visibility: EventVisibility
    actor: str                                  # role:handle
    at: datetime
    body: str                                   # customer-safe text (public) or the protected note (internal)
    data: Mapping[str, Any]                     # small structured facts (state from/to, reference, remedy)
    prior_digest: str                           # "" for the first event
    digest: str = ""                            # filled by `sealed()`

    def __post_init__(self) -> None:
        _identifier(self.event_id, "event_id")
        _identifier(self.case_id, "case_id")
        if isinstance(self.seq, bool) or self.seq < 1:
            raise CareContractError("seq starts at 1")
        if not isinstance(self.kind, EventKind) or not isinstance(self.visibility, EventVisibility):
            raise CareContractError("kind and visibility must be their enums")
        if self.kind in INTERNAL_KINDS and self.visibility is not EventVisibility.INTERNAL:
            raise CareContractError(f"{self.kind.value} is internal by construction")
        _actor(self.actor)
        object.__setattr__(self, "at", _time(self.at, "at"))
        _text(self.body, "body", allow_empty=True)
        if not isinstance(self.data, Mapping):
            raise CareContractError("data must be a mapping")
        if self.prior_digest and not _SHA256.fullmatch(self.prior_digest):
            raise CareContractError("prior_digest must be a SHA-256 or empty")
        if self.digest and not _SHA256.fullmatch(self.digest):
            raise CareContractError("digest must be a SHA-256 or empty")

    def canonical_payload(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "case_id": self.case_id, "seq": self.seq, "kind": self.kind.value,
                "visibility": self.visibility.value, "actor": self.actor, "at": self.at.isoformat(), "body": self.body,
                "data": dict(self.data), "prior_digest": self.prior_digest}

    def sealed(self) -> "CaseEvent":
        """The event with its digest computed over its canonical payload (which includes prior_digest)."""
        payload = self.canonical_payload()
        return CaseEvent(**{**payload, "kind": self.kind, "visibility": self.visibility, "at": self.at,
                            "digest": canonical_digest(payload)})

    def verify(self) -> bool:
        return self.digest == canonical_digest(self.canonical_payload())

    def to_dict(self) -> dict[str, Any]:
        return {**self.canonical_payload(), "digest": self.digest}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CaseEvent":
        return cls(str(data["event_id"]), str(data["case_id"]), int(data["seq"]), EventKind(str(data["kind"])),
                   EventVisibility(str(data["visibility"])), str(data["actor"]), _parse_time(data["at"]), str(data["body"]),
                   dict(data.get("data", {})), str(data.get("prior_digest", "")), str(data.get("digest", "")))


def verify_chain(events: tuple[CaseEvent, ...] | list[CaseEvent]) -> list[str]:
    """Every break in a case's chain, in order (empty means intact): seq gaps, a prior_digest that is
    not the previous digest, a digest that does not match its payload."""
    problems: list[str] = []
    prior = ""
    for index, event in enumerate(events, start=1):
        if event.seq != index:
            problems.append(f"event {event.event_id}: seq {event.seq} != {index}")
        if event.prior_digest != prior:
            problems.append(f"event {event.event_id}: prior_digest does not match the previous event")
        if not event.verify():
            problems.append(f"event {event.event_id}: digest does not match its payload")
        prior = event.digest
    return problems


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _opt_parse(value: Any) -> datetime | None:
    return None if value is None else _parse_time(value)


__all__ = [
    "check_action_id",
    "INTERNAL_KINDS", "MAX_REFERENCES", "MAX_TEXT", "OPEN_STATES", "REGULATED_CLASSES", "TRANSITIONS",
    "Case", "CaseEvent", "CaseReference", "CaseState", "CareConflict", "CareContractError", "CareRefused",
    "CareUnavailable", "EventKind", "EventVisibility", "Impact", "IssueClass", "OwnerClass", "Queue",
    "ReferenceKind", "RemedyLink", "Role", "RoutingPolicy", "Targets", "Urgency", "business_deadline",
    "canonical_digest", "canonical_json", "transition", "verify_chain",
]
