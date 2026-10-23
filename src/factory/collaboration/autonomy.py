"""Authority and lifecycle records for the durable collaboration supervisor.

These records contain bounds only.  They do not grant commit, push, release,
approval, deployment, publication, or any other consequential effect.  A
canonical authorization digest makes a changed bound a new authorization, so
an attempt can never continue under silently widened authority.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from factory.collaboration.contracts import (
    ContractViolation,
    EffectClass,
    ParticipantRole,
    TrustClass,
    canonical_digest,
)


class AutonomyMode(str, Enum):
    OFF = "off"
    SUPERVISED = "supervised"
    CONTINUOUS = "continuous"


class RunStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    HARD_STOPPED = "hard_stopped"


class TicketStatus(str, Enum):
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    ACKNOWLEDGED = "acknowledged"
    STRANDED = "stranded"
    ARTIFACT_SUBMITTED = "artifact_submitted"
    REVIEW_QUEUED = "review_queued"
    REVISION_REQUESTED = "revision_requested"
    COMPLETED = "completed"
    FAILED = "failed"


def _text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractViolation(f"{name} must be a non-blank string")
    return value


def _digest(value: str, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ContractViolation(f"{name} must be a lowercase sha256 digest")
    return value


def _money(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractViolation(f"{name} must be a number")
    if not math.isfinite(value) or value < 0:
        raise ContractViolation(f"{name} must be finite and non-negative")
    return float(value)


@dataclass(frozen=True, slots=True)
class WorkerGrant:
    """One qualified participant lane, including the billing fact it uses."""

    participant_id: str
    lane: str
    billing_mode: str
    qualification_digest: str

    def __post_init__(self) -> None:
        _text(self.participant_id, "participant_id")
        _text(self.lane, "lane")
        _text(self.billing_mode, "billing_mode")
        _digest(self.qualification_digest, "qualification_digest")

    def canonical_payload(self) -> dict[str, str]:
        return {
            "participant_id": self.participant_id,
            "lane": self.lane,
            "billing_mode": self.billing_mode,
            "qualification_digest": self.qualification_digest,
        }


@dataclass(frozen=True, slots=True)
class RunDefinition:
    """The immutable owner-approved work graph boundary for one run."""

    tenant_id: str
    run_id: str
    objective_digest: str
    acceptance_gate_digest: str
    protocol_digest: str
    context_digest: str
    graph_digest: str

    def __post_init__(self) -> None:
        _text(self.tenant_id, "tenant_id")
        _text(self.run_id, "run_id")
        for name in (
            "objective_digest",
            "acceptance_gate_digest",
            "protocol_digest",
            "context_digest",
            "graph_digest",
        ):
            _digest(getattr(self, name), name)

    def canonical_payload(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "objective_digest": self.objective_digest,
            "acceptance_gate_digest": self.acceptance_gate_digest,
            "protocol_digest": self.protocol_digest,
            "context_digest": self.context_digest,
            "graph_digest": self.graph_digest,
        }


@dataclass(frozen=True, slots=True)
class AutonomyAuthorization:
    """Exact owner authorization.  Mutation changes ``authorization_digest``."""

    run: RunDefinition
    owner_actor_id: str
    owner_authentication_digest: str
    mode: AutonomyMode
    issued_at: float
    expires_at: float
    budget_ceiling_usd: float
    per_ticket_ceiling_usd: float
    max_retries: int
    takeover_participants: tuple[str, ...]
    workers: tuple[WorkerGrant, ...]
    allowed_effects: tuple[EffectClass, ...] = (EffectClass.READ_ONLY, EffectClass.ROUTINE)

    def __post_init__(self) -> None:
        if not isinstance(self.run, RunDefinition):
            raise ContractViolation("run must be a RunDefinition")
        _text(self.owner_actor_id, "owner_actor_id")
        _digest(self.owner_authentication_digest, "owner_authentication_digest")
        if not isinstance(self.mode, AutonomyMode) or self.mode is AutonomyMode.OFF:
            raise ContractViolation("authorization mode must be supervised or continuous")
        if not all(isinstance(value, (int, float)) and math.isfinite(value)
                   for value in (self.issued_at, self.expires_at)):
            raise ContractViolation("authorization timestamps must be finite numbers")
        if self.expires_at <= self.issued_at:
            raise ContractViolation("authorization expiry must be after issuance")
        _money(self.budget_ceiling_usd, "budget_ceiling_usd")
        _money(self.per_ticket_ceiling_usd, "per_ticket_ceiling_usd")
        if self.per_ticket_ceiling_usd > self.budget_ceiling_usd:
            raise ContractViolation("per-ticket ceiling cannot exceed run ceiling")
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ContractViolation("max_retries must be a non-negative integer")
        if not isinstance(self.takeover_participants, tuple) or not isinstance(self.workers, tuple):
            raise ContractViolation("takeover participants and workers must be immutable tuples")
        if not isinstance(self.allowed_effects, tuple):
            raise ContractViolation("allowed_effects must be an immutable tuple")
        if not self.workers:
            raise ContractViolation("at least one qualified worker is required")
        worker_ids = [worker.participant_id for worker in self.workers]
        if len(set(worker_ids)) != len(worker_ids):
            raise ContractViolation("worker participant ids must be unique")
        if len(set(self.takeover_participants)) != len(self.takeover_participants):
            raise ContractViolation("takeover participants must be unique")
        if any(participant not in worker_ids for participant in self.takeover_participants):
            raise ContractViolation("every takeover participant must be a qualified worker")
        if (not self.allowed_effects
                or any(not isinstance(effect, EffectClass) for effect in self.allowed_effects)
                or EffectClass.CONSEQUENTIAL in self.allowed_effects):
            raise ContractViolation("autonomy may allow only read-only or routine effects")
        if len(set(self.allowed_effects)) != len(self.allowed_effects):
            raise ContractViolation("allowed effects must be unique")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "run": self.run.canonical_payload(),
            "owner_actor_id": self.owner_actor_id,
            "owner_authentication_digest": self.owner_authentication_digest,
            "mode": self.mode.value,
            "issued_at": float(self.issued_at),
            "expires_at": float(self.expires_at),
            "budget_ceiling_usd": float(self.budget_ceiling_usd),
            "per_ticket_ceiling_usd": float(self.per_ticket_ceiling_usd),
            "max_retries": self.max_retries,
            "takeover_participants": list(self.takeover_participants),
            "workers": [worker.canonical_payload() for worker in self.workers],
            "allowed_effects": [effect.value for effect in self.allowed_effects],
        }

    @property
    def authorization_digest(self) -> str:
        return canonical_digest(self.canonical_payload())

    def worker(self, participant_id: str) -> WorkerGrant | None:
        return next((worker for worker in self.workers if worker.participant_id == participant_id), None)


@dataclass(frozen=True, slots=True)
class OwnerCommand:
    """Authentication result attached to an owner lifecycle command."""

    actor_id: str
    trust: TrustClass
    authenticated: bool
    authentication_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        _text(self.actor_id, "actor_id")
        if not isinstance(self.trust, TrustClass):
            raise ContractViolation("trust must be a TrustClass")
        if not isinstance(self.authenticated, bool):
            raise ContractViolation("authenticated must be boolean")
        _digest(self.authentication_digest, "authentication_digest")
        _text(self.idempotency_key, "idempotency_key")

    @property
    def is_owner(self) -> bool:
        return self.authenticated and self.trust is TrustClass.OWNER


@dataclass(frozen=True, slots=True)
class WorkspaceGraphCommand:
    """Server-resolved customer authority for one tenant and exact work graph.

    This is not installation-owner authority and cannot authorize autonomous
    dispatch, credentials, release, or another graph. Only graph preparation
    and ticket materialization consume it.
    """

    tenant_id: str
    graph_digest: str
    actor_id: str
    authentication_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "actor_id", "idempotency_key"):
            _text(getattr(self, name), name)
        _digest(self.graph_digest, "graph_digest")
        _digest(self.authentication_digest, "authentication_digest")


@dataclass(frozen=True, slots=True)
class WorkspaceRunCommand:
    """Server-resolved customer authority for one tenant and ONE collaboration run.

    A customer must always be able to stop their own work: the supervisor accepts this command for pause,
    disable and a ticket's cancellation request. It also starts the customer's OWN work, under kernel laws
    the command cannot widen: an authorization it issues must name its own actor and authentication
    receipt, may allow NO automatic retry and NO takeover pool (a stranded attempt may have been charged, so
    only an explicit, acknowledged re-attempt ever runs it again); resume requires a paused run whose
    authorization is still in force; a re-attempt is one explicit grant per stranded attempt. It never
    attests cost (resolving a stranded reservation stays with owner authority) and never reassigns under
    an automatic recovery policy. Which workers it may name is the composition's decision: the customer
    worker plane admits only the workspace's own qualified connected lanes. The actor comes from the
    verified session, never from a request body.
    """

    tenant_id: str
    run_id: str
    actor_id: str
    authentication_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "run_id", "actor_id", "idempotency_key"):
            _text(getattr(self, name), name)
        _digest(self.authentication_digest, "authentication_digest")


@dataclass(frozen=True, slots=True)
class AttemptSignal:
    """Authenticated ACK/heartbeat identity.  It deliberately has no clock."""

    tenant_id: str
    run_id: str
    ticket_id: str
    attempt_id: str
    participant_id: str
    authentication_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "run_id", "ticket_id", "attempt_id",
                     "participant_id", "idempotency_key"):
            _text(getattr(self, name), name)
        _digest(self.authentication_digest, "authentication_digest")


@dataclass(frozen=True, slots=True)
class ArtifactSignal(AttemptSignal):
    artifact_digest: str

    def __post_init__(self) -> None:
        super(ArtifactSignal, self).__post_init__()
        _digest(self.artifact_digest, "artifact_digest")


@dataclass(frozen=True, slots=True)
class ClaimedAttempt:
    tenant_id: str
    run_id: str
    ticket_id: str
    ticket_digest: str
    attempt_id: str
    attempt_number: int
    participant_id: str
    authorization_digest: str
    reservation_id: str
    reservation_usd: float
    billing_mode: str
    lane: str
    ack_deadline_at: float
    lease_expires_at: float
    # Section 43/44: the REQUIRED typed seat this attempt occupies and, for a
    # REVIEW attempt, the exact queued author-artifact digest - both from the
    # event store, never a browser, prompt, or provider. No default: an old or
    # malformed constructor can never silently become an author.
    role: ParticipantRole
    review_artifact_digest: str = ""
    revision_findings_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.role, ParticipantRole):
            raise ContractViolation("claim role must be a ParticipantRole")
        if self.role is ParticipantRole.REVIEWER:
            _digest(self.review_artifact_digest, "review_artifact_digest")
            if self.revision_findings_digest != "":
                raise ContractViolation("only an author claim may carry findings")
        else:
            if self.review_artifact_digest != "":
                raise ContractViolation("only a review claim may carry an artifact digest")
            if self.revision_findings_digest != "":
                _digest(self.revision_findings_digest, "revision_findings_digest")
