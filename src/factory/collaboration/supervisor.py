"""Restart-safe, zero-spend reconciliation kernel for governed collaboration."""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Protocol, cast

from factory.collaboration.autonomy import (
    ArtifactSignal,
    AttemptSignal,
    AutonomyAuthorization,
    AutonomyMode,
    ClaimedAttempt,
    OwnerCommand,
    RunDefinition,
    RunStatus,
    WorkerGrant,
    WorkspaceGraphCommand,
    WorkspaceRunCommand,
)
from factory.collaboration.contracts import (
    DispatchReceipt,
    EffectClass,
    LeasePolicy,
    NetworkMode,
    ParticipantRole,
    RoleBinding,
    VisibilityPhase,
    WorkTicket,
)
from factory.collaboration.store import (
    CollaborationStore,
    EventDraft,
    StoreConflict,
    StorePlan,
    SupervisorEvent,
    SupervisorEventType,
)
from factory.collaboration.transport import ParticipantTransport


class AuthorityRefused(StoreConflict):
    """The requested transition exceeds or does not match durable authority."""


@dataclass(frozen=True, slots=True)
class CycleResult:
    claimed: ClaimedAttempt | None
    transport_called: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ConfirmedWorkGuard:
    """An explicit bounded job may only consume the exact lifecycle the customer confirmed."""

    authorization_digest: str
    lifecycle_sequence: int


LIFECYCLE_EVENTS = frozenset({"authorization_changed", "run_paused", "run_resumed", "stopping", "hard_stopped"})


def lifecycle_sequence(events: tuple[SupervisorEvent, ...]) -> int:
    return max((e.sequence for e in events if e.event_type.value in LIFECYCLE_EVENTS), default=0)


@dataclass(frozen=True, slots=True)
class NativeCycleResult:
    invocation_digest: str | None
    invoked: bool
    reconciled: bool
    reason: str


class NativeCyclePort(Protocol):
    """Composition-owned native extension without importing a product engine."""

    def cycle(self, tenant_id: str, goal_id: str, task_id: str) -> NativeCycleResult: ...


@dataclass(slots=True)
class _AttemptState:
    attempt_id: str
    ticket_id: str
    attempt_number: int
    participant_id: str
    role: ParticipantRole
    authorization_digest: str
    qualification_digest: str
    reservation_id: str
    reservation_usd: float
    billing_mode: str
    lane: str
    ack_deadline_at: float
    lease_expires_at: float
    acknowledged: bool = False
    stranded: bool = False
    settled: bool = False
    released: bool = False


@dataclass(slots=True)
class _TicketState:
    ticket: WorkTicket
    branch_approved: bool
    status: str = "queued"
    current_author: str = ""
    queued_artifact_digest: str = ""
    revision_findings_digest: str = ""
    attempts: list[_AttemptState] = field(default_factory=list)
    # The participant an explicit, not-yet-dispatched re-attempt grant names (empty when none). The next
    # reserved attempt consumes it; it is the ONLY way past the automatic retry allowance.
    pending_grant: str = ""
    # How many explicit re-attempts were granted: each one offsets exactly one stranding in the retry count.
    granted_attempts: int = 0

    def __post_init__(self) -> None:
        if not self.current_author:
            self.current_author = self.ticket.participant_for(ParticipantRole.AUTHOR) or ""


@dataclass(slots=True)
class _RunState:
    definition: RunDefinition | None = None
    authorization: AutonomyAuthorization | None = None
    effective_expires_at: float = 0.0
    status: RunStatus = RunStatus.STOPPED
    tickets: dict[str, _TicketState] = field(default_factory=dict)
    spent_usd: float = 0.0
    reserved_usd: float = 0.0

def _ticket_payload(ticket: WorkTicket) -> dict[str, object]:
    return ticket.canonical_payload()


def _ticket_from_payload(payload: object) -> WorkTicket:
    if not isinstance(payload, dict):
        raise StoreConflict("persisted ticket payload is invalid")
    roles_raw = payload.get("roles")
    lease_raw = payload.get("lease")
    if not isinstance(roles_raw, list) or not isinstance(lease_raw, dict):
        raise StoreConflict("persisted ticket roles or lease are invalid")
    return WorkTicket(
        ticket_id=str(payload["ticket_id"]),
        tenant_id=str(payload["tenant_id"]),
        project_ref=str(payload["project_ref"]),
        source_snapshot_digest=str(payload["source_snapshot_digest"]),
        roles=tuple(RoleBinding(ParticipantRole(str(role["role"])), str(role["participant_id"]))
                    for role in roles_raw if isinstance(role, dict)),
        protocol_phase=str(payload["protocol_phase"]),
        visibility=VisibilityPhase(str(payload["visibility"])),
        allowed_tools=tuple(str(value) for value in cast(list[object], payload["allowed_tools"])),
        allowed_paths=tuple(str(value) for value in cast(list[object], payload["allowed_paths"])),
        network_mode=NetworkMode(str(payload["network_mode"])),
        effect_class=EffectClass(str(payload["effect_class"])),
        reservation_id=str(payload["reservation_id"]),
        ceiling_usd=float(cast(float, payload["ceiling_usd"])),
        expected_artifact=str(payload["expected_artifact"]),
        lease=LeasePolicy(
            ack_deadline_s=int(cast(int, lease_raw["ack_deadline_s"])),
            lease_s=int(cast(int, lease_raw["lease_s"])),
            max_retries=int(cast(int, lease_raw["max_retries"])),
            reassignment=str(lease_raw["reassignment"]),
        ),
        dependencies=tuple(str(value) for value in cast(list[object], payload["dependencies"])),
        acceptance_gate=str(payload["acceptance_gate"]),
        idempotency_key=str(payload["idempotency_key"]),
    )


def _run_from_payload(payload: object) -> RunDefinition:
    if not isinstance(payload, dict):
        raise StoreConflict("persisted run definition is invalid")
    return RunDefinition(**{name: str(payload[name]) for name in (
        "tenant_id", "run_id", "objective_digest", "acceptance_gate_digest",
        "protocol_digest", "context_digest", "graph_digest")})


def _authorization_from_payload(payload: object) -> AutonomyAuthorization:
    if not isinstance(payload, dict):
        raise StoreConflict("persisted authorization is invalid")
    run = _run_from_payload(payload["run"])
    workers_raw = payload["workers"]
    if not isinstance(workers_raw, list):
        raise StoreConflict("persisted workers are invalid")
    workers = tuple(WorkerGrant(
        participant_id=str(item["participant_id"]),
        lane=str(item["lane"]),
        billing_mode=str(item["billing_mode"]),
        qualification_digest=str(item["qualification_digest"]),
    ) for item in workers_raw if isinstance(item, dict))
    return AutonomyAuthorization(
        run=run,
        owner_actor_id=str(payload["owner_actor_id"]),
        owner_authentication_digest=str(payload["owner_authentication_digest"]),
        mode=AutonomyMode(str(payload["mode"])),
        issued_at=float(cast(float, payload["issued_at"])),
        expires_at=float(cast(float, payload["expires_at"])),
        budget_ceiling_usd=float(cast(float, payload["budget_ceiling_usd"])),
        per_ticket_ceiling_usd=float(cast(float, payload["per_ticket_ceiling_usd"])),
        max_retries=int(cast(int, payload["max_retries"])),
        takeover_participants=tuple(str(value) for value in cast(list[object], payload["takeover_participants"])),
        workers=workers,
        allowed_effects=tuple(EffectClass(str(value))
                              for value in cast(list[object], payload["allowed_effects"])),
    )


def _project(events: tuple[SupervisorEvent, ...]) -> _RunState:
    state = _RunState()
    attempts: dict[str, _AttemptState] = {}
    for event in events:
        p = event.payload
        if event.event_type is SupervisorEventType.RUN_CREATED:
            state.definition = _run_from_payload(p["run"])
        elif event.event_type is SupervisorEventType.AUTHORIZATION_CHANGED:
            if p.get("mode") == AutonomyMode.OFF.value:
                state.authorization = None
                state.status = RunStatus.STOPPING
            else:
                state.authorization = _authorization_from_payload(p["authorization"])
                state.effective_expires_at = float(cast(float, p["effective_expires_at"]))
                state.status = RunStatus.ACTIVE
        elif event.event_type is SupervisorEventType.TICKET_QUEUED:
            queued_ticket = _ticket_from_payload(p["ticket"])
            state.tickets[queued_ticket.ticket_id] = _TicketState(
                ticket=queued_ticket, branch_approved=bool(p["branch_approved"]))
        elif event.event_type is SupervisorEventType.BUDGET_RESERVED:
            ticket_state = state.tickets[event.ticket_id]
            role = ParticipantRole(str(p["role"]))
            attempt = _AttemptState(
                attempt_id=str(p["attempt_id"]), ticket_id=event.ticket_id,
                attempt_number=int(cast(int, p["attempt_number"])),
                participant_id=str(p["participant_id"]), role=role,
                authorization_digest=str(p["authorization_digest"]),
                qualification_digest=str(p["qualification_digest"]),
                reservation_id=str(p["reservation_id"]),
                reservation_usd=float(cast(float, p["reservation_usd"])),
                billing_mode=str(p["billing_mode"]), lane=str(p["lane"]),
                ack_deadline_at=float(cast(float, p["ack_deadline_at"])),
                lease_expires_at=float(cast(float, p["lease_expires_at"])),
            )
            ticket_state.attempts.append(attempt)
            ticket_state.pending_grant = ""
            attempts[attempt.attempt_id] = attempt
            state.reserved_usd += attempt.reservation_usd
        elif event.event_type is SupervisorEventType.TICKET_DISPATCHED:
            state.tickets[event.ticket_id].status = "dispatched"
        elif event.event_type is SupervisorEventType.TICKET_ACKNOWLEDGED:
            attempt = attempts[str(p["attempt_id"])]
            attempt.acknowledged = True
            attempt.lease_expires_at = float(cast(float, p["lease_expires_at"]))
            state.tickets[event.ticket_id].status = "acknowledged"
        elif event.event_type is SupervisorEventType.HEARTBEAT_RECORDED:
            attempts[str(p["attempt_id"])].lease_expires_at = float(cast(float, p["lease_expires_at"]))
        elif event.event_type is SupervisorEventType.TICKET_STRANDED:
            attempts[str(p["attempt_id"])].stranded = True
            state.tickets[event.ticket_id].status = "stranded"
        elif event.event_type is SupervisorEventType.BUDGET_SETTLED:
            attempt = attempts[str(p["attempt_id"])]
            if not attempt.settled and not attempt.released:
                state.reserved_usd -= attempt.reservation_usd
                state.spent_usd += float(cast(float, p["actual_usd"]))
                attempt.settled = True
        elif event.event_type is SupervisorEventType.RESERVATION_RELEASED:
            attempt = attempts[str(p["attempt_id"])]
            if not attempt.settled and not attempt.released:
                state.reserved_usd -= attempt.reservation_usd
                attempt.released = True
        elif event.event_type is SupervisorEventType.AUTHORSHIP_TRANSFERRED:
            state.tickets[event.ticket_id].current_author = str(p["to_participant_id"])
        elif event.event_type is SupervisorEventType.ATTEMPT_GRANTED:
            state.tickets[event.ticket_id].pending_grant = str(p["participant_id"])
            state.tickets[event.ticket_id].granted_attempts += 1
        elif event.event_type is SupervisorEventType.ARTIFACT_SUBMITTED:
            state.tickets[event.ticket_id].status = "artifact_submitted"
        elif event.event_type is SupervisorEventType.REVIEW_QUEUED:
            queued = state.tickets[event.ticket_id]
            queued.status = "review_queued"
            queued.queued_artifact_digest = str(p.get("artifact_digest", ""))
        elif event.event_type is SupervisorEventType.REVISION_REQUESTED:
            revised = state.tickets[event.ticket_id]
            revised.status = "revision_requested"
            revised.revision_findings_digest = str(p.get("findings_digest", ""))
        elif event.event_type is SupervisorEventType.TICKET_COMPLETED:
            state.tickets[event.ticket_id].status = "completed"
        elif event.event_type is SupervisorEventType.TICKET_FAILED:
            state.tickets[event.ticket_id].status = "failed"
        elif event.event_type is SupervisorEventType.RUN_PAUSED:
            if state.status is RunStatus.ACTIVE:
                state.status = RunStatus.PAUSED
        elif event.event_type is SupervisorEventType.RUN_RESUMED:
            if state.status is RunStatus.PAUSED and state.authorization is not None:
                state.status = RunStatus.ACTIVE
        elif event.event_type is SupervisorEventType.STOPPING:
            state.status = RunStatus.STOPPING
        elif event.event_type is SupervisorEventType.STOPPED:
            state.status = RunStatus.STOPPED
        elif event.event_type is SupervisorEventType.HARD_STOPPED:
            state.status = RunStatus.HARD_STOPPED
    return state


def _existing(events: tuple[SupervisorEvent, ...], key: str,
              event_type: SupervisorEventType, ticket_id: str = "") -> SupervisorEvent | None:
    prior = next((event for event in events if event.idempotency_key == key), None)
    if prior is not None and (prior.event_type is not event_type or prior.ticket_id != ticket_id):
        raise StoreConflict("idempotency key reused across event kind or ticket")
    return prior


def _require_owner(command: object) -> None:
    # Any other authority type (a workspace graph or run command) is refused here, never trusted by shape.
    if not isinstance(command, OwnerCommand) or not command.is_owner:
        raise AuthorityRefused("only authenticated owner authority may change autonomy")


def _require_run_authority(command: OwnerCommand | WorkspaceRunCommand, tenant_id: str, run_id: str) -> None:
    """Owner authority, or a customer's authority for exactly this tenant and run (never by shape alone)."""
    if isinstance(command, WorkspaceRunCommand):
        if command.tenant_id != tenant_id or command.run_id != run_id:
            raise AuthorityRefused("workspace authority names a different tenant or run")
        return
    _require_owner(command)


#: Stop-direction controls accept the same two authorities; the name records the direction at call sites.
_require_stop_authority = _require_run_authority


def _require_workspace_bounds(authorization: AutonomyAuthorization) -> None:
    """Kernel laws a workspace authorization can never widen.

    A stranded attempt's provider call may have been charged and its outcome is unknown, so a workspace run
    never retries automatically and never hands a stranded ticket to a takeover pool: only an explicit,
    acknowledged re-attempt (``grant_attempt``) runs a stranded ticket again.
    """
    if authorization.max_retries != 0:
        raise AuthorityRefused("a workspace authorization allows no automatic retries (max_retries must be 0)")
    if authorization.takeover_participants:
        raise AuthorityRefused("a workspace authorization names no automatic takeover participants")


class CollaborationSupervisor:
    """Durable reconciler.  It contains no model/provider client and spends zero."""

    def __init__(self, store: CollaborationStore,
                 transports: dict[str, ParticipantTransport] | None = None, *,
                 native: NativeCyclePort | None = None) -> None:
        self.store = store
        self.transports = dict(transports or {})
        self.native = native

    def native_cycle(self, tenant_id: str, goal_id: str, task_id: str) -> NativeCycleResult:
        """Advance one adaptive native task through its authoritative root store.

        Composition must supply current server authority and qualified adapters.
        No native execution path is enabled by the default constructor.
        """
        if self.native is None:
            raise AuthorityRefused("native adaptive execution is not configured")
        return self.native.cycle(tenant_id, goal_id, task_id)

    def create_run(self, definition: RunDefinition, command: OwnerCommand | WorkspaceGraphCommand) -> SupervisorEvent:
        self._require_graph_authority(command, definition)
        if definition.tenant_id == "" or definition.run_id == "":  # construction already enforces this
            raise AuthorityRefused("invalid run identity")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, SupervisorEventType.RUN_CREATED)
            if prior is not None:
                return StorePlan((), prior)
            if events:
                raise StoreConflict("run already exists")
            draft = EventDraft(SupervisorEventType.RUN_CREATED, command.idempotency_key,
                               {"run": definition.canonical_payload(), "owner_actor_id": command.actor_id})
            return StorePlan((draft,))

        result = self.store.transact(definition.tenant_id, definition.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def authorize(self, authorization: AutonomyAuthorization,
                  command: OwnerCommand | WorkspaceRunCommand) -> SupervisorEvent:
        """Record an exact authorization: the owner's, or a workspace's own for its own run (bounded)."""
        _require_run_authority(command, authorization.run.tenant_id, authorization.run.run_id)
        if isinstance(command, WorkspaceRunCommand):
            _require_workspace_bounds(authorization)
        if command.actor_id != authorization.owner_actor_id:
            raise AuthorityRefused("owner actor does not match authorization")
        if command.authentication_digest != authorization.owner_authentication_digest:
            raise AuthorityRefused("owner authentication receipt does not match authorization")

        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key,
                              SupervisorEventType.AUTHORIZATION_CHANGED)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            if state.definition is None or state.definition != authorization.run:
                raise AuthorityRefused("authorization does not match the immutable run definition")
            duration = authorization.expires_at - authorization.issued_at
            draft = EventDraft(SupervisorEventType.AUTHORIZATION_CHANGED, command.idempotency_key, {
                "mode": authorization.mode.value,
                "authorization": authorization.canonical_payload(),
                "authorization_digest": authorization.authorization_digest,
                "effective_issued_at": now,
                "effective_expires_at": now + duration,
            })
            return StorePlan((draft,))

        result = self.store.transact(authorization.run.tenant_id, authorization.run.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def disable(self, tenant_id: str, run_id: str,
                command: OwnerCommand | WorkspaceRunCommand) -> SupervisorEvent:
        _require_stop_authority(command, tenant_id, run_id)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, SupervisorEventType.AUTHORIZATION_CHANGED)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            if state.definition is None:
                raise KeyError(run_id)
            changes = (
                EventDraft(SupervisorEventType.AUTHORIZATION_CHANGED, command.idempotency_key,
                           {"mode": AutonomyMode.OFF.value, "owner_actor_id": command.actor_id}),
                EventDraft(SupervisorEventType.STOPPING, f"{command.idempotency_key}:stopping",
                           {"reason": "owner_disabled"}),
            )
            return StorePlan(changes)

        result = self.store.transact(tenant_id, run_id, plan)
        return result.appended[0] if result.appended else cast(SupervisorEvent, result.value)

    def pause(self, tenant_id: str, run_id: str,
              command: OwnerCommand | WorkspaceRunCommand) -> SupervisorEvent:
        """Owner or workspace pause: blocks NEW dispatch only. Scope, leases, and in-flight
        work are untouched; stranding stays honest (C-F3a)."""
        _require_stop_authority(command, tenant_id, run_id)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, SupervisorEventType.RUN_PAUSED)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            if state.definition is None:
                raise KeyError(run_id)
            if state.status is not RunStatus.ACTIVE:
                raise AuthorityRefused(f"pause requires an active run (status: {state.status.value})")
            return StorePlan((EventDraft(SupervisorEventType.RUN_PAUSED, command.idempotency_key,
                                         {"owner_actor_id": command.actor_id}),))

        result = self.store.transact(tenant_id, run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def resume(self, tenant_id: str, run_id: str,
               command: OwnerCommand | WorkspaceRunCommand) -> SupervisorEvent:
        """Resume from pause (owner, or the run's own workspace); refused if the authorization lapsed."""
        _require_run_authority(command, tenant_id, run_id)

        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, SupervisorEventType.RUN_RESUMED)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            if state.definition is None:
                raise KeyError(run_id)
            if state.status is not RunStatus.PAUSED:
                raise AuthorityRefused(f"resume requires a paused run (status: {state.status.value})")
            if state.authorization is None or now >= state.effective_expires_at:
                raise AuthorityRefused("authorization lapsed; a fresh owner authorization is required")
            if isinstance(command, WorkspaceRunCommand):
                _require_workspace_bounds(state.authorization)
            return StorePlan((EventDraft(SupervisorEventType.RUN_RESUMED, command.idempotency_key,
                                         {"owner_actor_id": command.actor_id}),))

        result = self.store.transact(tenant_id, run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def request_cancel(self, tenant_id: str, run_id: str, ticket_id: str,
                       command: OwnerCommand | WorkspaceRunCommand) -> SupervisorEvent:
        """Owner cancellation REQUEST, routed to the qualified transport.

        Two-phase for durability (C-F3a-R2): the request event for the EXACT
        attempt commits BEFORE any external call; the transport's validated
        answer is recorded separately. A retry after an answer returns the
        recorded answer with zero further transport calls; a crash between
        the phases resumes honestly from the durable request. No canceled
        state is ever projected — the lease machinery stays the only
        lifecycle authority (accepted Half B cancellation law)."""
        _require_stop_authority(command, tenant_id, run_id)

        # Phase 1: durably record the request for the exact live attempt (or
        # return the already-recorded answer for it).
        def request_phase(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            state = _project(events)
            ticket = state.tickets.get(ticket_id)
            if ticket is None:
                raise KeyError(ticket_id)
            live = next((attempt for attempt in ticket.attempts
                         if not attempt.stranded and not attempt.settled and not attempt.released),
                        None)
            if live is None or ticket.status not in {"dispatched", "acknowledged"}:
                raise AuthorityRefused("cancellation requires a live dispatched attempt")
            answered = next((event for event in events
                             if event.idempotency_key == f"{live.attempt_id}:cancel-answered"),
                            None)
            if answered is not None:
                return StorePlan((), ("answered", answered))
            prior = _existing(events, f"{live.attempt_id}:cancel-requested",
                              SupervisorEventType.CANCEL_REQUESTED, ticket_id)
            if prior is not None:
                return StorePlan((), ("requested", live.attempt_id, live.participant_id,
                                      live.ticket_id))
            draft = EventDraft(SupervisorEventType.CANCEL_REQUESTED,
                               f"{live.attempt_id}:cancel-requested", {
                "attempt_id": live.attempt_id, "participant_id": live.participant_id,
                "owner_actor_id": command.actor_id,
            }, ticket_id)
            return StorePlan((draft,), ("requested", live.attempt_id, live.participant_id,
                                        live.ticket_id))

        outcome = self.store.transact(tenant_id, run_id, request_phase).value
        assert isinstance(outcome, tuple)
        if outcome[0] == "answered":
            return cast(SupervisorEvent, outcome[1])
        attempt_id, participant = cast(str, outcome[1]), cast(str, outcome[2])

        # External call, outside any store lock. The answer is validated
        # against the claimed identity before it may become durable truth.
        state = _project(self.store.events(tenant_id, run_id))
        expected_digest = state.tickets[ticket_id].ticket.ticket_digest
        transport = self.transports.get(participant)
        if transport is None:
            accepted, detail = False, "worker_transport_unavailable"
        else:
            try:
                receipt = transport.cancel(ticket_id)
                if (receipt.ticket_id != ticket_id
                        or receipt.participant_id != participant
                        or receipt.ticket_digest != expected_digest):
                    accepted, detail = False, "receipt_identity_mismatch"
                else:
                    accepted, detail = receipt.accepted, "transport_answered"
            except Exception as exc:  # noqa: BLE001 - refusal is a truthful outcome
                accepted, detail = False, f"transport_error:{type(exc).__name__}"

        def answer_phase(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, f"{attempt_id}:cancel-answered",
                              SupervisorEventType.CANCEL_ANSWERED, ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            return StorePlan((EventDraft(SupervisorEventType.CANCEL_ANSWERED,
                                         f"{attempt_id}:cancel-answered", {
                "attempt_id": attempt_id, "participant_id": participant,
                "accepted": accepted, "detail": detail,
                "owner_actor_id": command.actor_id,
            }, ticket_id),))

        result = self.store.transact(tenant_id, run_id, answer_phase)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def reassign(self, tenant_id: str, run_id: str, ticket_id: str,
                 to_participant: str, command: OwnerCommand) -> SupervisorEvent:
        """Owner reassignment, strictly through the ticket's pinned recovery
        policy and the authorization's eligible set; no-self-review preserved;
        the transfer is recorded (C-F3a)."""
        _require_owner(command)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key,
                              SupervisorEventType.AUTHORSHIP_TRANSFERRED, ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            ticket_state = state.tickets.get(ticket_id)
            if ticket_state is None:
                raise KeyError(ticket_id)
            ticket = ticket_state.ticket
            auth = state.authorization
            if auth is None:
                raise AuthorityRefused("reassignment requires an active authorization")
            if ticket_state.status != "stranded":
                raise AuthorityRefused("reassignment requires a stranded ticket")
            if ticket.lease.reassignment == "halt":
                raise AuthorityRefused("ticket recovery policy is halt; owner may re-queue instead")
            last = ticket_state.attempts[-1] if ticket_state.attempts else None
            if last is not None and last.role is ParticipantRole.REVIEWER:
                raise AuthorityRefused(
                    "the reviewer seat is pinned by the ticket; a stranded review retries "
                    "the same reviewer")
            reviewer = ticket.participant_for(ParticipantRole.REVIEWER)
            eligible = (set(auth.takeover_participants)
                        if ticket.lease.reassignment == "takeover"
                        else {worker.participant_id for worker in auth.workers})
            eligible -= {reviewer, ticket_state.current_author}
            if to_participant not in eligible:
                raise AuthorityRefused("participant is not eligible under the pinned recovery policy")
            return StorePlan((EventDraft(SupervisorEventType.AUTHORSHIP_TRANSFERRED,
                                         command.idempotency_key, {
                "from_participant_id": ticket_state.current_author,
                "to_participant_id": to_participant,
                "owner_actor_id": command.actor_id,
            }, ticket_id),))

        result = self.store.transact(tenant_id, run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def grant_attempt(self, tenant_id: str, run_id: str, ticket_id: str, participant_id: str,
                      command: OwnerCommand | WorkspaceRunCommand, *,
                      acknowledge_possible_charge: bool) -> SupervisorEvent:
        """Grant exactly ONE explicit re-attempt of a stranded ticket to a named authorized worker.

        This is the only way past the automatic retry allowance, so it is an explicit act of the run's
        authority, never a policy: one grant per stranded attempt (its idempotency key names that attempt),
        consumed by the next dispatch. The author seat may move to another authorized worker (recorded as an
        authorship transfer) or stay with the same author; the reviewer seat is pinned by the ticket and a
        reviewer never becomes the author (no self-review). When the stranded attempt's reservation is still
        held, its call may have been charged and its outcome is unknown: the grant is refused unless that is
        explicitly acknowledged, and the held reservation stays visible either way.
        """
        _require_run_authority(command, tenant_id, run_id)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            state = _project(events)
            ticket_state = state.tickets.get(ticket_id)
            if ticket_state is None:
                raise KeyError(ticket_id)
            last = ticket_state.attempts[-1] if ticket_state.attempts else None
            if last is None or ticket_state.status != "stranded" or not last.stranded:
                raise AuthorityRefused("a re-attempt requires a stranded ticket")
            key = f"{last.attempt_id}:attempt-granted"
            prior = _existing(events, key, SupervisorEventType.ATTEMPT_GRANTED, ticket_id)
            if prior is not None:
                if prior.payload.get("participant_id") != participant_id:
                    raise StoreConflict("this stranded attempt already has a re-attempt for another worker")
                return StorePlan((), prior)
            auth = state.authorization
            if auth is None or state.status not in {RunStatus.ACTIVE, RunStatus.PAUSED}:
                raise AuthorityRefused("a re-attempt requires a run with an authorization in force")
            if isinstance(command, WorkspaceRunCommand):
                _require_workspace_bounds(auth)
            if auth.worker(participant_id) is None:
                raise AuthorityRefused("the named worker is not authorized for this run")
            ticket = ticket_state.ticket
            reviewer = ticket.participant_for(ParticipantRole.REVIEWER)
            if last.role is ParticipantRole.REVIEWER:
                if participant_id != reviewer:
                    raise AuthorityRefused(
                        "the reviewer seat is pinned by the ticket; re-attempt the same reviewer")
            elif participant_id == reviewer:
                raise AuthorityRefused("the ticket's reviewer can never author it (no self-review)")
            held = not last.settled and not last.released
            if held and not acknowledge_possible_charge:
                raise AuthorityRefused(
                    "the stranded attempt may have been charged and its outcome is unknown; acknowledge that "
                    "before running the work again")
            drafts: list[EventDraft] = []
            if last.role is ParticipantRole.AUTHOR and participant_id != ticket_state.current_author:
                drafts.append(EventDraft(SupervisorEventType.AUTHORSHIP_TRANSFERRED,
                                         f"{last.attempt_id}:granted-transfer", {
                    "from_participant_id": ticket_state.current_author,
                    "to_participant_id": participant_id,
                    "owner_actor_id": command.actor_id,
                }, ticket_id))
            drafts.append(EventDraft(SupervisorEventType.ATTEMPT_GRANTED, key, {
                "participant_id": participant_id, "role": last.role.value,
                "after_attempt_id": last.attempt_id, "possible_charge_acknowledged": held,
                "owner_actor_id": command.actor_id,
            }, ticket_id))
            return StorePlan(tuple(drafts))

        result = self.store.transact(tenant_id, run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[-1])

    def queue_ticket(self, run: RunDefinition, ticket: WorkTicket, command: OwnerCommand | WorkspaceGraphCommand, *,
                     graph_digest: str, branch_approved: bool) -> SupervisorEvent:
        self._require_graph_authority(command, run)
        if ticket.tenant_id != run.tenant_id:
            raise AuthorityRefused("cross-tenant ticket refused")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, SupervisorEventType.TICKET_QUEUED,
                              ticket.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            if state.definition != run or graph_digest != run.graph_digest:
                raise AuthorityRefused("ticket is outside the pinned work graph")
            if ticket.ticket_id in state.tickets:
                raise StoreConflict("ticket id already exists with another idempotency key")
            draft = EventDraft(SupervisorEventType.TICKET_QUEUED, command.idempotency_key, {
                "ticket": _ticket_payload(ticket), "ticket_digest": ticket.ticket_digest,
                "branch_approved": branch_approved, "owner_actor_id": command.actor_id,
            }, ticket.ticket_id)
            return StorePlan((draft,))

        result = self.store.transact(run.tenant_id, run.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    @staticmethod
    def _require_graph_authority(
        command: OwnerCommand | WorkspaceGraphCommand, run: RunDefinition,
    ) -> None:
        if isinstance(command, WorkspaceGraphCommand):
            if command.tenant_id != run.tenant_id or command.graph_digest != run.graph_digest:
                raise AuthorityRefused("workspace authority does not bind this tenant and graph")
            return
        _require_owner(command)

    def _claim(self, tenant_id: str, run_id: str) -> ClaimedAttempt | None:
        return self._claim_confirmed(tenant_id, run_id, "")[0]

    def _claim_confirmed(self, tenant_id: str, run_id: str,
                         confirmation_id: str, guard: ConfirmedWorkGuard | None = None) -> tuple[ClaimedAttempt | None, bool]:
        """Claim the next due attempt; with a confirmation, at most once (``True`` = an earlier claim)."""
        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            state = _project(events)
            if guard is not None:
                if (state.authorization is None
                        or state.authorization.authorization_digest != guard.authorization_digest
                        or lifecycle_sequence(events) != guard.lifecycle_sequence):
                    raise AuthorityRefused("the confirmed work authorization or lifecycle changed")
                if any(t.status in {"stranded", "revision_requested"} for t in state.tickets.values()):
                    raise AuthorityRefused("stopped or revised work needs a new customer decision")
            if confirmation_id:
                # One confirmation claims at most once: decided under the per-run lock, so two concurrent
                # replays of the same confirmation can never both claim.
                used = next((event for event in events
                             if event.event_type is SupervisorEventType.BUDGET_RESERVED
                             and event.payload.get("confirmation_id") == confirmation_id), None)
                if used is not None:
                    return StorePlan((), ("used", used.ticket_id, str(used.payload["attempt_id"])))
            auth = state.authorization
            if state.definition is None or auth is None or state.status is not RunStatus.ACTIVE:
                return StorePlan((), None)
            if now >= state.effective_expires_at:
                stop_key = f"system:authorization-expired:{auth.authorization_digest}"
                prior = _existing(events, stop_key,
                                  SupervisorEventType.HARD_STOPPED)
                if prior is not None:
                    return StorePlan((), None)
                return StorePlan((EventDraft(SupervisorEventType.HARD_STOPPED,
                                              stop_key, {
                    "reason": "authorization_expired",
                    "authorization_digest": auth.authorization_digest,
                }),), None)
            if state.spent_usd + state.reserved_usd >= auth.budget_ceiling_usd:
                stop_key = f"system:budget-exhausted:{auth.authorization_digest}"
                prior = _existing(events, stop_key,
                                  SupervisorEventType.HARD_STOPPED)
                if prior is not None:
                    return StorePlan((), None)
                return StorePlan((EventDraft(SupervisorEventType.HARD_STOPPED,
                                              stop_key, {
                    "reason": "budget_exhausted",
                    "authorization_digest": auth.authorization_digest,
                }),), None)
            for ticket_state in state.tickets.values():
                ticket = ticket_state.ticket
                if ticket_state.status not in {"queued", "stranded", "review_queued", "revision_requested"}:
                    continue
                if auth.mode is AutonomyMode.SUPERVISED and not ticket_state.branch_approved:
                    continue
                if any(state.tickets.get(dep) is None or state.tickets[dep].status != "completed"
                       for dep in ticket.dependencies):
                    continue
                if ticket.effect_class not in auth.allowed_effects:
                    continue
                if ticket.ceiling_usd > auth.per_ticket_ceiling_usd:
                    continue
                attempts = ticket_state.attempts
                granted = ticket_state.pending_grant if ticket_state.status == "stranded" else ""
                # Normal author/reviewer/revision turns are not retries.  Only
                # stranded attempts consume the bounded recovery allowance; an
                # explicit grant is authority, not a retry, and names its worker.
                strandings = sum(attempt.stranded for attempt in attempts) - ticket_state.granted_attempts
                if not granted and strandings > min(auth.max_retries, ticket.lease.max_retries):
                    continue
                if granted and attempts:
                    role = attempts[-1].role
                elif ticket_state.status == "stranded" and attempts:
                    role = attempts[-1].role
                else:
                    role = (ParticipantRole.REVIEWER if ticket_state.status == "review_queued"
                            else ParticipantRole.AUTHOR)
                participant = (ticket.participant_for(ParticipantRole.REVIEWER)
                               if role is ParticipantRole.REVIEWER else ticket_state.current_author)
                transfer: EventDraft | None = None
                last_stranded = attempts[-1].participant_id if attempts else None
                if granted:
                    # The grant already fixed the exact participant (and recorded any transfer).
                    participant = granted
                elif (ticket_state.status == "stranded" and role is ParticipantRole.AUTHOR
                        and last_stranded is not None and participant != last_stranded):
                    # A transfer (owner reassignment or a prior automatic one)
                    # already selected the EXACT next author: dispatch that
                    # participant, and never emit a second transfer (C-F3a-R1).
                    pass
                elif ticket_state.status == "stranded" and role is ParticipantRole.AUTHOR:
                    if ticket.lease.reassignment == "halt":
                        continue
                    if ticket.lease.reassignment == "takeover":
                        reviewer = ticket.participant_for(ParticipantRole.REVIEWER)
                        candidate = next((value for value in auth.takeover_participants
                                          if value not in {participant, reviewer}), None)
                        if candidate is None:
                            continue
                        transfer = EventDraft(
                            SupervisorEventType.AUTHORSHIP_TRANSFERRED,
                            f"{ticket.ticket_id}:transfer:{len(attempts) + 1}",
                            {"from_participant_id": participant,
                             "to_participant_id": candidate}, ticket.ticket_id)
                        participant = candidate
                if participant is None:
                    continue
                worker = auth.worker(participant)
                if worker is None:
                    continue
                if state.spent_usd + state.reserved_usd + ticket.ceiling_usd > auth.budget_ceiling_usd:
                    continue
                attempt_number = len(attempts) + 1
                attempt_id = f"{ticket.ticket_id}:attempt:{attempt_number}"
                reservation_id = f"{attempt_id}:reservation"
                ack_deadline = now + ticket.lease.ack_deadline_s
                lease_expiry = now + ticket.lease.lease_s
                claimed = ClaimedAttempt(
                    tenant_id, run_id, ticket.ticket_id, ticket.ticket_digest,
                    attempt_id, attempt_number, participant, auth.authorization_digest,
                    reservation_id, ticket.ceiling_usd, worker.billing_mode, worker.lane,
                    ack_deadline, lease_expiry,
                    role=role,
                    review_artifact_digest=(ticket_state.queued_artifact_digest
                                            if role is ParticipantRole.REVIEWER else ""),
                    revision_findings_digest=(
                        ticket_state.revision_findings_digest
                        if role is ParticipantRole.AUTHOR else ""),
                )
                common = {
                    "attempt_id": attempt_id, "attempt_number": attempt_number,
                    "participant_id": participant, "role": role.value,
                    "authorization_digest": auth.authorization_digest,
                    "qualification_digest": worker.qualification_digest,
                    "reservation_id": reservation_id, "reservation_usd": ticket.ceiling_usd,
                    "billing_mode": worker.billing_mode, "lane": worker.lane,
                    "ack_deadline_at": ack_deadline, "lease_expires_at": lease_expiry,
                    "ticket_digest": ticket.ticket_digest,
                }
                if confirmation_id:
                    common["confirmation_id"] = confirmation_id
                drafts = (() if transfer is None else (transfer,)) + (
                    EventDraft(SupervisorEventType.BUDGET_RESERVED,
                               f"{attempt_id}:reserved", common, ticket.ticket_id),
                    EventDraft(SupervisorEventType.TICKET_DISPATCHED,
                               f"{attempt_id}:dispatched", common, ticket.ticket_id),
                )
                return StorePlan(drafts, claimed)
            return StorePlan((), None)

        value = self.store.transact(tenant_id, run_id, plan).value
        if isinstance(value, tuple):
            # A replayed confirmation: the durable attempt it claimed, never a new claim.
            return self._claimed(tenant_id, run_id, str(value[1]), str(value[2])), True
        return cast(ClaimedAttempt | None, value), False

    def _claimed(self, tenant_id: str, run_id: str, ticket_id: str, attempt_id: str) -> ClaimedAttempt:
        state = _project(self.store.events(tenant_id, run_id))
        ticket_state = state.tickets[ticket_id]
        attempt = self._matching_attempt(state, ticket_id, attempt_id)
        return ClaimedAttempt(
            tenant_id, run_id, ticket_id, ticket_state.ticket.ticket_digest, attempt.attempt_id,
            attempt.attempt_number, attempt.participant_id, attempt.authorization_digest,
            attempt.reservation_id, attempt.reservation_usd, attempt.billing_mode, attempt.lane,
            attempt.ack_deadline_at, attempt.lease_expires_at, role=attempt.role,
            review_artifact_digest=(ticket_state.queued_artifact_digest
                                    if attempt.role is ParticipantRole.REVIEWER else ""),
            revision_findings_digest=(ticket_state.revision_findings_digest
                                      if attempt.role is ParticipantRole.AUTHOR else ""))

    def cycle(self, tenant_id: str, run_id: str, *, confirmation_id: str = "",
              guard: ConfirmedWorkGuard | None = None) -> CycleResult:
        """Claim once and deliver.  The committed claim always precedes transport.

        ``confirmation_id`` binds the claim to one explicit confirmation (a workspace's "run the next
        step"): a replay of the same confirmation returns the attempt it already claimed with reason
        ``confirmation_already_used`` and never claims or delivers again.
        """
        self.strand_due(tenant_id, run_id)
        claim, reused = self._claim_confirmed(tenant_id, run_id, confirmation_id, guard)
        if claim is None:
            return CycleResult(None, False, "no_due_ticket")
        if reused:
            return CycleResult(claim, False, "confirmation_already_used")
        transport = self.transports.get(claim.participant_id)
        if transport is None:
            self._record_delivery_failure(claim, "worker_unavailable", release_unused=True)
            return CycleResult(claim, False, "worker_unavailable")
        ticket = self.ticket(tenant_id, run_id, claim.ticket_id)
        try:
            receipt = transport.dispatch(ticket)
        except Exception as exc:  # noqa: BLE001 - worker failure becomes durable evidence
            self._record_delivery_failure(claim, f"transport_error:{type(exc).__name__}")
            return CycleResult(claim, True, "transport_error")
        self.record_dispatch_receipt(claim, receipt)
        if not receipt.accepted:
            self._record_delivery_failure(claim, "transport_refused", release_unused=True)
            return CycleResult(claim, True, "transport_refused")
        return CycleResult(claim, True, "dispatched")

    def ticket(self, tenant_id: str, run_id: str, ticket_id: str) -> WorkTicket:
        state = _project(self.store.events(tenant_id, run_id))
        try:
            return state.tickets[ticket_id].ticket
        except KeyError as exc:
            raise KeyError(ticket_id) from exc

    def current_claim(self, tenant_id: str, run_id: str,
                      ticket_id: str) -> ClaimedAttempt:
        """Read the current attempt from durable state for a signal-only worker.

        The transport receives only the immutable ticket. It fetches attempt
        identity here after `ticket_dispatched` has committed, so retry identity
        is never smuggled through an untrusted wake or prompt.
        """
        state = _project(self.store.events(tenant_id, run_id))
        ticket_state = state.tickets.get(ticket_id)
        if ticket_state is None or not ticket_state.attempts:
            raise AuthorityRefused("ticket has no durable dispatched attempt")
        attempt = ticket_state.attempts[-1]
        if attempt.stranded:
            raise AuthorityRefused("latest attempt is already stranded")
        return ClaimedAttempt(
            tenant_id=tenant_id,
            run_id=run_id,
            ticket_id=ticket_id,
            ticket_digest=ticket_state.ticket.ticket_digest,
            attempt_id=attempt.attempt_id,
            attempt_number=attempt.attempt_number,
            participant_id=attempt.participant_id,
            authorization_digest=attempt.authorization_digest,
            reservation_id=attempt.reservation_id,
            reservation_usd=attempt.reservation_usd,
            billing_mode=attempt.billing_mode,
            lane=attempt.lane,
            ack_deadline_at=attempt.ack_deadline_at,
            lease_expires_at=attempt.lease_expires_at,
            role=attempt.role,
            review_artifact_digest=(ticket_state.queued_artifact_digest
                                    if attempt.role is ParticipantRole.REVIEWER else ""),
            revision_findings_digest=(
                ticket_state.revision_findings_digest
                if attempt.role is ParticipantRole.AUTHOR else ""),
        )

    def record_dispatch_receipt(self, claim: ClaimedAttempt, receipt: DispatchReceipt) -> SupervisorEvent:
        if (receipt.ticket_id != claim.ticket_id or receipt.ticket_digest != claim.ticket_digest
                or receipt.participant_id != claim.participant_id):
            raise AuthorityRefused("dispatch receipt identity does not match claimed attempt")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            key = f"{claim.attempt_id}:receipt"
            prior = _existing(events, key, SupervisorEventType.DISPATCH_RECORDED, claim.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            attempt = self._matching_attempt(_project(events), claim.ticket_id, claim.attempt_id)
            if attempt.participant_id != claim.participant_id:
                raise AuthorityRefused("claimed participant changed")
            return StorePlan((EventDraft(SupervisorEventType.DISPATCH_RECORDED, key, {
                "attempt_id": claim.attempt_id, "accepted": receipt.accepted,
                "correlation": receipt.correlation or "",
                "transport_idempotency_key": receipt.idempotency_key,
            }, claim.ticket_id),))

        result = self.store.transact(claim.tenant_id, claim.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def _record_delivery_failure(self, claim: ClaimedAttempt, reason: str, *,
                                 release_unused: bool = False) -> None:
        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            state = _project(events)
            attempt = self._matching_attempt(state, claim.ticket_id, claim.attempt_id)
            if attempt.stranded:
                return StorePlan(())
            drafts = [EventDraft(SupervisorEventType.TICKET_STRANDED,
                                 f"{claim.attempt_id}:delivery-stranded", {
                "attempt_id": claim.attempt_id, "reason": reason,
            }, claim.ticket_id)]
            if release_unused and not attempt.settled and not attempt.released:
                drafts.append(EventDraft(SupervisorEventType.RESERVATION_RELEASED,
                                         f"{claim.attempt_id}:unused-released", {
                    "attempt_id": claim.attempt_id,
                    "reservation_id": attempt.reservation_id,
                    "reason": reason,
                }, claim.ticket_id))
            return StorePlan(tuple(drafts))
        self.store.transact(claim.tenant_id, claim.run_id, plan)

    @staticmethod
    def _matching_attempt(state: _RunState, ticket_id: str, attempt_id: str) -> _AttemptState:
        ticket = state.tickets.get(ticket_id)
        if ticket is None:
            raise AuthorityRefused("signal names an unknown ticket")
        attempt = next((value for value in ticket.attempts if value.attempt_id == attempt_id), None)
        if attempt is None:
            raise AuthorityRefused("signal names an unknown attempt")
        return attempt

    def acknowledge(self, signal: AttemptSignal) -> SupervisorEvent:
        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.TICKET_ACKNOWLEDGED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            if attempt.stranded or now >= attempt.ack_deadline_at:
                raise AuthorityRefused("late ACK refused")
            lease_expiry = now + state.tickets[signal.ticket_id].ticket.lease.lease_s
            return StorePlan((EventDraft(SupervisorEventType.TICKET_ACKNOWLEDGED,
                                         signal.idempotency_key, {
                "attempt_id": signal.attempt_id, "participant_id": signal.participant_id,
                "lease_expires_at": lease_expiry,
            }, signal.ticket_id),))
        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def heartbeat(self, signal: AttemptSignal) -> SupervisorEvent:
        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.HEARTBEAT_RECORDED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            if not attempt.acknowledged or attempt.stranded or now >= attempt.lease_expires_at:
                raise AuthorityRefused("heartbeat does not match a live acknowledged attempt")
            lease_expiry = now + state.tickets[signal.ticket_id].ticket.lease.lease_s
            return StorePlan((EventDraft(SupervisorEventType.HEARTBEAT_RECORDED,
                                         signal.idempotency_key, {
                "attempt_id": signal.attempt_id, "participant_id": signal.participant_id,
                "lease_expires_at": lease_expiry,
            }, signal.ticket_id),))
        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    @staticmethod
    def _validate_signal(state: _RunState, signal: AttemptSignal, attempt: _AttemptState) -> None:
        if attempt.participant_id != signal.participant_id:
            raise AuthorityRefused("forged participant signal refused")
        if attempt.qualification_digest != signal.authentication_digest:
            raise AuthorityRefused("worker authentication receipt mismatch")
        if state.authorization is None or attempt.authorization_digest != state.authorization.authorization_digest:
            raise AuthorityRefused("signal is bound to stale authorization")

    def strand_due(self, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]:
        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            state = _project(events)
            drafts: list[EventDraft] = []
            for ticket in state.tickets.values():
                for attempt in ticket.attempts:
                    if attempt.stranded or attempt.settled or attempt.released:
                        continue
                    # OFF does not pretend an external worker was killed. It
                    # stays stopping until the existing lease expires. A new
                    # authorization does invalidate the old digest at once.
                    stale_auth = (state.authorization is not None and
                                  attempt.authorization_digest != state.authorization.authorization_digest)
                    deadline = attempt.lease_expires_at if attempt.acknowledged else attempt.ack_deadline_at
                    if stale_auth or now >= deadline:
                        reason = "authorization_changed" if stale_auth else (
                            "lease_expired" if attempt.acknowledged else "ack_deadline_expired")
                        drafts.append(EventDraft(
                            SupervisorEventType.TICKET_STRANDED,
                            f"{attempt.attempt_id}:stranded", {
                                "attempt_id": attempt.attempt_id, "reason": reason,
                            }, ticket.ticket.ticket_id))
            if state.status is RunStatus.STOPPING:
                active = [
                    attempt for ticket in state.tickets.values() for attempt in ticket.attempts
                    if not attempt.stranded
                ]
                stranding_ids = {
                    str(draft.payload["attempt_id"]) for draft in drafts
                    if draft.event_type is SupervisorEventType.TICKET_STRANDED
                }
                if all(attempt.attempt_id in stranding_ids for attempt in active):
                    drafts.append(EventDraft(SupervisorEventType.STOPPED,
                                             "system:owner-stop-complete", {
                        "reason": "all_active_leases_terminal",
                    }))
            return StorePlan(tuple(drafts))
        return self.store.transact(tenant_id, run_id, plan).appended

    def settle_attempt(self, signal: AttemptSignal, actual_usd: float,
                       billing_mode: str) -> SupervisorEvent:
        if (isinstance(actual_usd, bool) or not isinstance(actual_usd, (int, float))
                or not math.isfinite(actual_usd) or actual_usd < 0):
            raise ValueError("actual cost must be finite and non-negative")
        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.BUDGET_SETTLED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            if (attempt.participant_id != signal.participant_id
                    or attempt.qualification_digest != signal.authentication_digest):
                raise AuthorityRefused("cost signal identity mismatch")
            if attempt.settled or attempt.released:
                raise StoreConflict("attempt reservation is already terminal")
            if billing_mode != attempt.billing_mode:
                raise AuthorityRefused("billing mode differs from reserved attempt")
            if actual_usd > attempt.reservation_usd:
                raise AuthorityRefused("actual cost exceeds reserved attempt ceiling")
            return StorePlan((EventDraft(SupervisorEventType.BUDGET_SETTLED,
                                         signal.idempotency_key, {
                "attempt_id": signal.attempt_id, "reservation_id": attempt.reservation_id,
                "actual_usd": float(actual_usd), "billing_mode": billing_mode,
            }, signal.ticket_id),))
        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def resolve_stranded_reservation(
            self, tenant_id: str, run_id: str, ticket_id: str, attempt_id: str,
            command: OwnerCommand, *, actual_usd: float | None, billing_mode: str,
            cost_evidence_digest: str) -> SupervisorEvent:
        """Owner resolution for cost that a dead worker can no longer report.

        A stranded reservation deliberately remains held because the kernel
        cannot infer whether the external invocation incurred cost.  The owner
        may later settle a verified actual amount, or release it as no-cost,
        but only with a content-addressed evidence receipt.  This command is
        the Half-C API/UI seam; models and workers cannot call it with their
        own authority.
        """
        _require_owner(command)
        if (len(cost_evidence_digest) != 64
                or any(char not in "0123456789abcdef" for char in cost_evidence_digest)):
            raise ValueError("cost evidence digest must be sha256")
        if (actual_usd is not None
                and (isinstance(actual_usd, bool) or not isinstance(actual_usd, (int, float))
                     or not math.isfinite(actual_usd) or actual_usd < 0)):
            raise ValueError("actual cost must be finite and non-negative")

        event_type = (SupervisorEventType.RESERVATION_RELEASED if actual_usd is None
                      else SupervisorEventType.BUDGET_SETTLED)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, command.idempotency_key, event_type, ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, ticket_id, attempt_id)
            if not attempt.stranded:
                raise AuthorityRefused("owner cost resolution requires a stranded attempt")
            if attempt.settled or attempt.released:
                raise StoreConflict("attempt reservation is already terminal")
            if billing_mode != attempt.billing_mode:
                raise AuthorityRefused("billing mode differs from reserved attempt")
            if actual_usd is not None and actual_usd > attempt.reservation_usd:
                raise AuthorityRefused("actual cost exceeds reserved attempt ceiling")
            payload: dict[str, object] = {
                "attempt_id": attempt_id,
                "reservation_id": attempt.reservation_id,
                "billing_mode": billing_mode,
                "owner_actor_id": command.actor_id,
                "cost_evidence_digest": cost_evidence_digest,
                "reason": "owner_verified_stranded_cost",
            }
            if actual_usd is not None:
                payload["actual_usd"] = float(actual_usd)
            return StorePlan((EventDraft(event_type, command.idempotency_key,
                                         payload, ticket_id),))

        result = self.store.transact(tenant_id, run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def submit_artifact(self, signal: ArtifactSignal) -> tuple[SupervisorEvent, SupervisorEvent]:
        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.ARTIFACT_SUBMITTED, signal.ticket_id)
            if prior is not None:
                review = next(event for event in events
                              if event.idempotency_key == f"{signal.idempotency_key}:review")
                return StorePlan((), (prior, review))
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            ticket = state.tickets[signal.ticket_id]
            if attempt.role is not ParticipantRole.AUTHOR or not attempt.acknowledged or attempt.stranded:
                raise AuthorityRefused("only the live acknowledged author may submit an artifact")
            reviewer = ticket.ticket.participant_for(ParticipantRole.REVIEWER)
            if reviewer is None or reviewer == ticket.current_author:
                raise AuthorityRefused("crossed reviewer unavailable")
            drafts = (
                EventDraft(SupervisorEventType.ARTIFACT_SUBMITTED, signal.idempotency_key, {
                    "attempt_id": signal.attempt_id, "artifact_digest": signal.artifact_digest,
                    "visibility": ticket.ticket.visibility.value,
                }, signal.ticket_id),
                EventDraft(SupervisorEventType.REVIEW_QUEUED,
                           f"{signal.idempotency_key}:review", {
                    "artifact_digest": signal.artifact_digest, "reviewer_id": reviewer,
                    "peer_reasoning_released": False,
                }, signal.ticket_id),
            )
            return StorePlan(drafts)
        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        if result.appended:
            return cast(tuple[SupervisorEvent, SupervisorEvent], result.appended)
        return cast(tuple[SupervisorEvent, SupervisorEvent], result.value)

    def request_revision(self, signal: AttemptSignal, findings_digest: str) -> SupervisorEvent:
        if len(findings_digest) != 64:
            raise ValueError("findings digest must be sha256")
        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.REVISION_REQUESTED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            if attempt.role is not ParticipantRole.REVIEWER or not attempt.acknowledged:
                raise AuthorityRefused("only the acknowledged crossed reviewer may request revision")
            return StorePlan((EventDraft(SupervisorEventType.REVISION_REQUESTED,
                                         signal.idempotency_key, {
                "attempt_id": signal.attempt_id, "reviewer_id": signal.participant_id,
                "findings_digest": findings_digest,
            }, signal.ticket_id),))
        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def complete_ticket(self, signal: AttemptSignal, artifact_digest: str) -> SupervisorEvent:
        """Record crossed-review completion.  Completion is not approval or release."""
        if len(artifact_digest) != 64:
            raise ValueError("artifact digest must be sha256")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, signal.idempotency_key,
                              SupervisorEventType.TICKET_COMPLETED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            if (attempt.role is not ParticipantRole.REVIEWER or not attempt.acknowledged
                    or attempt.stranded):
                raise AuthorityRefused("only the live crossed reviewer may complete a ticket")
            return StorePlan((EventDraft(SupervisorEventType.TICKET_COMPLETED,
                                         signal.idempotency_key, {
                "attempt_id": signal.attempt_id,
                "reviewer_id": signal.participant_id,
                "artifact_digest": artifact_digest,
                "consequential_effect_authorized": False,
            }, signal.ticket_id),))

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def fail_attempt(self, signal: AttemptSignal, actual_usd: float,
                     billing_mode: str, reason: str) -> tuple[SupervisorEvent, ...]:
        """ATOMIC worker failure (section 46.1): settlement of the actual cost
        and the typed stranding land in ONE transaction, so the pinned
        retry/reassign law becomes eligible immediately - never a settled
        orphan stuck outside the claim loop."""
        if (isinstance(actual_usd, bool) or not isinstance(actual_usd, (int, float))
                or not math.isfinite(actual_usd) or actual_usd < 0):
            raise ValueError("actual cost must be finite and non-negative")
        if not reason.strip():
            raise ValueError("a worker failure requires a named reason")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, f"{signal.idempotency_key}:stranded",
                              SupervisorEventType.TICKET_STRANDED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), tuple(
                    event for event in events
                    if event.idempotency_key in {
                        f"{signal.idempotency_key}:settle",
                        f"{signal.idempotency_key}:stranded"}))
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            if (attempt.participant_id != signal.participant_id
                    or attempt.qualification_digest != signal.authentication_digest):
                raise AuthorityRefused("failure signal identity mismatch")
            if attempt.settled or attempt.released:
                raise StoreConflict("attempt reservation is already terminal")
            if billing_mode != attempt.billing_mode:
                raise AuthorityRefused("billing mode differs from reserved attempt")
            if actual_usd > attempt.reservation_usd:
                raise AuthorityRefused("actual cost exceeds reserved attempt ceiling")
            drafts: list[EventDraft] = []
            drafts.append(EventDraft(SupervisorEventType.BUDGET_SETTLED,
                                     f"{signal.idempotency_key}:settle", {
                "attempt_id": signal.attempt_id, "reservation_id": attempt.reservation_id,
                "actual_usd": float(actual_usd), "billing_mode": billing_mode,
            }, signal.ticket_id))
            if not attempt.stranded:
                drafts.append(EventDraft(SupervisorEventType.TICKET_STRANDED,
                                         f"{signal.idempotency_key}:stranded", {
                    "attempt_id": signal.attempt_id, "reason": reason,
                }, signal.ticket_id))
            return StorePlan(tuple(drafts))

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return result.appended if result.appended else cast(
            "tuple[SupervisorEvent, ...]", result.value)

    def submit_authored(self, signal: ArtifactSignal, actual_usd: float,
                        billing_mode: str) -> tuple[SupervisorEvent, ...]:
        """ATOMIC author completion (section 44.3): settlement, the artifact,
        and the review queue land in ONE transaction - a refusal appends
        nothing, so the attempt stays live, visible, and recoverable."""
        if (isinstance(actual_usd, bool) or not isinstance(actual_usd, (int, float))
                or not math.isfinite(actual_usd) or actual_usd < 0):
            raise ValueError("actual cost must be finite and non-negative")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, f"{signal.idempotency_key}:artifact",
                              SupervisorEventType.ARTIFACT_SUBMITTED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), tuple(
                    event for event in events
                    if event.idempotency_key in {
                        f"{signal.idempotency_key}:settle",
                        f"{signal.idempotency_key}:artifact",
                        f"{signal.idempotency_key}:review"}))
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            ticket = state.tickets[signal.ticket_id]
            if attempt.role is not ParticipantRole.AUTHOR or not attempt.acknowledged or attempt.stranded:
                raise AuthorityRefused("only the live acknowledged author may submit an artifact")
            if attempt.settled or attempt.released:
                raise StoreConflict("attempt reservation is already terminal")
            if billing_mode != attempt.billing_mode:
                raise AuthorityRefused("billing mode differs from reserved attempt")
            if actual_usd > attempt.reservation_usd:
                raise AuthorityRefused("actual cost exceeds reserved attempt ceiling")
            reviewer = ticket.ticket.participant_for(ParticipantRole.REVIEWER)
            if reviewer is None or reviewer == ticket.current_author:
                raise AuthorityRefused("crossed reviewer unavailable")
            drafts = (
                EventDraft(SupervisorEventType.BUDGET_SETTLED,
                           f"{signal.idempotency_key}:settle", {
                    "attempt_id": signal.attempt_id, "reservation_id": attempt.reservation_id,
                    "actual_usd": float(actual_usd), "billing_mode": billing_mode,
                }, signal.ticket_id),
                EventDraft(SupervisorEventType.ARTIFACT_SUBMITTED,
                           f"{signal.idempotency_key}:artifact", {
                    "attempt_id": signal.attempt_id, "artifact_digest": signal.artifact_digest,
                    "visibility": ticket.ticket.visibility.value,
                }, signal.ticket_id),
                EventDraft(SupervisorEventType.REVIEW_QUEUED,
                           f"{signal.idempotency_key}:review", {
                    "artifact_digest": signal.artifact_digest, "reviewer_id": reviewer,
                    "peer_reasoning_released": False,
                }, signal.ticket_id),
            )
            return StorePlan(drafts)

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return result.appended if result.appended else cast(
            "tuple[SupervisorEvent, ...]", result.value)

    def submit_review(self, signal: AttemptSignal, verdict: str, artifact_digest: str,
                      findings_digest: str, actual_usd: float,
                      billing_mode: str) -> tuple[SupervisorEvent, ...]:
        """ATOMIC review completion (section 44.3): settlement plus the
        role-valid transition (accept -> completed for THIS exact artifact;
        revise -> revision with the findings) in ONE transaction. A refusal
        appends nothing - never a settled orphan, never a swallowed verdict."""
        if verdict not in {"accept", "revise"}:
            raise ValueError("review verdict must be accept or revise")
        for name, value in (("artifact", artifact_digest), ("findings", findings_digest)):
            if len(value) != 64:
                raise ValueError(f"review {name} digest must be sha256")
        if (isinstance(actual_usd, bool) or not isinstance(actual_usd, (int, float))
                or not math.isfinite(actual_usd) or actual_usd < 0):
            raise ValueError("actual cost must be finite and non-negative")
        outcome_type = (SupervisorEventType.TICKET_COMPLETED if verdict == "accept"
                        else SupervisorEventType.REVISION_REQUESTED)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, f"{signal.idempotency_key}:outcome",
                              outcome_type, signal.ticket_id)
            if prior is not None:
                return StorePlan((), tuple(
                    event for event in events
                    if event.idempotency_key in {
                        f"{signal.idempotency_key}:settle",
                        f"{signal.idempotency_key}:outcome"}))
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            ticket = state.tickets[signal.ticket_id]
            if (attempt.role is not ParticipantRole.REVIEWER or not attempt.acknowledged
                    or attempt.stranded):
                raise AuthorityRefused("only the live crossed reviewer may conclude a review")
            if attempt.settled or attempt.released:
                raise StoreConflict("attempt reservation is already terminal")
            if billing_mode != attempt.billing_mode:
                raise AuthorityRefused("billing mode differs from reserved attempt")
            if actual_usd > attempt.reservation_usd:
                raise AuthorityRefused("actual cost exceeds reserved attempt ceiling")
            if ticket.queued_artifact_digest != artifact_digest:
                raise AuthorityRefused("review concludes a different artifact than queued")
            if verdict == "accept":
                outcome_payload: dict[str, object] = {
                    "attempt_id": signal.attempt_id,
                    "reviewer_id": signal.participant_id,
                    "artifact_digest": artifact_digest,
                    "consequential_effect_authorized": False,
                }
            else:
                outcome_payload = {
                    "attempt_id": signal.attempt_id,
                    "reviewer_id": signal.participant_id,
                    "findings_digest": findings_digest,
                }
            drafts = (
                EventDraft(SupervisorEventType.BUDGET_SETTLED,
                           f"{signal.idempotency_key}:settle", {
                    "attempt_id": signal.attempt_id, "reservation_id": attempt.reservation_id,
                    "actual_usd": float(actual_usd), "billing_mode": billing_mode,
                }, signal.ticket_id),
                EventDraft(outcome_type, f"{signal.idempotency_key}:outcome",
                           outcome_payload, signal.ticket_id),
            )
            return StorePlan(drafts)

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return result.appended if result.appended else cast(
            "tuple[SupervisorEvent, ...]", result.value)

    # -- in-process worker records (zero spend: the caller makes the call, the kernel records it) ------------

    def release_uncalled_reservations(self, tenant_id: str, run_id: str,
                                      command: WorkspaceRunCommand) -> tuple[SupervisorEvent, ...]:
        """Release the held reservation of every stranded attempt that provably never made its call.

        Only for a workspace run: its workers are in-process and durably record ``worker_call_started``
        BEFORE any provider call, so a stranded attempt without that marker (a request that died between
        the claim and the call) spent nothing, and zero is the truth. An external worker gives no such
        guarantee, which is why owner-plane stranded reservations stay held for evidence-backed resolution
        and this method refuses owner authority. An attempt WITH the marker is never touched here.
        """
        if not isinstance(command, WorkspaceRunCommand):
            raise AuthorityRefused("only a workspace run's in-process workers prove an attempt never called")
        _require_run_authority(command, tenant_id, run_id)

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            called = {str(event.payload.get("attempt_id", "")) for event in events
                      if event.event_type is SupervisorEventType.WORKER_CALL_STARTED}
            state = _project(events)
            if state.authorization is not None:
                _require_workspace_bounds(state.authorization)
            drafts = tuple(
                EventDraft(SupervisorEventType.RESERVATION_RELEASED, f"{attempt.attempt_id}:uncalled-released", {
                    "attempt_id": attempt.attempt_id, "reservation_id": attempt.reservation_id,
                    "reason": "no_call_started", "owner_actor_id": command.actor_id,
                }, ticket.ticket.ticket_id)
                for ticket in state.tickets.values() for attempt in ticket.attempts
                if attempt.stranded and not attempt.settled and not attempt.released
                and attempt.attempt_id not in called)
            return StorePlan(drafts)

        return self.store.transact(tenant_id, run_id, plan).appended

    def begin_worker_call(self, signal: AttemptSignal, *, guard: ConfirmedWorkGuard | None = None) -> bool:
        """Record, exclusively, that this attempt's one provider call begins now.

        ``True`` only for the caller whose marker was appended; every other caller (a replay, a concurrent
        request) gets ``False`` and must not call. The attempt must be the live acknowledged one.
        """
        key = f"{signal.attempt_id}:call-started"

        def plan(events: tuple[SupervisorEvent, ...], now: float) -> StorePlan:
            if _existing(events, key, SupervisorEventType.WORKER_CALL_STARTED, signal.ticket_id) is not None:
                return StorePlan((), False)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            self._validate_signal(state, signal, attempt)
            # A claim/ack is not permission to enter the provider after a later pause or expiry.
            # Decide under the same run lock that commits the exclusive call-start marker.
            if state.status is not RunStatus.ACTIVE or now >= state.effective_expires_at:
                raise AuthorityRefused("a worker call requires an active, unexpired authorization")
            if guard is not None and (attempt.authorization_digest != guard.authorization_digest
                                      or lifecycle_sequence(events) != guard.lifecycle_sequence):
                raise AuthorityRefused("the confirmed work lifecycle changed before provider entry")
            if (not attempt.acknowledged or attempt.stranded or attempt.settled or attempt.released
                    or now >= attempt.lease_expires_at):
                raise AuthorityRefused("a worker call requires the live acknowledged attempt")
            return StorePlan((EventDraft(SupervisorEventType.WORKER_CALL_STARTED, key, {
                "attempt_id": signal.attempt_id, "participant_id": signal.participant_id,
                "lane": attempt.lane,
            }, signal.ticket_id),), True)

        return bool(self.store.transact(signal.tenant_id, signal.run_id, plan).value)

    def retain_worker_output(self, signal: AttemptSignal, *, output: str, output_digest: str, run_id: str,
                             cost_usd: float | None, succeeded: bool, model: str,
                             usage: dict[str, object] | None = None) -> SupervisorEvent:
        """Retain the verbatim worker output before any transition consumes it; idempotent per attempt."""
        if len(output_digest) != 64:
            raise ValueError("output digest must be sha256")
        if cost_usd is not None and (isinstance(cost_usd, bool) or not math.isfinite(cost_usd) or cost_usd < 0):
            raise ValueError("a reported cost must be finite and non-negative")
        key = f"{signal.attempt_id}:output"

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            prior = _existing(events, key, SupervisorEventType.WORKER_OUTPUT_RETAINED, signal.ticket_id)
            if prior is not None:
                return StorePlan((), prior)
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            if (attempt.participant_id != signal.participant_id
                    or attempt.qualification_digest != signal.authentication_digest):
                raise AuthorityRefused("output signal identity mismatch")
            return StorePlan((EventDraft(SupervisorEventType.WORKER_OUTPUT_RETAINED, key, {
                "attempt_id": signal.attempt_id, "participant_id": signal.participant_id,
                "role": attempt.role.value, "lane": attempt.lane, "model": model,
                "output": output, "output_digest": output_digest, "run_id": run_id,
                "cost_usd": None if cost_usd is None else float(cost_usd), "succeeded": bool(succeeded),
                "usage": dict(usage or {}),
            }, signal.ticket_id),))

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return cast(SupervisorEvent, result.value or result.appended[0])

    def strand_attempt(self, signal: AttemptSignal, reason: str) -> SupervisorEvent | None:
        """Strand the attempt NOW, holding its reservation: its cost is unknown or not attestable here.

        Used when a call's outcome is unknown (a crash or an error after the call began) or a reported cost
        cannot settle inside the reservation. Nothing is settled or released, so the possible charge stays
        visible as an unresolved stranded reservation. ``None`` when the attempt is already stranded.
        """
        if not reason.strip():
            raise ValueError("a stranding requires a named reason")

        def plan(events: tuple[SupervisorEvent, ...], _now: float) -> StorePlan:
            state = _project(events)
            attempt = self._matching_attempt(state, signal.ticket_id, signal.attempt_id)
            if (attempt.participant_id != signal.participant_id
                    or attempt.qualification_digest != signal.authentication_digest):
                raise AuthorityRefused("stranding signal identity mismatch")
            if attempt.stranded:
                return StorePlan((), None)
            return StorePlan((EventDraft(SupervisorEventType.TICKET_STRANDED,
                                         f"{signal.attempt_id}:worker-stranded", {
                "attempt_id": signal.attempt_id, "reason": reason,
            }, signal.ticket_id),))

        result = self.store.transact(signal.tenant_id, signal.run_id, plan)
        return result.appended[0] if result.appended else None

    def events(self, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]:
        return self.store.events(tenant_id, run_id)
