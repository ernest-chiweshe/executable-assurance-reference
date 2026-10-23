"""Governed Collaboration contracts and durable supervisor substrate.

The typed boundary for the collaboration kernel chartered by the owner-approved
hybrid ruling: Agent Factory's governed kernel is the system of record and
authority; the A2A protocol is an external interoperability boundary only.
The CD-0 modules (``contracts``, ``extension``, and ``transport``) remain pure.
CD-1 adds authority records, append-only stores, and the zero-spend supervisor;
there is still no HTTP surface, provider adapter, or SDK object here. Work
orders: ``docs/ec-last-mile/WO-cd-0.md`` and
``WO-cd-1-autonomy-supervisor.md``.

Import law: nothing here may import session internals, provider drivers,
Hub/API, Git/subprocess, the factory core, or the experimental A2A SDK.
"""
from factory.collaboration.contracts import (
    CollaborationEventRecord,
    CollaborationEventType,
    ContractViolation,
    DispatchReceipt,
    EffectClass,
    LeasePolicy,
    NetworkMode,
    ParticipantCapability,
    ParticipantCard,
    ParticipantRole,
    RemoteTaskProjection,
    RemoteTaskState,
    ReviewVerdict,
    RoleBinding,
    TrustClass,
    VisibilityPhase,
    WakeKind,
    WakeSignal,
    WorkTicket,
    canonical_digest,
    parse_wake_signal,
)
from factory.collaboration.extension import (
    A2A_1_0_ROLE_USER,
    GOVERNED_COLLABORATION_EXTENSION_URI,
    GovernedCollaborationExtension,
    classify_inbound_trust,
    extension_from_message,
    extension_payload,
    parse_extension,
    project_remote_task,
    ticket_to_a2a_payload,
)
from factory.collaboration.transport import ParticipantTransport
from factory.collaboration.autonomy import (
    ArtifactSignal,
    AttemptSignal,
    AutonomyAuthorization,
    AutonomyMode,
    ClaimedAttempt,
    OwnerCommand,
    RunDefinition,
    RunStatus,
    TicketStatus,
    WorkerGrant,
)
from factory.collaboration.store import (
    CollaborationStore,
    EventDraft,
    InMemoryCollaborationStore,
    PgCollaborationStore,
    StoreConflict,
    StorePlan,
    StoreResult,
    SupervisorEvent,
    SupervisorEventType,
)
from factory.collaboration.supervisor import (
    AuthorityRefused,
    CollaborationSupervisor,
    CycleResult,
)

__all__ = [
    "A2A_1_0_ROLE_USER",
    "GOVERNED_COLLABORATION_EXTENSION_URI",
    "CollaborationEventRecord",
    "CollaborationEventType",
    "ContractViolation",
    "DispatchReceipt",
    "EffectClass",
    "GovernedCollaborationExtension",
    "LeasePolicy",
    "NetworkMode",
    "ParticipantCapability",
    "ParticipantCard",
    "ParticipantRole",
    "ParticipantTransport",
    "RemoteTaskProjection",
    "RemoteTaskState",
    "ReviewVerdict",
    "RoleBinding",
    "TrustClass",
    "VisibilityPhase",
    "WakeKind",
    "WakeSignal",
    "WorkTicket",
    "ArtifactSignal",
    "AttemptSignal",
    "AutonomyAuthorization",
    "AutonomyMode",
    "AuthorityRefused",
    "ClaimedAttempt",
    "CollaborationStore",
    "CollaborationSupervisor",
    "CycleResult",
    "EventDraft",
    "InMemoryCollaborationStore",
    "OwnerCommand",
    "PgCollaborationStore",
    "RunDefinition",
    "RunStatus",
    "StoreConflict",
    "StorePlan",
    "StoreResult",
    "SupervisorEvent",
    "SupervisorEventType",
    "TicketStatus",
    "WorkerGrant",
    "canonical_digest",
    "classify_inbound_trust",
    "extension_from_message",
    "extension_payload",
    "parse_extension",
    "parse_wake_signal",
    "project_remote_task",
    "ticket_to_a2a_payload",
]
