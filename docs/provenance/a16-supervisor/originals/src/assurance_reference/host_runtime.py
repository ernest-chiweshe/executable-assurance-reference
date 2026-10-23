"""Compose the pinned pack host with the reference's additional authority checks.

The original host validates its complete configuration first. Its configured
services, including delegation, restrictions, tier four and heartbeat controls,
are then passed to the reference engine. No policies, keys or trust anchors are
invented here, and construction performs no migration or cloud operation.
"""

from dataclasses import dataclass, fields, replace

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.floor_bound_engine import FloorBoundReferenceEngine
from assurance_reference.generation_floor import GenerationFloorConfigError, log_floor_non_use
from assurance_reference.generation_floor_admission import GenerationFloorAdmission
from assurance_reference.host_contract import require_reference_host_contract
from assurance_reference.qualified_engine import QualificationSet, QualifiedReferenceEngine
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.retention_contract import require_retention_operations
from factory.pg_session import SessionBoundPool
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.host_runtime import RuntimeAuthorities, compose_regulated_host
from regulated_core.pack_gate import PackGateFactory
from regulated_core.persistence_pg import PostgresGrantStore
from regulated_core.runtime_pg import compose_regulated_stores


@dataclass(frozen=True)
class ReferencePackGateFactory(PackGateFactory):
    """Check the actual per-pack adapters after the original factory resolves them."""

    def __post_init__(self):
        require_retention_operations(self.worm)

    def __call__(self, pack, registry, surface):
        gate = super().__call__(pack, registry, surface)
        if not callable(getattr(gate._credverify, "admit_release", None)):
            raise ValueError("resolved pack credentials require session admission")
        if not isinstance(gate._engine, QualifiedReferenceEngine):
            raise TypeError("pack gate lost the reference qualification engine")
        return gate


def compose_reference_stores(roles, *, evidence_signer, trust, clock: DurableClock,
                             partitioned_lifecycle=False):
    """Use separate recorder/allocation logins and mandatory lifecycle governance.

    Provisioning is a separate explicit operation. This composition cannot
    bootstrap a missing table or fall back to migration credentials.
    """
    if not isinstance(clock, DurableClock):
        raise TypeError("reference stores require the durable authority clock")
    if type(partitioned_lifecycle) is not bool:
        raise TypeError("partitioned_lifecycle must be an explicit boolean")
    delegation_issuer = getattr(roles, "delegation_issuer", None)
    if delegation_issuer is None:
        raise ValueError("reference stores require an explicit delegation_issuer login")
    if len({roles.receiver.role, roles.allocator.role, roles.recorder.role}) != 3:
        raise ValueError("receiver, allocator and recorder logins must be distinct")
    if delegation_issuer.role in {roles.receiver.role, roles.allocator.role, roles.recorder.role}:
        raise ValueError("delegation issuer must be separate from receiver, allocator and recorder")
    stores = compose_regulated_stores(
        roles.receiver, evidence_signer=evidence_signer, trust=trust,
        guard=GovernanceGuard(), budget_allocator_pool=roles.allocator,
        recorder_pool=roles.recorder,
    )
    recorder = ReferenceDecisionRecorder(
        evidence_signer, trust, pool=SessionBoundPool(roles.recorder), clock=clock,
    )
    if partitioned_lifecycle:
        # Explicit staged storage selection, with no migration or legacy fallback.
        from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
        stores = replace(stores, activation=PartitionedActivationLedger(
            "", pool=stores.pool, guard=stores.activation.governance_guard))
    # Signed root/child issuance has its own append-only login; receiver stays read-only.
    grants = PostgresGrantStore(pool=SessionBoundPool(delegation_issuer))
    return replace(stores, recorder=recorder, grants=grants)


def compose_reference_host(stores, authorities: RuntimeAuthorities, *,
                           alerts: AlertJournal, qualifications: QualificationSet,
                           generation_floor: GenerationFloorAdmission | None = None,
                           floor_not_used_reason: str | None = None):
    """Retain every pinned host service and require reference qualification.

    The scope of the qualification set remains explicit host configuration;
    composing it does not establish medical validity or deployed custody.
    """
    if not isinstance(stores.recorder, ReferenceDecisionRecorder):
        raise TypeError("reference host requires the age-bounded reference recorder")
    if not isinstance(authorities.clock, DurableClock):
        raise TypeError("reference host requires the durable authority clock")
    if stores.recorder.clock is not authorities.clock:
        raise ValueError("recorder and host must share the same authority clock")
    if not callable(getattr(authorities.credential_verifier, "admit_release", None)):
        raise ValueError("reference host requires receiving-side session admission")
    require_reference_host_contract(stores, authorities, alerts=alerts, qualifications=qualifications)
    if generation_floor is None:
        if floor_not_used_reason is None:
            raise GenerationFloorConfigError("reference host requires a generation floor or explicit non-use")
        log_floor_non_use(prefix="REFERENCE_HOST_GENERATION_FLOOR", reason=floor_not_used_reason)
    else:
        if floor_not_used_reason is not None:
            raise GenerationFloorConfigError("generation floor and non-use cannot both be selected")
        if not isinstance(generation_floor, GenerationFloorAdmission):
            raise GenerationFloorConfigError("reference host requires a bound generation-floor admission guard")
        if (generation_floor.verifier.trust is not authorities.trust
                or generation_floor.expected_domain != authorities.clock.domain):
            raise GenerationFloorConfigError("generation floor must share host trust and primary domain")
    original = compose_regulated_host(stores, authorities)
    base = original.factory.engine
    engine = FloorBoundReferenceEngine(
        generation_floor=generation_floor,
        retention=authorities.worm,
        default_mission_budget=authorities.default_mission_budget,
        alerts=alerts, qualifications=qualifications,
        registry=base._registry, recorder=base._recorder,
        verification_trust=base._vtrust, approvals=base._approvals,
        emission=base._emission, preflight=base._preflight,
        targets=base.targets, budget=base._budget, revocation=base._revocation,
        delegation=base._delegation, tier4=base._tier4,
        restrictions=base._restrictions, delegation_source_status=base._source_status,
        heartbeat=base._heartbeat, clock=authorities.clock,
    )
    parameters = {field.name: getattr(original.factory, field.name) for field in fields(original.factory)}
    return replace(original, factory=ReferencePackGateFactory(**{**parameters, "engine": engine}))
