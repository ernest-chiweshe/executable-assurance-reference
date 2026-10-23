"""Host-owned regulated composition with injected authorities and one bounded pool.

This module neither invents authority nor claims production assurance. The host
must supply its approved signers, trust anchors, qualified verification functions
and credential source. Construction performs no signing, cloud call or migration.
"""
from __future__ import annotations

from .production_gate import PackReadiness

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from factory.packs.collections import PostgresPackCollectionStore
from factory.packs.registry import InstalledPack, PackRegistry

from .clock import TrustedClock
from .budget import host_budget_terms
from .approval import ApprovalWorkflow
from .document_gate import VerifierRegistry
from .engine import RegulatedEngine
from .heartbeat import DEFAULT_MAX_AGE_US, HeartbeatGate, heartbeat_alarm
from .identity import IdentityVerifier
from .outage import LogOutageAlarm, OutageAlarm
from .pack_gate import PackGateFactory, RulebookGate
from .permit import EmissionAuthority
from .preflight import IntendedUseRegistry, PreflightAuthority
from .projectos_gate import CredentialVerifier, QualificationRegistry
from .registry import PolicyRegistry
from .runtime_pg import RegulatedPostgresStores
from .signing import Signer, TrustDirectory
from .verification import VerificationTrustStore
from .worm import WormStore
from .delegation import DelegationAuthority
from .restrictions import RestrictionRegistry
from .target import DEFAULT_EFFECT_MARGIN_US
from .tier4 import ReportingLineDirectory, Tier4Controls


@dataclass(frozen=True)
class RuntimeAuthorities:
    trust: TrustDirectory
    approval_signer: Signer
    emission_signer: Signer
    preflight_signer: Signer
    identity_authority: str
    credential_authority: str | None
    credential_verifier: CredentialVerifier
    host_verifiers: VerifierRegistry
    verifier_signers: Mapping[str, Signer]
    worm: WormStore
    clock: TrustedClock
    qualifications: QualificationRegistry | None = None
    production_assurance: PackReadiness | None = None
    # Delegated authority (A08): the registered key that signs delegation grants. Absent, the host composes no
    # delegation and any delegated release is refused; present, it must be a trust anchor like every other authority.
    delegation_signer: Signer | None = None
    # Tier 4 (A03): the host's reporting-line directory, the registered monitor keys and the cooling-off period. With
    # no directory, tier-4 controls are not composed and every tier-4 action is refused, never waved through.
    tier4_directory: ReportingLineDirectory | None = None
    tier4_monitor_key_ids: frozenset[str] = frozenset()
    tier4_cooling_off_us: int = 0
    # Signed restriction policies a delegated child may add (A08), registered by the host's composition.
    restrictions: RestrictionRegistry | None = None
    # The host's receiving-side status port for delegated grants (factory DurableProjectReleaseAuthority.assert_current,
    # ledger 3114). A deployment composing delegation must supply it, so the target rechecks the grant's source.
    delegation_source_status: Callable[[str, str], None] | None = None
    required_jurisdiction: str | None = None
    review_extension_factory: Any = None
    # Where authority outages are delivered (A17): leveled, and routed to the organisation's own infrastructure
    # (regulated_core.outage.alarm_from_config). Absent, the structured log channel the metric filter reads.
    outage_alarm: OutageAlarm | None = None
    # The independent monitor's heartbeat (A17): with monitor keys named, new authority at or above tier 3 needs a
    # fresh, verified heartbeat from one of them for this installation, and a silence raises the outage alarm. With
    # none named, no heartbeat gate is composed, and the host says so in its own configuration.
    heartbeat_monitor_key_ids: frozenset[str] = frozenset()
    heartbeat_installation: str = ""
    heartbeat_max_age_us: int = DEFAULT_MAX_AGE_US
    credential_authorities: Mapping[str, str] | None = None
    credential_provider_families: Mapping[str, str] | None = None
    # Trusted installation configuration, used only where the signed policy declares no budget.
    default_mission_budget: Mapping[str, int] | None = None

    def __post_init__(self):
        object.__setattr__(self, "default_mission_budget", host_budget_terms(self.default_mission_budget))


@dataclass(frozen=True)
class RegulatedHostRuntime:
    stores: RegulatedPostgresStores
    collections: PostgresPackCollectionStore
    factory: PackGateFactory

    def __call__(self, pack: InstalledPack, registry: PackRegistry, surface: Any) -> RulebookGate:
        if registry.ledger is not self.stores.activation:
            raise ValueError("regulated host requires its composed bounded activation ledger")
        return self.factory(pack, registry, surface)


def compose_regulated_host(stores: RegulatedPostgresStores, authorities: RuntimeAuthorities) -> RegulatedHostRuntime:
    """Bind host-approved objects; the caller retains ownership of the pool.

    Compose stores first, then construct any DB-backed authority adapters with
    stores.pool. This order avoids a second adapter or late mutation of authority.
    """
    if not isinstance(authorities.clock, TrustedClock):
        raise ValueError("regulated host requires a named trusted clock")
    if stores.recorder._trust is not authorities.trust:
        raise ValueError("regulated recorder and host must share their configured trust directory")
    signers = (stores.recorder._signer, authorities.approval_signer,
               authorities.emission_signer, authorities.preflight_signer,
               *authorities.verifier_signers.values(),
               *((authorities.delegation_signer,) if authorities.delegation_signer is not None else ()))
    mapped_credentials = (authorities.credential_authorities is not None
                          or authorities.credential_provider_families is not None)
    credential_keys = (
        (*((authorities.credential_authorities or {}).values()),
         *((authorities.credential_provider_families or {}).values()))
        if mapped_credentials else (authorities.credential_authority,)
    )
    identities = (authorities.identity_authority, *credential_keys,
                  *(signer.key_id for signer in signers))
    if any(not identity or not authorities.trust.is_known(identity) for identity in identities):
        raise ValueError("every regulated authority requires an explicitly configured trust anchor")
    if mapped_credentials and not authorities.trust.distinct_keys(identities):
        raise ValueError("regulated host authority domains require distinct trusted keys")
    if authorities.delegation_signer is not None and authorities.delegation_source_status is None:
        # A delegated grant is only as current as the project, goal and membership behind it (ledger 3114).
        raise ValueError("a delegating host must compose the delegated source status port")
    if authorities.credential_verifier is None or not authorities.verifier_signers:
        raise ValueError("regulated host requires explicit credential and verification authorities")
    heartbeat = _heartbeat_gate(stores, authorities)
    intended = IntendedUseRegistry()
    engine = RegulatedEngine(
        registry=PolicyRegistry(), recorder=stores.recorder,
        verification_trust=VerificationTrustStore(authorities.trust),
        approvals=ApprovalWorkflow(authorities.trust, authorities.approval_signer,
            IdentityVerifier(authorities.trust, authorities.identity_authority),
            credential_authority=authorities.credential_authority,
            credential_authorities=authorities.credential_authorities,
            credential_provider_families=authorities.credential_provider_families),
        emission=EmissionAuthority(authorities.emission_signer, authorities.trust, stores.permits),
        preflight=PreflightAuthority(authorities.preflight_signer, intended, authorities.trust),
        budget=stores.budget, revocation=stores.revocation,
        default_mission_budget=authorities.default_mission_budget,
        clock=authorities.clock, effect_margin_us=DEFAULT_EFFECT_MARGIN_US,
        delegation_source_status=authorities.delegation_source_status,
        delegation=(DelegationAuthority(authorities.delegation_signer, authorities.trust, stores.grants)
                    if authorities.delegation_signer is not None else None),
        tier4=(Tier4Controls(directory=authorities.tier4_directory, clearances=stores.clearances,
                             trust=authorities.trust, monitor_key_ids=authorities.tier4_monitor_key_ids,
                             cooling_off_us=authorities.tier4_cooling_off_us)
               if authorities.tier4_directory is not None else None),
        restrictions=authorities.restrictions, heartbeat=heartbeat,
    )
    factory = PackGateFactory(
        trust=authorities.trust, engine=engine, host_verifiers=authorities.host_verifiers,
        verifier_signers=dict(authorities.verifier_signers), credential_verifier=authorities.credential_verifier,
        intended_uses=intended, worm=authorities.worm, qualifications=authorities.qualifications,
        production_assurance=authorities.production_assurance,
        required_jurisdiction=authorities.required_jurisdiction, review_store=stores.reviews,
        review_extension_factory=authorities.review_extension_factory, outage_alarm=authorities.outage_alarm,
    )
    return RegulatedHostRuntime(stores, PostgresPackCollectionStore("", pool=stores.pool), factory)


def _heartbeat_gate(stores: RegulatedPostgresStores, authorities: RuntimeAuthorities) -> HeartbeatGate | None:
    """The monitor heartbeat gate the host asked for, over the shared durable store, or None when it named no monitor.

    A monitor key must be a trust anchor, and the installation must be named; half a configuration refuses."""
    keys, installation = authorities.heartbeat_monitor_key_ids, authorities.heartbeat_installation
    if not keys and not installation:
        return None
    if not keys or not installation:
        raise ValueError("a monitor heartbeat needs both its monitor keys and the installation they watch")
    unknown = sorted(k for k in keys if not authorities.trust.is_known(k))
    if unknown:
        raise ValueError("monitor heartbeat keys must be trust anchors of this host: " + ", ".join(unknown))
    if stores.heartbeats is None:
        raise ValueError("a monitor heartbeat needs the shared durable heartbeat store")
    clock = authorities.clock.now_us
    return HeartbeatGate(store=stores.heartbeats, trust=authorities.trust, installation=installation,
                         monitor_key_ids=keys, max_age_us=authorities.heartbeat_max_age_us,
                         on_stale=heartbeat_alarm(authorities.outage_alarm or LogOutageAlarm(),
                                                  installation=installation, clock_us=clock))
