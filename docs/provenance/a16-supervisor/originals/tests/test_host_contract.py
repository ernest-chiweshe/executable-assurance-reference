"""Offline startup refusal contracts; no invalid host reaches an effect."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.host_runtime import compose_reference_host, compose_reference_stores
from assurance_reference.qualified_engine import QualificationSet, RequiredQualification
from regulated_core.clock_pg import DbClock
from regulated_core.document_gate import VerifierRegistry
from regulated_core.host_runtime import RuntimeAuthorities
from regulated_core.signing import Ed25519Signer, TrustDirectory


class NoIOPool:
    def __init__(self, role):
        self.role = role

    def connection(self):
        raise AssertionError("startup must not access a database")


class ConstructionSigner(Ed25519Signer):
    def sign(self, payload):
        raise AssertionError("startup must not sign")


class NoIORetention:
    def anchor(self, *args, **kwargs):
        raise AssertionError("startup must not anchor")

    def fetch(self, *args, **kwargs):
        raise AssertionError("startup must not fetch")

    def verify(self, *args, **kwargs):
        raise AssertionError("startup must not inspect retention")


class UnusedSessionPort:
    def admit_release(self, **request):
        raise AssertionError("startup must not admit an effect")


@pytest.fixture
def contract(request):
    roles = SimpleNamespace(**{name: NoIOPool(name) for name in ("receiver", "allocator", "recorder", "clock", "delegation_issuer", "alerts")})
    clock = DurableClock(DbClock(roles.receiver, "pg:123"), floor_pool=roles.clock)
    trust = TrustDirectory()
    signer_factory = getattr(request, "param", ConstructionSigner)
    keys = {name: signer_factory("fixture:" + name) for name in (
        "evidence", "approval", "emission", "preflight", "identity", "credential", "verifier", "alert", "qualification")}
    for key in keys.values():
        trust.register_signer(key)
    stores = compose_reference_stores(roles, evidence_signer=keys["evidence"], trust=trust, clock=clock)
    authorities = RuntimeAuthorities(trust, keys["approval"], keys["emission"], keys["preflight"],
        keys["identity"].key_id, keys["credential"].key_id, UnusedSessionPort(), VerifierRegistry(),
        {"fixture:check": keys["verifier"]}, NoIORetention(), clock)
    alerts = AlertJournal(roles.alerts, keys["alert"], trust)
    qualifications = QualificationSet(trust=trust, authority=keys["qualification"].key_id,
        clock_domain=clock.domain, required=(RequiredQualification(
            "fixture:check", "1", "a" * 64, "fixture", "en", "synthetic", "1", "1"),), reports=())
    # No reports qualify any request here: this fixture tests construction only.
    return SimpleNamespace(stores=stores, authorities=authorities, alerts=alerts,
                           qualifications=qualifications, keys=keys)


def compose(c, **changes):
    return compose_reference_host(changes.get("stores", c.stores), changes.get("authorities", c.authorities),
        alerts=changes.get("alerts", c.alerts), qualifications=changes.get("qualifications", c.qualifications),
        generation_floor=changes.get("generation_floor"),
        floor_not_used_reason=changes.get("floor_not_used_reason", "Offline host-construction contract fixture"))


def test_host_refuses_omitted_generation_floor_selection(contract):
    with pytest.raises(ValueError, match="generation floor or explicit non-use"):
        compose_reference_host(contract.stores, contract.authorities,
            alerts=contract.alerts, qualifications=contract.qualifications)


def test_host_explicit_non_use_is_logged(contract, caplog):
    compose(contract)
    records = [record for record in caplog.records if getattr(record, "generation_floor_mode", None) == "not_used"]
    assert len(records) == 1
    assert records[0].generation_floor_prefix == "REFERENCE_HOST_GENERATION_FLOOR"


def bound_floor(c, *, domain="pg:123", trust=None):
    from assurance_reference.generation_floor_admission import GenerationFloorAdmission
    from factory.customer.generation_floor_pg import GenerationFloorVerifier
    trust = trust or c.authorities.trust
    trust.register_signer(ConstructionSigner("fixture:generation-floor"))
    return GenerationFloorAdmission(GenerationFloorVerifier(trust=trust,
        issuer_key_id="fixture:generation-floor", installation_id="local-test", schema="floor"),
        NoIOPool("receiver"), domain, "factory_test", "receiver")


def test_host_configured_floor_is_preserved_in_policy_sibling_without_io(contract):
    from regulated_core.preflight import IntendedUseRegistry
    from regulated_core.registry import PolicyRegistry
    floor = bound_floor(contract)
    host = compose(contract, generation_floor=floor, floor_not_used_reason=None)
    engine = host.factory.engine
    sibling = engine.for_policy(registry=PolicyRegistry(), preflight=engine._preflight.for_uses(IntendedUseRegistry()))
    assert engine._generation_floor is sibling._generation_floor is floor


def test_host_refuses_contradictory_floor_selection(contract):
    with pytest.raises(ValueError, match="cannot both"):
        compose(contract, generation_floor=bound_floor(contract))


@pytest.mark.parametrize("mismatch", ["trust", "domain"])
def test_host_refuses_floor_with_different_trust_or_primary(contract, mismatch):
    floor = bound_floor(contract, **({"trust": TrustDirectory()} if mismatch == "trust" else {"domain": "pg:999"}))
    with pytest.raises(ValueError, match="share host trust and primary domain"):
        compose(contract, generation_floor=floor, floor_not_used_reason=None)


def test_complete_configuration_constructs_without_io(contract):
    host = compose(contract)
    assert host.stores is contract.stores
    assert host.factory.engine._alerts is contract.alerts
    assert host.factory.engine._qualifications is contract.qualifications


def test_unselected_monitor_and_production_readiness_are_explicitly_optional(contract):
    host = compose(contract)
    assert host.factory.engine._heartbeat is None
    assert host.factory.production_assurance is None


@pytest.mark.parametrize("keys,installation", [
    (frozenset(), "synthetic-installation"),
    (frozenset({"synthetic:monitor"}), ""),
])
def test_partial_monitor_configuration_refuses_without_io(contract, keys, installation):
    if keys:
        contract.authorities.trust.register_signer(ConstructionSigner("synthetic:monitor"))
    with pytest.raises(ValueError, match="both its monitor keys and the installation"):
        compose(contract, authorities=replace(
            contract.authorities, heartbeat_monitor_key_ids=keys,
            heartbeat_installation=installation,
        ))


def test_configured_monitor_is_preserved_without_io(contract):
    key = ConstructionSigner("synthetic:monitor")
    contract.authorities.trust.register_signer(key)
    host = compose(contract, authorities=replace(
        contract.authorities, heartbeat_monitor_key_ids=frozenset({key.key_id}),
        heartbeat_installation="synthetic-installation",
    ))
    assert host.factory.engine._heartbeat is not None


def test_production_readiness_port_is_preserved_without_invoking_it(contract):
    class UnusedReadinessPort:
        def bind(self, *args, **kwargs):
            raise AssertionError("host construction must not load readiness proofs")

    port = UnusedReadinessPort()
    host = compose(contract, authorities=replace(contract.authorities, production_assurance=port))
    assert host.factory.production_assurance is port


@pytest.mark.parametrize("store", ["pool", "activation", "permits", "reviews", "budget",
                                   "revocation", "grants", "clearances", "governance", "heartbeats"])
def test_missing_store_refuses_at_startup(contract, store):
    with pytest.raises(ValueError, match=f"requires the {store} store"):
        compose(contract, stores=replace(contract.stores, **{store: None}))


@pytest.mark.parametrize("retention", [None, object()])
def test_missing_retention_contract_refuses_at_startup(contract, retention):
    with pytest.raises(ValueError, match="explicit retention"):
        compose(contract, authorities=replace(contract.authorities, worm=retention))


def test_lifecycle_without_governance_contract_refuses_at_startup(contract):
    # Incomplete configuration never becomes a host or invokes a lifecycle write.
    with pytest.raises(ValueError, match="governed pack lifecycle"):
        compose(contract, stores=replace(contract.stores, activation=SimpleNamespace()))


def test_missing_qualification_set_refuses_at_startup(contract):
    with pytest.raises(ValueError, match="qualifications must share"):
        compose(contract, qualifications=None)


def test_reused_authority_key_refuses_at_startup(contract):
    with pytest.raises(ValueError, match="keys must be separated"):
        compose(contract, authorities=replace(contract.authorities, approval_signer=contract.keys["emission"]))


def test_different_key_labels_do_not_hide_reused_public_material(contract):
    c = contract
    c.authorities.trust.register("fixture:alias", c.keys["emission"].public_key_bytes)
    with pytest.raises(ValueError, match="keys must be separated"):
        compose(c, authorities=replace(c.authorities, approval_signer=SimpleNamespace(key_id="fixture:alias")))


def test_repeated_verifier_key_within_one_authority_domain_is_preserved(contract):
    c = contract
    host = compose(c, authorities=replace(c.authorities,
        verifier_signers={"fixture:first": c.keys["verifier"], "fixture:second": c.keys["verifier"]}))
    assert set(host.factory.verifier_signers) == {"fixture:first", "fixture:second"}


def test_unpinned_alert_key_refuses_at_startup(contract):
    c = contract
    alerts = AlertJournal(c.alerts.pool, ConstructionSigner("fixture:unregistered"), c.authorities.trust)
    with pytest.raises(ValueError, match="alerts requires explicit trusted keys"):
        compose(c, alerts=alerts)


def test_different_alert_trust_directory_refuses_at_startup(contract):
    c = contract
    with pytest.raises(ValueError, match="alert journal must share"):
        compose(c, alerts=AlertJournal(c.alerts.pool, c.keys["alert"], TrustDirectory()))


def test_qualification_clock_must_match_host_at_startup(contract):
    c = contract
    q = QualificationSet(trust=c.authorities.trust, authority=c.keys["qualification"].key_id,
        clock_domain="pg:456", required=c.qualifications._required, reports=())
    with pytest.raises(ValueError, match="host clock domain"):
        compose(c, qualifications=q)
