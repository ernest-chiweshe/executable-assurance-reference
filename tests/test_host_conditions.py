"""Guarded offline host-condition contracts using explicitly synthetic proofs.

No provider, database or effect is invoked. Provider markers below are fixture
inputs to the existing interface, never evidence of real custody or identity.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockReading
from regulated_core.heartbeat import (
    HeartbeatGate, HeartbeatIngress, HeartbeatRefused, InMemoryHeartbeatStore,
    STALE, issue_heartbeat,
)
from regulated_core.production_gate import (
    MANDATORY, AssuranceEvidence, ProductionGate, ProductionReadinessError,
)
from regulated_core.qualification import LabeledCase, QualificationDataset, qualify
from regulated_core.resilience import DrillOutcome, DrillReport
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory
from regulated_core.worm import LocalWormStore


class FixtureClock:
    domain = "synthetic:host-conditions"

    def __init__(self, now=100):
        self.now = now
        self.unavailable = False

    def read(self):
        if self.unavailable:
            raise RuntimeError("synthetic clock unavailable")
        return ClockReading(self.domain, self.now)

    def now_us(self):
        return self.read().now_us


def signed(value, signer):
    return replace(value, signature=signer.sign(value.signed_body()))


@pytest.fixture
def monitor():
    key = Ed25519Signer("synthetic:monitor")
    trust = TrustDirectory()
    trust.register_signer(key)
    clock, store, alerts = FixtureClock(), InMemoryHeartbeatStore(), []
    config = dict(store=store, trust=trust, installation="synthetic-installation",
                  monitor_key_ids=frozenset({key.key_id}), max_age_us=20)
    return SimpleNamespace(
        key=key, clock=clock, store=store, alerts=alerts,
        ingress=HeartbeatIngress(**config, clock_us=clock.now_us),
        gate=HeartbeatGate(**config, on_stale=alerts.append),
    )


def test_healthy_monitor_is_admitted_then_silence_refuses(monitor):
    m = monitor
    m.ingress.receive(issue_heartbeat(m.key, installation="synthetic-installation",
                                     sequence=1, beat_at_us=100))
    assert m.gate.problem(3, now_us=120) is None  # documented inclusive age bound
    assert m.gate.problem(3, now_us=121)[0] == STALE
    assert len(m.alerts) == 1


def test_missing_monitor_blocks_configured_tiers_but_grants_nothing(monitor):
    assert monitor.gate.problem(2, now_us=100) is None
    for tier in (3, 4):
        assert monitor.gate.problem(tier, now_us=100)[0] == STALE
    assert len(monitor.alerts) == 2


@pytest.mark.parametrize("installation,at", [
    ("different-installation", 100), ("synthetic-installation", 101),
    ("synthetic-installation", 79),
])
def test_inconsistent_monitor_observation_refused_before_storage(monitor, installation, at):
    m = monitor
    beat = issue_heartbeat(m.key, installation=installation, sequence=1, beat_at_us=at)
    with pytest.raises(HeartbeatRefused):
        m.ingress.receive(beat)
    assert m.store.latest(installation, m.key.key_id) is None
    assert m.gate.problem(3, now_us=100)[0] == STALE


def test_monitor_sequence_never_replaces_newer_observation(monitor):
    m = monitor
    newest = issue_heartbeat(m.key, installation="synthetic-installation",
                             sequence=2, beat_at_us=100)
    m.ingress.receive(newest)
    m.ingress.receive(issue_heartbeat(m.key, installation="synthetic-installation",
                                     sequence=1, beat_at_us=99))
    assert m.store.latest("synthetic-installation", m.key.key_id) == newest


class SyntheticProviderPort:
    """Marker-only fake; no actual approver verification is claimed here."""

    provider_backed = True

    def verify(self, *args, **kwargs):
        raise AssertionError("readiness must not call an identity provider")


@pytest.fixture
def readiness():
    clock, trust = FixtureClock(), TrustDirectory()
    keys = {name: Ed25519Signer("synthetic:" + name)
            for name in ("assurance", "qualification", "drill")}
    for key in keys.values():
        trust.register_signer(key)
    blank = Signature("", "")
    evidence = signed(AssuranceEvidence(
        "synthetic-installation", 90, dict.fromkeys(MANDATORY, True), 1,
        "synthetic-owner", "synthetic-validator", "0.01", blank,
    ), keys["assurance"])
    dataset = QualificationDataset(
        "synthetic-binary", "1", "Two artificial strings; no domain validation.",
        (LabeledCase("yes", True), LabeledCase("no", False)),
    )
    qualification = qualify(
        keys["qualification"], verification_class="synthetic:check", verifier_version="1",
        dataset=dataset, predicate=lambda value: value == "yes", qualified_at_us=90,
        valid_for_us=80, jurisdictions=("synthetic",), languages=("en",),
        document_types=("synthetic",), limitations=("Fixture classification only.",),
    )
    # Signed synthetic observations, not a claim that a real drill ran.
    drill = signed(DrillReport(
        "synthetic-installation", 90, 180,
        (DrillOutcome("synthetic:drill", True, "Synthetic input; no drill executed."),),
        keys["drill"].key_id, blank,
    ), keys["drill"])
    worm = LocalWormStore()
    receipt = worm.anchor(evidence.scope, canonical_bytes(evidence.signed_body()),
                          retain_us=86_400_000_000, now_us=90)
    gate = ProductionGate(
        trust, keys["assurance"].key_id, clock=clock, scope=evidence.scope,
        required_verifiers=("synthetic:check",), required_drills=("synthetic:drill",),
        qualification_authority=keys["qualification"].key_id,
        drill_authority=keys["drill"].key_id, max_attestation_age_us=100, min_worm_days=1,
    )
    inputs = dict(
        evidence_signer=SimpleNamespace(kind="kms-external"),  # synthetic metadata only
        credential_verifier=SyntheticProviderPort(),
        qualifications=SimpleNamespace(current=lambda name, now: qualification),
        drill_report=drill, worm_store=worm, worm_receipt=receipt,
    )
    return SimpleNamespace(clock=clock, keys=keys, evidence=evidence,
                           qualification=qualification, gate=gate, inputs=inputs)


def test_complete_synthetic_readiness_has_earliest_proof_deadline(readiness):
    r = readiness
    window = r.gate.check(r.evidence, **r.inputs)
    assert (window.verified_at_us, window.expires_at_us) == (100, 170)
    r.clock.now = 169
    window.check_current()
    r.clock.now = 170
    with pytest.raises(ProductionReadinessError, match="no longer current"):
        window.check_current()


@pytest.mark.parametrize("control", MANDATORY)
def test_each_unmet_signed_control_refuses_readiness(readiness, control):
    r = readiness
    evidence = signed(replace(r.evidence, controls=r.evidence.controls | {control: False}),
                      r.keys["assurance"])
    with pytest.raises(ProductionReadinessError, match="controls not satisfied"):
        r.gate.check(evidence, **r.inputs)


@pytest.mark.parametrize("missing", [
    "evidence_signer", "credential_verifier", "qualifications", "drill_report",
    "worm_store", "worm_receipt",
])
def test_missing_composed_proof_refuses_readiness(readiness, missing):
    with pytest.raises(ProductionReadinessError):
        readiness.gate.check(readiness.evidence, **(readiness.inputs | {missing: None}))


@pytest.mark.parametrize("change,reason", [
    ({"scope": "elsewhere"}, "scope differs"),
    ({"attested_at_us": 101}, "future"),
    ({"attested_at_us": 0}, "maximum age"),
    ({"worm_retention_days": 0}, "below"),
    ({"model_validator_id": "synthetic-owner"}, "independent"),
    ({"calibration_error": "0.50"}, "calibration"),
])
def test_signed_inconsistent_readiness_input_refuses(readiness, change, reason):
    r = readiness
    evidence = signed(replace(r.evidence, **change), r.keys["assurance"])
    with pytest.raises(ProductionReadinessError, match=reason):
        r.gate.check(evidence, **r.inputs)


@pytest.mark.parametrize("unavailable", [False, True])
def test_retained_readiness_window_refuses_clock_regression_or_outage(readiness, unavailable):
    r = readiness
    window = r.gate.check(r.evidence, **r.inputs)
    r.clock.now, r.clock.unavailable = 99, unavailable
    with pytest.raises(ProductionReadinessError):
        window.check_current()


@pytest.mark.parametrize("change", [
    {"verification_class": "synthetic:other"}, {"qualified_at_us": 101},
    {"expires_at_us": 100},
])
def test_inapplicable_signed_qualification_refuses_readiness(readiness, change):
    r = readiness
    report = signed(replace(r.qualification, **change), r.keys["qualification"])
    lookup = SimpleNamespace(current=lambda name, now: report)
    with pytest.raises(ProductionReadinessError, match="not currently qualified"):
        r.gate.check(r.evidence, **(r.inputs | {"qualifications": lookup}))


@pytest.mark.parametrize("change,reason", [
    ({"scope": "elsewhere"}, "scope or authority"),
    ({"executed_at_us": 101}, "not current"),
    ({"expires_at_us": 100}, "not current"),
    ({"outcomes": ()}, "incomplete"),
    ({"outcomes": (DrillOutcome("synthetic:drill", False, "Synthetic failure."),)},
     "unsuccessful"),
    ({"outcomes": (DrillOutcome("synthetic:other", True, "Synthetic other drill."),)},
     "incomplete"),
])
def test_inapplicable_signed_drill_observation_refuses_readiness(readiness, change, reason):
    r = readiness
    report = signed(replace(r.inputs["drill_report"], **change), r.keys["drill"])
    with pytest.raises(ProductionReadinessError, match=reason):
        r.gate.check(r.evidence, **(r.inputs | {"drill_report": report}))


@pytest.mark.parametrize("change", [
    {"content_digest": "0" * 64}, {"stored_at_us": 89}, {"stored_at_us": 101},
    {"retained_until_us": 100},
])
def test_inconsistent_retention_receipt_refuses_readiness(readiness, change):
    r = readiness
    receipt = replace(r.inputs["worm_receipt"], **change)
    with pytest.raises(ProductionReadinessError, match="retention proof content or validity"):
        r.gate.check(r.evidence, **(r.inputs | {"worm_receipt": receipt}))


@pytest.mark.parametrize("completed_at", [99, 170])
def test_readiness_rechecks_time_after_proof_loading(readiness, completed_at):
    r = readiness
    retained = r.inputs["worm_store"]

    class SyntheticElapsedProofLoad:
        def fetch(self, tenant, ref):
            data = retained.fetch(tenant, ref)
            r.clock.now = completed_at
            return data

        def verify(self, receipt):
            return retained.verify(receipt)

    with pytest.raises(ProductionReadinessError, match="backwards|expired during"):
        r.gate.check(r.evidence, **(r.inputs | {"worm_store": SyntheticElapsedProofLoad()}))
