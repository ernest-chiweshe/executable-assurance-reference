"""Measured synthetic reports, ordinary refusal cases, and one composed local render."""

import hashlib
import json
import os
import uuid
from dataclasses import asdict, replace

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.qualified_engine import (
    QualificationSet, QualifiedReferenceEngine, RequiredQualification,
)
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.local_retention import LocalRetentionStore
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, CoursePolicy, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry, PolicyContext,
    PolicyRegistry, PreflightAuthority, TrustDirectory, VerificationTrustStore,
)
from regulated_core.clock import ClockReading
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import PostgresPermitUseStore, PostgresMissionBudget, migrate
from regulated_core.qualification import (
    LabeledCase, QualificationDataset, QualificationError, qualify,
)
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def report_case(now=100, duration=100, predicate=None):
    signer = Ed25519Signer("fixture:qualification")
    trust = TrustDirectory()
    trust.register_signer(signer)
    dataset = QualificationDataset(
        "synthetic-marker", "1", "Four artificial strings; no clinical interpretation.",
        tuple(LabeledCase(text, expected) for text, expected in (
            ("flag: one", True), ("flag: two", True), ("plain one", False), ("plain two", False),
        )),
    )
    report = qualify(
        signer, verification_class="fixture:marker", verifier_version="1", dataset=dataset,
        predicate=predicate or (lambda text: text.startswith("flag:")),
        qualified_at_us=now, valid_for_us=duration, jurisdictions=("fixture",),
        languages=("en",), document_types=("synthetic-text",),
        limitations=("Synthetic marker classifier; not clinical qualification.",),
    )
    requirement = RequiredQualification(
        "fixture:marker", "1", dataset.digest(), "fixture", "en", "synthetic-text", "1", "1",
    )
    return signer, trust, report, requirement


def gate(trust, report, requirement, domain="fixture:clock"):
    return QualificationSet(
        trust=trust, authority="fixture:qualification", clock_domain=domain,
        required=(requirement,), reports=() if report is None else (report,),
    )


def test_measured_report_signature_digest_and_exact_validity_window():
    signer, trust, report, requirement = report_case()
    assert asdict(report.characteristics) | {} == {
        "precision": "1.0000", "recall": "1.0000", "f1": "1.0000",
        "tp": 2, "fp": 0, "fn": 0, "tn": 2,
        "jurisdictions": ("fixture",), "languages": ("en",),
        "document_types": ("synthetic-text",),
    }
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
        bytes.fromhex(report.signature.value), canonical(report.signed_body()),
    )
    digest = hashlib.sha256(canonical(dict(report.signed_body(), sig=report.signature.value))).hexdigest()
    configured = gate(trust, report, requirement)
    assert configured.check(ClockReading("fixture:clock", 100)) == ((digest,), 200)
    assert configured.check(ClockReading("fixture:clock", 199)) == ((digest,), 200)
    for now in (99, 200):
        with pytest.raises(QualificationError, match="not current"):
            configured.check(ClockReading("fixture:clock", now))


@pytest.mark.parametrize("change", [
    {"verifier_version": "2"}, {"dataset_digest": "a" * 64},
    {"jurisdiction": "elsewhere"}, {"language": "fr"}, {"document_type": "clinical"},
])
def test_host_requirement_mismatch_is_refused(change):
    _, trust, report, requirement = report_case()
    with pytest.raises(QualificationError):
        gate(trust, report, replace(requirement, **change)).check(ClockReading("fixture:clock", 150))


def test_missing_untrusted_low_quality_and_other_clock_are_refused():
    _, trust, report, requirement = report_case()
    _, _, poor, _ = report_case(predicate=lambda _: False)
    for configured, reading in (
        (gate(trust, None, requirement), ClockReading("fixture:clock", 150)),
        (gate(TrustDirectory(), report, requirement), ClockReading("fixture:clock", 150)),
        (gate(trust, report, requirement), ClockReading("other:clock", 150)),
    ):
        with pytest.raises(QualificationError):
            configured.check(reading)
    # Use the low-quality report's own explicitly trusted fixture authority.
    _, poor_trust, poor, requirement = report_case(predicate=lambda _: False)
    with pytest.raises(QualificationError, match="thresholds"):
        gate(poor_trust, poor, requirement).check(ClockReading("fixture:clock", 150))


@pytest.mark.parametrize("policy_sibling", [False, True])
def test_composed_engine_records_refusal_and_binds_report_to_real_permit(tmp_path, policy_sibling):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn and conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    (tmp_path / "retained-schema.json").write_text(json.dumps({"schema": schema}), encoding="utf-8")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    # Synthetic single-login provisioning within this test's isolated schema.
    with pool.connection() as connection:
        connection.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                           "SELECT session_user::text,kind FROM "
                           "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
    budget = PostgresMissionBudget(pool=pool)
    provision_alerts(pool)
    primary = DbClock(pool, domain)
    provision_floor(pool, primary)
    clock = DurableClock(primary, floor_pool=pool)
    signer, trust, report, requirement = report_case(clock.now_us(), 60_000_000)
    signers = {role: Ed25519Signer("qualified:" + role) for role in (
        "evidence", "approval", "identity", "emission", "preflight", "alert",
    )}
    for key in signers.values():
        trust.register_signer(key)
    recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    uses = PostgresPermitUseStore(pool=pool)
    registry = PolicyRegistry()
    registry.register(CoursePolicy())
    intended = IntendedUseRegistry()
    operation = "course:render-lesson"
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(signers["preflight"], intended, trust)
    engine = QualifiedReferenceEngine(
        budget=budget, default_mission_budget={"limit": 1, "units": 1},
        retention=LocalRetentionStore(tmp_path / "retention"),
        qualifications=gate(trust, report, requirement, domain),
        alerts=AlertJournal(pool, signers["alert"], trust), registry=registry, recorder=recorder,
        verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, signers["approval"], IdentityVerifier(trust, "qualified:identity")),
        emission=EmissionAuthority(signers["emission"], trust, uses), preflight=preflight, clock=clock,
    )
    if policy_sibling:
        sibling_uses = IntendedUseRegistry()
        sibling_uses.declare(IntendedUse("course", operation, 1))
        sibling_registry = PolicyRegistry()
        sibling_registry.register(CoursePolicy())
        engine = engine.for_policy(registry=sibling_registry,
                                   preflight=preflight.for_uses(sibling_uses))
    tenant = "synthetic-qualified-render"
    body = b"A local reversible draft, not a publication or clinical result.\n"
    digest = hashlib.sha256(body).hexdigest()
    target = FilesystemTargetAdapter(
        path=tmp_path / "draft.txt", tenant_id=tenant, authority=engine.targets, uses=uses,
        operation_name=operation, budget=budget,
    )
    assertion = Assertion("draft", tenant, "course:lesson", content_digest=digest)
    context = PolicyContext(tenant, Actor("author", tenant, frozenset()), "education:draft", "draft", 0)
    action = Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination(
        {}, BoundEffect(digest, target.target, target.current_state(),
                        mission="synthetic:qualified-render"),
    ))
    capability = preflight.authorize(
        tenant_id=tenant, vertical="course", action_id=operation, risk_tier=1,
        correlation_id="draft", now_us=clock.now_us(), ttl_us=120_000_000, nonce="draft-capability",
    )
    parameters = dict(vertical="course", capability=capability, assertion=assertion, action=action,
                      ctx=context, output=body, target=target, permit_ttl_us=120_000_000)
    refused = engine.authorize_for_target(
        **parameters, nonce="request-owned-report", qualification_digests=(report.digest(),),
    )
    assert not refused.authorized and refused.permit is None and not target.path.exists()
    assert refused.envelope.record.decision.reason_codes == ("QUALIFICATION_REFUSED",)
    assert recorder.verify_entry(refused.envelope)
    # An ordinary caller cannot select an unknown qualification report.
    unknown_digest = hashlib.sha256(b"synthetic:unregistered-qualification-report").hexdigest()
    assert unknown_digest != report.digest()
    unknown = engine.authorize_for_target(
        **parameters, nonce="unknown-report-reference", qualification_digests=(unknown_digest,),
    )
    assert not unknown.authorized and unknown.permit is None and not target.path.exists()
    assert unknown.envelope.record.decision.reason_codes == ("QUALIFICATION_REFUSED",)
    assert recorder.verify_entry(unknown.envelope)
    assert budget.committed(tenant, "synthetic:qualified-render") == 0
    authorized = engine.authorize_for_target(**parameters, nonce="host-qualified")
    assert authorized.authorized and authorized.permit is not None
    permit = authorized.permit.permit
    assert permit.qualification_digests == (report.digest(),)
    assert permit.expires_at_us == report.expires_at_us
    assert permit.decision_record_hash == authorized.envelope.record_hash
    Ed25519PublicKey.from_public_bytes(signers["emission"].public_key_bytes).verify(
        bytes.fromhex(authorized.permit.signature.value), canonical(permit.signed_body()),
    )
    result = engine.commit(authorized, body, target)
    assert result.outcome is Outcome.COMMITTED and target.path.read_bytes() == body
    assert budget.committed(tenant, "synthetic:qualified-render") == 1
    assert recorder.verify_chain(tenant)
    (tmp_path / "qualification-evidence.json").write_text(json.dumps({
        "report": report.signed_body(), "report_signature": asdict(report.signature),
        "report_digest": report.digest(), "permit": permit.signed_body(),
        "permit_signature": asdict(authorized.permit.signature),
        "qualification_public_key": signer.public_key_bytes.hex(),
        "permit_public_key": signers["emission"].public_key_bytes.hex(),
        "scope": "Synthetic qualification-to-permit linkage; no clinical or governed-registry claim.",
    }, indent=2), encoding="utf-8")
