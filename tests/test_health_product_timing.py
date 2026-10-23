"""Guarded timing contracts on the actual Health and neutral application paths.

Used alongside test_education_scoped_faults for three-application qualification.
Only source availability, caller scheduling and post-transaction acknowledgement
delivery vary. No guard, signed deadline, physical effect or clock is bypassed.
"""

import hashlib
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.session_credentials import SessionUnavailable
from assurance_reference.timing_observations import (
    CompletionObservation, SignedCompletionObservation, TimingObservationRecorder,
)
from education_fault_fixtures import AcknowledgementSessions, FaultClock
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_FAILED,
    FINALISATION_UNKNOWN, Paragraph, Session, build_document)
from factory.health_ui.store import StoreDegraded
from factory.health_ui.templates import CONSULTATION
from factory.projectos.engine import ProjectEngineError
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import digest_hex
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome
from test_product_spec_authority import ScriptedFactory, approve


@pytest.fixture(params=["health", "product_spec"])
def case(request, tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    fault = FaultClock(DbClock(roles.receiver, roles.domain))
    if request.param == "health":
        app = build_clinical_fixture(roles, tmp_path, clock_source=fault, session_type=AcknowledgementSessions)
        document = build_document(CONSULTATION, "Fictional timing record", "case-fixture", "Invented subject", [])
        for section in document.sections:
            section.paragraphs.append(Paragraph("Invented timing qualification text; no patient or clinical advice.",
                                               OBSERVATION, origin=CLINICIAN))
        session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
            "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
            workspace_id=app.clinician.workspace_id, documents=[document])
        app.store.save(session)
        gate, tenant = app.gate, app.clinician.workspace_id
        def invoke():
            return app.finaliser.finalise(session, document, app.clinician)

        def files():
            return list(app.records.rglob("*.docx"))
    else:
        app = build_product_spec_fixture(roles, tmp_path, factory=ScriptedFactory(),
            clock_source=fault, session_type=AcknowledgementSessions)
        app.engine.new("inventory", title="Fictional inventory", idea="A local workshop fixture")
        for stage in ("problem", "solution", "scope", "spec"):
            app.engine.run_stage("inventory", stage, tenant=app.tenant)
        now = app.clock.now_us()
        app.context = EmissionContext(tenant=app.tenant, actor_id="requester", project_id="inventory",
            vertical_name=app.spec.name, action_id="release", nonce="timing-fixture",
            now_us=now, not_after_us=now + 30_000_000, release_target=str(app.path))
        _, assembled = app.engine.assemble("inventory", tenant=app.tenant, context=app.context)
        assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
        context = approve(app)
        gate, tenant = app.gates["requester"], app.tenant
        def invoke():
            return app.engine.release("inventory", str(app.path), context=context)

        def files():
            return [app.path] if app.path.exists() else []
    app.sessions.acknowledgement_wait_seconds = 35
    return SimpleNamespace(kind=request.param, app=app, gate=gate, tenant=tenant,
        roles=roles, fault=fault, invoke=invoke, files=files)


def observe_commit(case, before=lambda kwargs: None):
    """Observe the ordinary boundary; always call its original guard and effect."""
    original = case.gate.commit_release
    captured = {}

    def call(**kwargs):
        assert kwargs["decision"].allowed
        captured.update(kwargs)
        before(kwargs)
        result = original(**kwargs)
        captured["result"] = result
        return result

    case.gate.commit_release = call
    return captured


def wait_expiry(case, kwargs):
    expiry = kwargs["decision"].permit.permit.permit.expires_at_us
    timeout = time.monotonic() + 35
    while case.app.clock.now_us() < expiry:
        assert time.monotonic() < timeout
        time.sleep(0.05)


def run_refused_or_unknown(case, expected):
    if case.kind == "health":
        result = case.invoke()
        assert result.state == {"failed": FINALISATION_FAILED, "unknown": FINALISATION_UNKNOWN}[expected], result
    else:
        with pytest.raises(ProjectEngineError):
            case.invoke()


@pytest.mark.parametrize("fault", ["unavailable", "uncertain"])
def test_trusted_time_source_refuses_before_new_permit(case, fault):
    with case.roles.receiver.connection() as conn:
        before = conn.execute("SELECT count(*) FROM regulated_permit_uses_v1").fetchone()
    case.fault.fault = fault
    with pytest.raises((ClockError, SessionUnavailable, StoreDegraded)) as refused:
        case.invoke()
    error = refused.value
    while error is not None and not isinstance(error, ClockError):
        error = error.__cause__
    assert isinstance(error, ClockError) and "fixture" in str(error)
    assert case.files() == []
    with case.roles.receiver.connection() as conn:
        assert conn.execute("SELECT count(*) FROM regulated_permit_uses_v1").fetchone() == before
    case.fault.fault = None
    assert case.app.stores.recorder.verify_chain(case.tenant)


def test_expired_permit_is_refused_before_application_file(case):
    captured = observe_commit(case, lambda kwargs: wait_expiry(case, kwargs))
    run_refused_or_unknown(case, "failed")
    assert captured["result"].state == "failed"
    assert case.files() == []
    assert case.app.stores.recorder.verify_chain(case.tenant)


@pytest.mark.parametrize("at_deadline", [False, True])
def test_lost_close_ack_reconciles_without_second_effect(case, at_deadline):
    def lose_ack(kwargs):
        case.app.sessions.lose_exit_acknowledgement = True
        if at_deadline:
            case.app.sessions.acknowledgement_deadline_us = kwargs["decision"].permit.permit.permit.expires_at_us

    captured = observe_commit(case, lose_ack)
    run_refused_or_unknown(case, "unknown")
    assert captured["result"].state == "unknown"
    path = Path(captured["out_path"])
    assert case.files() == [path]
    assert path.read_bytes() == captured["artifact"]
    stat = (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
    decision = captured["decision"]
    if at_deadline:
        assert case.app.clock.now_us() >= decision.permit.permit.permit.expires_at_us
    target = case.gate.target_for(str(path), case.tenant)
    reconciled = case.gate._engine.reconcile(decision.permit, target)
    assert reconciled.outcome is Outcome.COMMITTED
    receipt = case.gate.release_receipt(spec=case.app.spec, out_path=str(path), tenant=case.tenant,
        nonce=captured["context"].nonce, artifact_sha256=stat[1],
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None
    assert (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) == stat
    assert case.app.stores.recorder.verify_chain(case.tenant)


@pytest.mark.parametrize("classification", ["UNCERTAIN", "LATE"])
def test_signed_synthetic_completion_preserves_actual_receipt(case, classification):
    captured = observe_commit(case)
    result = case.invoke()
    assert "result" in captured, result
    assert captured["result"].state == "committed", captured["result"]
    path = Path(captured["out_path"])
    stat = (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
    decision = captured["decision"]
    permit = decision.permit.permit
    p = permit.permit
    journal = case.gate._engine._alerts
    observer = Ed25519Signer("fixture:" + case.kind + ":synthetic-completion-observer")
    journal.trust.register_signer(observer)
    reporter = TimingObservationRecorder(journal=journal,
        permit_key_ids={permit.signature.key_id}, observer_key_ids={observer.key_id})
    lower = -1 if classification == "UNCERTAIN" else 1
    event = CompletionObservation(p.tenant_id, digest_hex(p.signed_body()), p.clock_domain,
        p.expires_at_us + lower, p.expires_at_us + 2, True)
    identifier = reporter.record(permit, SignedCompletionObservation(event, observer.sign(event.body())))
    payload = journal.read(identifier, tenant_id=p.tenant_id)["payload"]
    assert payload["classification"] == classification
    assert payload["synthetic"] is True and payload["effect_invoked"] is False
    assert payload["outcome"] == "unknown" and payload["requires_reconciliation"] is True
    assert payload["permit_hash"] == digest_hex(p.signed_body())
    assert payload["decision_hash"] == decision.permit.envelope.record_hash
    assert payload["authority_time_us"] is None
    # The synthetic observation does not rewrite the real committed receipt or
    # claim the earlier lawful effect was late. No second effect is invoked.
    receipt = case.gate.release_receipt(spec=case.app.spec, out_path=str(path), tenant=case.tenant,
        nonce=captured["context"].nonce, artifact_sha256=stat[1],
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None
    assert (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) == stat
    assert case.app.stores.recorder.verify_chain(case.tenant)
