"""Guarded Education fault/expiry checks, with no physical late-write race."""

import hashlib
import time

import pytest

# Pytest discovers this imported fixture; test arguments intentionally share its name.
# ruff: noqa: F811

from regulated_core.clock import ClockError
from regulated_core.permit import EmissionError
from regulated_core.canonical import digest_hex
from regulated_core.target import Outcome, TargetResult
from regulated_core.signing import Ed25519Signer
from assurance_reference.timing_observations import (
    CompletionObservation, SignedCompletionObservation, TimingObservationRecorder,
)
from test_education_session_release import education, approved_request, reviewed_context  # noqa: F401

pytestmark = pytest.mark.parametrize("education", [True], indirect=True)


@pytest.mark.parametrize("fault", ["unavailable", "uncertain"])
def test_trusted_time_fault_refuses_before_release_authority(education, fault):
    app = education
    context = reviewed_context(app)
    app.fault_source.fault = fault
    with pytest.raises(EmissionError, match="authority clock unavailable") as refusal:
        app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
            out_path=str(app.path), context=context, artifact=app.body)
    assert isinstance(refusal.value.__cause__, ClockError)
    assert "fixture" in str(refusal.value.__cause__)
    assert not app.path.exists()
    # Inspection after restoring the fixture source is not an authority restart
    # or rollback recovery claim. No receipt is manufactured during the outage.
    app.fault_source.fault = None
    assert app.stores.recorder.verify_chain("school-a")


def test_retention_outage_withholds_release_permit(education):
    app = education
    context = reviewed_context(app)
    app.fault_retention.unavailable = True
    decision = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert not decision.allowed and decision.permit is None
    assert decision.evidence["outage"] == "write-once-evidence"
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")


def test_expired_approved_permit_refuses_before_file_effect(education):
    app = education
    context, decision = approved_request(app, effect_window_us=5_000_000)
    expiry = decision.permit.permit.permit.expires_at_us
    deadline = time.monotonic() + 7
    while app.clock.now_us() < expiry:
        assert time.monotonic() < deadline, "fixture clock did not reach the ordinary expiry"
        time.sleep(0.05)
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "failed", result
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")


@pytest.mark.parametrize("at_deadline", [False, True])
def test_lost_admission_close_acknowledgement_reconciles_from_receipt(education, at_deadline):
    app = education
    context, decision = approved_request(app, effect_window_us=8_000_000 if at_deadline else None)
    expiry = decision.permit.permit.permit.expires_at_us
    app.sessions.lose_exit_acknowledgement = True
    if at_deadline:
        app.sessions.acknowledgement_deadline_us = expiry
    gate = app.gates["requester"]
    result = gate.commit_release(spec=app.spec, contract=app.contract, decision=decision,
        artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "unknown", result
    if at_deadline:
        assert app.clock.now_us() >= expiry
    assert app.path.read_bytes() == app.body
    # Observe the actual receiving receipt; never resubmit the effect to decide.
    target = gate.target_for(str(app.path), "school-a")
    reconciled = gate._engine.reconcile(decision.permit, target)
    assert reconciled.outcome is Outcome.COMMITTED
    receipt = gate.release_receipt(spec=app.spec, out_path=str(app.path), tenant="school-a",
        nonce=context.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None
    assert app.stores.recorder.verify_chain("school-a")


def test_synthetic_uncertified_completion_retains_exact_signed_alert(education):
    """Exercise the reporting contract, without causing a late effect."""
    app = education
    _, decision = approved_request(app)
    engine = app.gates["requester"]._engine
    observation = TargetResult(Outcome.UNKNOWN,
        "SYNTHETIC observation: completion before permit expiry is uncertified; no effect invoked")
    result = engine._record_outcome(decision.permit, observation, reconciled=False)
    assert result.outcome is Outcome.UNKNOWN
    assert result.envelope.record.decision.reason_codes == ("OUTCOME_UNKNOWN",)
    journal = engine._alerts
    ids = journal.list_ids(tenant_id="school-a")
    alerts = [journal.read(identifier, tenant_id="school-a")["payload"] for identifier in ids]
    exact = [alert for alert in alerts
             if alert.get("permit_hash") == digest_hex(decision.permit.permit.permit.signed_body())]
    assert len(exact) == 1
    assert exact[0]["code"] == "TARGET_UNKNOWN"
    assert exact[0]["decision_hash"] == decision.permit.envelope.record_hash
    assert exact[0]["outcome"] == "unknown"
    assert exact[0]["authority_time_us"] is None
    assert exact[0]["requires_reconciliation"] is True
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")


def test_synthetic_known_late_completion_is_classified_and_retained(education):
    app = education
    _, decision = approved_request(app)
    permit = decision.permit.permit
    p = permit.permit
    journal = app.gates["requester"]._engine._alerts
    observer = Ed25519Signer("fixture:education-completion-observer")
    journal.trust.register_signer(observer)
    reporter = TimingObservationRecorder(journal=journal,
        permit_key_ids={permit.signature.key_id}, observer_key_ids={observer.key_id})
    # An explicit synthetic event, not a clock change or a physical late write.
    event = CompletionObservation(p.tenant_id, digest_hex(p.signed_body()), p.clock_domain,
                                  p.expires_at_us + 1, p.expires_at_us + 2, True)
    identifier = reporter.record(permit, SignedCompletionObservation(event, observer.sign(event.body())))
    payload = journal.read(identifier, tenant_id=p.tenant_id)["payload"]
    assert payload["code"] == "SYNTHETIC_COMPLETION_LATE"
    assert payload["classification"] == "LATE"
    assert payload["synthetic"] is True
    assert payload["permit_hash"] == digest_hex(p.signed_body())
    assert payload["decision_hash"] == decision.permit.envelope.record_hash
    assert payload["outcome"] == "unknown"
    assert payload["requires_reconciliation"] is True
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")
