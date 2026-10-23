"""Synthetic store availability observations with all authority checks intact."""

from contextlib import contextmanager
import os

import psycopg
import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.outage import RecordingOutageAlarm, Severity
from regulated_core.target import Outcome
from test_education_record_outage import RecordFailurePool
from test_education_session_release import reviewed_context


class UnavailablePool:
    @contextmanager
    def connection(self):
        raise psycopg.OperationalError("synthetic store unavailable")
        yield  # pragma: no cover


def fixture(tmp_path):
    alarm = RecordingOutageAlarm()
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path, outage_alarm=alarm)
    return app, app.gates["requester"], alarm


def assert_alarm(alarm, *, effect_possible, operation):
    event, = alarm.events
    assert event.detail == "OperationalError"
    assert event.component == "authority-store" and event.operation == operation
    assert event.phase == ("outcome-unknown" if effect_possible else "contained")
    assert event.severity is (Severity.CRITICAL if effect_possible else Severity.HIGH)


def test_entry_review_store_unavailable_refuses_without_permit(tmp_path):
    app, gate, alarm = fixture(tmp_path)
    context = reviewed_context(app)
    store = gate._review_store
    original = store._pool
    store._pool = UnavailablePool()
    try:
        decision = gate.authorize_release(spec=app.spec, contract=app.contract,
            out_path=str(app.path), context=context, artifact=app.body)
    finally:
        store._pool = original
    assert not decision.allowed and decision.permit is None
    assert decision.evidence == {"outage": "authority-store", "signed": False}
    assert not app.path.exists()
    assert not app.stores.permits.used("school-a", context.nonce)
    assert_alarm(alarm, effect_possible=False, operation="authorize_release")


def test_entrance_recording_unavailable_returns_unsigned_refusal(tmp_path):
    app, gate, alarm = fixture(tmp_path)
    recorder = app.stores.recorder
    original = recorder._pool
    before = recorder.entries("school-a")
    fault = RecordFailurePool(original, "insert")
    recorder._pool = fault
    try:
        decision = gate.record_entrance_refusal(spec=app.spec, contract=app.contract,
            context=app.context, code="SYNTHETIC_REFUSAL", reason="synthetic entrance refusal")
    finally:
        recorder._pool = original
    assert not decision.allowed and decision.permit is None
    assert decision.evidence == {"outage": "authority-store", "signed": False}
    assert fault.failures == 1
    assert recorder.entries("school-a") == before
    assert not app.path.exists()
    assert_alarm(alarm, effect_possible=False, operation="record_entrance_refusal")


@pytest.mark.parametrize("phase", ["insert", "before-commit"])
def test_outcome_recording_unavailable_preserves_unknown_then_reconciles(tmp_path, phase):
    app, gate, alarm = fixture(tmp_path)
    context = reviewed_context(app)
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert decision.allowed and decision.permit is not None
    recorder = app.stores.recorder
    original = recorder._pool
    before = recorder.entries("school-a")
    fault = RecordFailurePool(original, phase)
    recorder._pool = fault
    try:
        result = gate.commit_release(spec=app.spec, contract=app.contract,
            decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    finally:
        recorder._pool = original
    assert result.state == "unknown"
    assert result.evidence == {"outage": "authority-store", "signed": False}
    assert fault.failures == 1
    assert recorder.entries("school-a") == before
    assert app.path.read_bytes() == app.body
    assert app.stores.permits.used("school-a", context.nonce)
    assert_alarm(alarm, effect_possible=True, operation="commit_release")
    # Recovery reads the target's retained receipt; it does not resend the bytes.
    target = gate.target_for(str(app.path), "school-a")
    recovered = gate._engine.reconcile(decision.permit, target)
    assert recovered.outcome is Outcome.COMMITTED
    assert recorder.verify_chain("school-a")
