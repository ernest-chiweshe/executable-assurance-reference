"""Run the existing outage/expiry contracts against the complete scoped host.

The imported tests retain every original assertion. Only their fixture changes:
signed fictional enrollment/appointments and explicit source confirmation now
participate in the same receiving admission as sessions and the reference core.
The two local timing tests allocate a 30-second REQUEST window so the scoped
checks can issue a permit before testing its expiry. They still wait for that
exact signed deadline; no permit, policy, clock, guard or margin is changed.
No physical late effect is induced and no provider runs.
"""

import os
import hashlib
import time

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock_pg import DbClock
from regulated_core.outage import AlarmRoute, FanOutAlarm, RecordingOutageAlarm, Severity
from regulated_core.target import Outcome
from education_fault_fixtures import AcknowledgementSessions, FaultClock, FaultRetention, FaultSigner
from test_education_scoped_release import source_decision
from test_education_signer_outage import BrokenAlarm
from test_education_session_release import approved_request

# Pytest deliberately collects these unchanged contract tests with this module's
# scoped fixtures. Their individual parameter marks are preserved too.
from test_education_faults import (  # noqa: F401
    test_trusted_time_fault_refuses_before_release_authority,
    test_retention_outage_withholds_release_permit,
    test_synthetic_uncertified_completion_retains_exact_signed_alert,
    test_synthetic_known_late_completion_is_classified_and_retained,
)
from test_education_signer_outage import (  # noqa: F401
    test_signer_failure_before_permit_refuses_and_raises_independent_alarm,
    test_outcome_signer_failure_is_unknown_then_reconciles_from_existing_receipt,
    test_broken_alarm_sink_does_not_mask_signer_refusal,
)


@pytest.fixture
def education(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path,
        clock_source=FaultClock(DbClock(roles.receiver, roles.domain)),
        retention=FaultRetention(LocalRetentionStore(tmp_path / "retention")),
        session_type=AcknowledgementSessions, scoped_authority=True)
    assert source_decision(app)["confirmed"]
    # Bound only the synthetic acknowledgement delivery wait. Runtime session
    # locks, deadlines, effect margin and database timeouts remain unchanged.
    app.sessions.acknowledgement_wait_seconds = 35
    return app


@pytest.fixture
def signer_app(tmp_path, request):
    drivers = {}

    def signer_factory(key_id):
        signer = FaultSigner(key_id)
        drivers[key_id.rsplit(":", 1)[1]] = signer
        return signer

    observed = RecordingOutageAlarm()
    routes = [AlarmRoute(observed, Severity.HIGH, "local-observer")]
    if getattr(request, "param", False):
        routes.insert(0, AlarmRoute(BrokenAlarm(), Severity.HIGH, "broken-fixture"))
    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]),
        tmp_path, signer_factory=signer_factory, outage_alarm=FanOutAlarm(routes), scoped_authority=True)
    assert source_decision(app)["confirmed"]
    return app, drivers, observed


def test_expired_approved_permit_refuses_before_file_effect(education):
    app = education
    context, decision = approved_request(app, effect_window_us=30_000_000)
    expiry = decision.permit.permit.permit.expires_at_us
    timeout = time.monotonic() + 35
    while app.clock.now_us() < expiry:
        assert time.monotonic() < timeout, "fixture clock did not reach the signed expiry"
        time.sleep(0.05)
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "failed", result
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")


@pytest.mark.parametrize("at_deadline", [False, True])
def test_lost_admission_close_acknowledgement_reconciles_from_receipt(education, at_deadline):
    app = education
    context, decision = approved_request(app, effect_window_us=30_000_000 if at_deadline else None)
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
    first_write = app.path.stat().st_mtime_ns
    target = gate.target_for(str(app.path), "school-a")
    reconciled = gate._engine.reconcile(decision.permit, target)
    assert reconciled.outcome is Outcome.COMMITTED
    receipt = gate.release_receipt(spec=app.spec, out_path=str(app.path), tenant="school-a",
        nonce=context.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None
    assert app.path.stat().st_mtime_ns == first_write
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
