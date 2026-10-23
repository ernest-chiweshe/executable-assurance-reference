"""Signer dependency faults on the composed Education path; guards stay intact."""

import json
import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.outage import (
    AlarmRoute, FanOutAlarm, RecordingOutageAlarm, Severity, alarm_envelope,
)
from regulated_core.target import Outcome
from education_fault_fixtures import FaultSigner
from test_education_session_release import approved_request, reviewed_context


class BrokenAlarm:
    def raise_alarm(self, event):
        raise OSError("fictional local alarm endpoint unavailable")


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
    alarm = FanOutAlarm(routes)
    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]),
        tmp_path, signer_factory=signer_factory, outage_alarm=alarm)
    return app, drivers, observed


@pytest.mark.parametrize("component", ["preflight", "verifier", "evidence", "emission"])
def test_signer_failure_before_permit_refuses_and_raises_independent_alarm(signer_app, component):
    app, drivers, observed = signer_app
    context = reviewed_context(app)
    drivers[component].unavailable = True
    decision = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert drivers[component].failed_calls > 0
    assert decision.allowed is False
    assert decision.permit is None
    assert decision.evidence == {"outage": "signer", "signed": False}
    assert not app.path.exists()
    assert len(observed.events) == 1
    event = observed.events[0]
    assert event.component == "signer" and event.operation == "authorize_release"
    assert event.severity is Severity.HIGH and event.phase == "contained"
    assert event.tenant_id == "school-a"
    assert app.stores.recorder.verify_chain("school-a")
    (app.path.parent / "signer-refusal-evidence.json").write_bytes(canonical_bytes({
        "fixture": True, "signer_role": component, "decision": decision,
        "alarm": alarm_envelope(event), "target_exists": False,
        "chain": app.stores.recorder.entries("school-a"), "public_keys": app.public_keys,
        "limits": "In-process independent alarm observer; no operator delivery or external custody claim.",
    }))


def test_outcome_signer_failure_is_unknown_then_reconciles_from_existing_receipt(signer_app):
    app, drivers, observed = signer_app
    context, decision = approved_request(app)
    drivers["evidence"].unavailable = True
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    assert drivers["evidence"].failed_calls > 0
    assert result.state == "unknown"
    assert result.evidence == {"outage": "signer", "signed": False}
    assert app.path.read_bytes() == app.body
    first_write = app.path.stat().st_mtime_ns
    assert len(observed.events) == 1
    event = observed.events[0]
    assert event.severity is Severity.CRITICAL and event.phase == "outcome-unknown"
    assert event.component == "signer" and event.operation == "commit_release"
    engine = app.gates["requester"]._engine
    journal = engine._alerts
    identifiers = journal.list_ids(tenant_id="school-a")
    retained = [journal.read(identifier, tenant_id="school-a") for identifier in identifiers]
    assert len(retained) == 1
    payload = retained[0]["payload"]
    assert payload["code"] == "OUTCOME_RECORDING_FAILED"
    assert payload["decision_hash"] == decision.permit.envelope.record_hash
    assert payload["permit_hash"] == digest_hex(decision.permit.permit.permit.signed_body())
    assert payload["requires_reconciliation"] is True
    assert payload["authority_time_us"] is None
    target = app.gates["requester"].target_for(str(app.path), "school-a")
    # Only restore this test driver's availability, then query the real receipt.
    # No replay/commit call, fabricated receipt, guard change or clock change.
    drivers["evidence"].unavailable = False
    reconciled = engine.reconcile(decision.permit, target)
    assert reconciled.outcome is Outcome.COMMITTED
    assert app.path.stat().st_mtime_ns == first_write
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
    (app.path.parent / "signer-reconciliation-evidence.json").write_bytes(canonical_bytes({
        "fixture": True, "initial_outcome": result, "alarm": alarm_envelope(event),
        "independent_signed_alert": retained[0], "reconciled": reconciled,
        "no_second_write": True, "public_keys": app.public_keys,
        "chain": app.stores.recorder.entries("school-a"),
        "limits": "Alert signing and database remained available; no general outage delivery guarantee.",
    }))


@pytest.mark.parametrize("signer_app", [True], indirect=True)
def test_broken_alarm_sink_does_not_mask_signer_refusal(signer_app, caplog):
    app, drivers, observed = signer_app
    # The failing route precedes the independent observer. It must not prevent
    # either the observer or the structured log from receiving the outage.
    context = reviewed_context(app)
    drivers["emission"].unavailable = True
    decision = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert not decision.allowed and decision.permit is None
    messages = [json.loads(record.message) for record in caplog.records
                if '"marker": "REGULATED_AUTHORITY_OUTAGE"' in record.message]
    assert messages and messages[-1]["phase"] == "contained"
    assert messages[-1]["severity"] == "HIGH"
    assert len(observed.events) == 1
    failures = [json.loads(record.message) for record in caplog.records
                if '"marker": "REGULATED_ALARM_SINK_FAILURE"' in record.message]
    assert failures and failures[-1]["route"] == "broken-fixture"
    assert not app.path.exists()
