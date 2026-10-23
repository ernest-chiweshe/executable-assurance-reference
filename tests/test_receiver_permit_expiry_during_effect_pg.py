"""Receiver expiry during a plain database effect must roll back the whole transaction.

The plain synthetic effect intentionally has no effect-side admission check. This
pins the receiver outcome independently of CAS-side protection. No runtime guard
is patched; only the requested permit lifetime is shortened during provisioning.
"""
from dataclasses import dataclass
import time
import json
import pytest

from assurance_reference.versioned_cas import VersionedRowEffect
from regulated_core.database_receiver_pg import PostgresTargetReceiver
from regulated_core.prepared_issuance_pg import PostgresPreparedIssuer
from regulated_core.target import Outcome
from versioned_cas_pg_fixture import BODY, OLD, prepared_cas_fixture, snapshot


@dataclass(frozen=True)
class PlainEffect(VersionedRowEffect):
    def _authorize_on(self, conn, output):
        return None


def test_permit_expiring_during_plain_effect_rolls_back_effect_receipt_use_and_budget(tmp_path, monkeypatch):
    original_draft = PostgresPreparedIssuer.draft

    def short_draft(self, *args, **kwargs):
        kwargs["ttl_us"] = 10_000_000
        return original_draft(self, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(PostgresPreparedIssuer, "draft", short_draft)
        f = prepared_cas_fixture(tmp_path)
    clock = f["authority"].clock
    permit = f["signed"].permit
    expires = permit.expires_at_us
    assert 0 < expires - permit.issued_at_us <= 10_000_000
    original = f["receiver"]._effect
    plain = PlainEffect(original.tenant_id, original.target, original.operation, original.expected_revision)
    calls = []

    class DelayedPlainEffect:
        tenant_id, target, operation = plain.tenant_id, plain.target, plain.operation

        def current_state_on(self, conn):
            return plain.current_state_on(conn)

        def apply_on(self, conn, output):
            call = {"entry_us": clock.read().now_us, "returned": False}
            calls.append(call)
            wait_limit = time.monotonic() + 20.0
            while True:
                reading = clock.read()
                if reading.now_us > expires + 50_000:
                    break
                assert time.monotonic() < wait_limit, "database clock did not cross expiry within harness bound"
                time.sleep(0.05)
            call["write_us"] = reading.now_us
            state = plain.apply_on(conn, output)
            call["returned"] = True
            return state

    receiver = PostgresTargetReceiver(pool=f["pool"], authority=f["authority"], effect=DelayedPlainEffect(),
                                      admission=f["receiver"]._admission)
    delivered = clock.read().now_us
    print("EXPIRY_DELIVERY " + json.dumps({"draft_us": permit.issued_at_us, "delivery_us": delivered, "draft_to_delivery_us": delivered - permit.issued_at_us, "remaining_us": expires - delivered}), flush=True)
    assert delivered < expires, "fixture permit expired before delivery; scenario not exercised"
    result = receiver.commit(f["signed"], BODY)
    finished = clock.read().now_us
    state = snapshot(f)
    evidence = {"delivered_us": delivered, "expires_us": expires, "finished_us": finished,
                "other_expiry_us": f["fixture"]["expires"], "calls": calls, "result": result, "state": state}
    print("EXPIRY_RESULT " + json.dumps({"draft_to_delivery_us": delivered - permit.issued_at_us, "delivered_us": delivered, "expires_us": expires, "finished_us": finished, "other_expiry_us": f["fixture"]["expires"], "calls": calls, "outcome": result.outcome.value, "detail": result.detail, "state": [state["state"][0], state["state"][1].hex()], "uses": state["uses"], "budget": state["budget"], "outcomes": state["outcomes"]}), flush=True)
    assert len(calls) == 1, evidence
    assert calls[0]["entry_us"] < expires < calls[0]["write_us"], evidence
    assert calls[0]["returned"], evidence
    assert finished < f["fixture"]["expires"], evidence
    assert result.outcome is Outcome.FAILED, evidence
    # A19 observes which layer refused; a different later layer can still keep the effect safe.
    assert result.detail == "permit clock domain or absolute window refused", evidence
    assert state == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}, evidence


@pytest.mark.parametrize("stage", ["before-claim", "after-effect"])
def test_earlier_host_deadline_refused_at_its_receiver_boundary(tmp_path, stage):
    """An earlier host deadline expires with permit and other credentials still live.

    The host fixture grants a two-second admission window. Waiting at the named
    boundary exercises actual database clock reads. No guard or clock is patched.
    PlainEffect is a synthetic transactional effect without a second CAS admission
    check, so the receiver must refuse and roll back. Refusal text measures guard
    sensitivity; a later-layer refusal is NOT an unsafe-commit finding.
    """
    f = prepared_cas_fixture(tmp_path, admission_window_us=2_000_000)
    clock, permit = f["authority"].clock, f["signed"].permit
    original = f["receiver"]
    effect = original._effect
    plain = PlainEffect(effect.tenant_id, effect.target, effect.operation, effect.expected_revision)
    deadlines, calls = [], []

    def wait_until_expired(deadline):
        limit = time.monotonic() + 10.0
        while True:
            reading = clock.read()
            if reading.now_us > deadline + 50_000:
                return reading.now_us
            assert time.monotonic() < limit, "host admission deadline did not elapse"
            time.sleep(0.025)

    class TimedAdmission:
        def lock_current_on(self, conn, signed, target):
            deadline = original._admission.lock_current_on(conn, signed, target)
            deadlines.append({"deadline_us": deadline, "returned_us": None})
            if stage == "before-claim":
                wait_until_expired(deadline)
            deadlines[-1]["returned_us"] = clock.read().now_us
            return deadline

    class TimedEffect:
        tenant_id, target, operation = plain.tenant_id, plain.target, plain.operation

        def current_state_on(self, conn):
            return plain.current_state_on(conn)

        def apply_on(self, conn, output):
            call = {"entry_us": clock.read().now_us, "returned": False}
            calls.append(call)
            if stage == "after-effect":
                call["write_us"] = wait_until_expired(deadlines[0]["deadline_us"])
            state = plain.apply_on(conn, output)
            call["returned"] = True
            return state

    receiver = PostgresTargetReceiver(pool=f["pool"], authority=f["authority"],
                                     effect=TimedEffect(), admission=TimedAdmission())
    result = receiver.commit(f["signed"], BODY)
    finished = clock.read().now_us
    state = snapshot(f)
    evidence = {"stage": stage, "deadlines": deadlines, "calls": calls,
                "finished_us": finished, "permit_expiry_us": permit.expires_at_us,
                "other_expiry_us": f["fixture"]["expires"], "detail": result.detail,
                "outcome": result.outcome.value, "state": [state["state"][0], state["state"][1].hex()],
                "uses": state["uses"], "budget": state["budget"], "outcomes": state["outcomes"]}
    evidence["lock_return_to_entry_us"] = (calls[0]["entry_us"] - deadlines[0]["returned_us"] if calls and deadlines else None)
    evidence["entry_margin_us"] = (deadlines[0]["deadline_us"] - calls[0]["entry_us"] if calls and deadlines else None)
    print("A19_HOST_DEADLINE " + json.dumps(evidence), flush=True)
    assert len(deadlines) == 1, evidence
    assert deadlines[0]["deadline_us"] < finished < min(permit.expires_at_us, f["fixture"]["expires"]), evidence
    assert result.outcome is Outcome.FAILED, evidence
    assert state == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}, evidence
    if stage == "before-claim":
        assert not calls, evidence
        assert deadlines[0]["returned_us"] > deadlines[0]["deadline_us"], evidence
        assert result.detail == "database admission or permit expired before claim", evidence
    else:
        assert len(calls) == 1 and calls[0]["returned"], evidence
        assert calls[0]["entry_us"] < deadlines[0]["deadline_us"] < calls[0]["write_us"], evidence
        assert result.detail == "authority expired before database commit", evidence
