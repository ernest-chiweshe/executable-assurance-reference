"""X-4 on actual restricted local logins: prepare, review, grant, settle one retained permit, recover by observation.

Fictional school; isolated PostgreSQL. The exact bytes are prepared and bound before review (inherited
PREPARATION_FIELD); producer and requester grants are refused by the inherited exchange
(test_education_session_release.py requester-self-review; test_producer_bound_requester_self_approval_pg.py).
Settlement retains exactly one authorization per approved review; re-entry returns that same permit and its live
reservation; a changed binding refuses; a crash at either named settlement point is UNKNOWN, never a second permit.
"""
from dataclasses import replace
import hashlib

import pytest

import assurance_reference.retained_settlement as settlement_module
from assurance_reference.retained_settlement import (RetainedSettlements, SettledReleaseGate, SettlementRefused,
                                                     SettlementUnknown)
from test_education_session_release import education, reviewed_context  # noqa: F401


class Crash(BaseException):
    """Stands in for process death at a named settlement point."""


def _scene(app):
    gate = SettledReleaseGate(app.gates["requester"], RetainedSettlements(pool=app.roles.settlement_writer))
    context = reviewed_context(app)
    request = dict(spec=app.spec, contract=app.contract, artifact=app.body, out_path=str(app.path))
    return gate, context, request


def _reservations(app, permit):
    with app.roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (permit.tenant_id,))
        return conn.execute("SELECT count(*) FROM regulated_mission_budget_events_v1 WHERE tenant=%s"
                            " AND kind='reserve' AND mission=%s", (permit.tenant_id, permit.mission)).fetchone()[0]


def test_settle_once_reenter_same_permit_commit_once_and_observe(education):  # noqa: F811
    app = education
    gate, context, request = _scene(app)
    first = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert first.allowed, first.reason
    again = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert again.evidence == {"settlement": "re-entered"}
    assert again.permit.permit == first.permit.permit  # The same signed permit and the same reservation.
    assert _reservations(app, first.permit.permit.permit) == 1
    result = gate.commit_release(spec=app.spec, contract=app.contract, decision=again, artifact=app.body,
                                 out_path=str(app.path), context=replace(context, now_us=app.clock.now_us()))
    assert result.state == "committed", result
    modified = app.path.stat().st_mtime_ns
    after = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert after.permit.permit == first.permit.permit
    second = gate.commit_release(spec=app.spec, contract=app.contract, decision=after, artifact=app.body,
                                 out_path=str(app.path), context=replace(context, now_us=app.clock.now_us()))
    assert second.state != "committed" or app.path.stat().st_mtime_ns == modified
    assert app.path.stat().st_mtime_ns == modified and app.path.read_bytes() == app.body
    receipt = app.gates["requester"].release_receipt(spec=app.spec, out_path=str(app.path), tenant="school-a",
        nonce=first.permit.permit.permit.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=first.permit.envelope.record_hash)
    assert receipt is not None  # Recovery by observation of the target receipt; nothing is resent.
    review = app.gates["requester"].get_review(spec=app.spec, contract=app.contract,
        context=replace(context, approval=None, now_us=app.clock.now_us()), review_id=context.approval)
    assert review["status"] == "approved"

@pytest.mark.parametrize("change", ["artifact", "contract", "out_path", "nonce", "principal"])
def test_reentry_with_a_changed_binding_is_refused(education, change):  # noqa: F811
    app = education
    gate, context, request = _scene(app)
    first = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert first.allowed, first.reason
    changed = dict(request)
    if change == "artifact":
        changed["artifact"] = app.body + b" changed"
    elif change == "contract":
        changed["contract"] = {**app.contract, "findings": ["changed"]}
    elif change == "out_path":
        changed["out_path"] = str(app.path.with_name("other.txt"))
    other = {"nonce": {"nonce": "other-nonce"}, "principal": {"actor_id": "other-principal"}}.get(change, {})
    timed = replace(context, now_us=app.clock.now_us(), **other)
    with pytest.raises(SettlementRefused, match="different binding"):
        gate.settle(**changed, context=timed)
    assert _reservations(app, first.permit.permit.permit) == 1 and not app.path.exists()


def test_a_settled_nonce_named_under_another_review_is_refused(education):  # noqa: F811
    app = education
    gate, context, request = _scene(app)
    first = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert first.allowed, first.reason
    with pytest.raises(SettlementRefused, match="another review"):
        gate.settle(**request, context=replace(context, approval="other-review", now_us=app.clock.now_us()))
    assert _reservations(app, first.permit.permit.permit) == 1 and not app.path.exists()


@pytest.mark.parametrize("point", ["after-intent-before-authorization", "after-authorization-before-retention"])
def test_crash_at_a_named_settlement_point_is_unknown_never_a_second_permit(education, monkeypatch, point):  # noqa: F811
    app = education
    gate, context, request = _scene(app)
    if point == "after-intent-before-authorization":
        monkeypatch.setattr(gate._gate, "authorize_release",
                            lambda **kwargs: (_ for _ in ()).throw(Crash(point)), raising=False)
    else:
        monkeypatch.setattr(settlement_module, "_encode", lambda authorization: (_ for _ in ()).throw(Crash(point)))
    with pytest.raises(Crash, match=point):
        gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    monkeypatch.undo()
    with pytest.raises(SettlementUnknown):
        gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert not app.path.exists()


def _tamper_retained(app, tenant, review_id, change):
    # The settlement writer login itself holds UPDATE(authorization_body): a compromised writer credential or a
    # defect can alter the retained authorization at rest without any administrator.
    import json as _json
    with app.roles.settlement_writer.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        body = conn.execute(f"SELECT authorization_body FROM {settlement_module.TABLE}"
                            " WHERE tenant=%s AND review_id=%s", (tenant, review_id)).fetchone()[0]
        body = body if isinstance(body, dict) else _json.loads(body)
        change(body)
        updated = conn.execute(f"UPDATE {settlement_module.TABLE} SET authorization_body=%s::jsonb"
                               " WHERE tenant=%s AND review_id=%s RETURNING review_id",
                               (_json.dumps(body), tenant, review_id)).fetchone()
        assert updated is not None


def _set_permit_field(name, value):
    def change(body):
        body["permit"]["permit"][name] = value
    return change


def _set_envelope_record_hash(body):
    body["envelope"]["record_hash"] = "0" * 64


@pytest.mark.parametrize("change", [
    pytest.param(_set_permit_field("budget_reservation", "other-reservation"), id="reservation"),
    pytest.param(_set_permit_field("nonce", "other-nonce"), id="permit-nonce"),
    pytest.param(_set_permit_field("principal", "other-principal"), id="permit-principal"),
    pytest.param(_set_envelope_record_hash, id="decision-record"),
])
def test_reentry_after_the_retained_authorization_is_altered_at_rest_is_refused(education, change):  # noqa: F811
    from regulated_core.permit import EmissionError
    app = education
    gate, context, request = _scene(app)
    first = gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    assert first.allowed, first.reason
    _tamper_retained(app, context.tenant, context.approval, change)
    with pytest.raises(EmissionError):
        gate.settle(**request, context=replace(context, now_us=app.clock.now_us()))
    # Nothing was granted from the altered row: no second reservation, no effect.
    assert _reservations(app, first.permit.permit.permit) == 1 and not app.path.exists()


def test_reentry_after_a_valid_signed_body_from_another_review_is_substituted_is_refused(education):  # noqa: F811
    # The stronger at-rest case: every signature in the substituted row is valid, because it is another review's
    # genuine retained authorization. Re-entry must still refuse, and grant nothing from it.
    import json as _json
    from regulated_core.permit import EmissionError
    app = education
    gate, context_a, request = _scene(app)
    first = gate.settle(**request, context=replace(context_a, now_us=app.clock.now_us()))
    assert first.allowed, first.reason
    from factory.projectos.governed_release import MISSION_FIELD
    # Review B: same tenant, artifact and target, its own nonce and mission (the mission budget allows one unit).
    app.context = replace(app.context, nonce="fictional-release-b", now_us=app.clock.now_us())
    app.contract = {**app.contract, MISSION_FIELD: f"synthetic:{context_a.tenant}:geometry-b"}
    context_b = reviewed_context(app)
    second = gate.settle(**dict(request, contract=app.contract), context=replace(context_b, now_us=app.clock.now_us()))
    assert second.allowed, second.reason
    assert second.permit.permit.permit.nonce != first.permit.permit.permit.nonce
    with app.roles.settlement_writer.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (context_a.tenant,))
        body_b = conn.execute(f"SELECT authorization_body FROM {settlement_module.TABLE}"
                              " WHERE tenant=%s AND review_id=%s", (context_a.tenant, context_b.approval)).fetchone()[0]
        body_b = body_b if isinstance(body_b, str) else _json.dumps(body_b)
        assert conn.execute(f"UPDATE {settlement_module.TABLE} SET authorization_body=%s::jsonb"
                            " WHERE tenant=%s AND review_id=%s RETURNING review_id",
                            (body_b, context_a.tenant, context_a.approval)).fetchone() is not None
    with pytest.raises((EmissionError, SettlementRefused)):
        gate.settle(**request, context=replace(context_a, now_us=app.clock.now_us()))
    assert _reservations(app, first.permit.permit.permit) == 1 and not app.path.exists()
