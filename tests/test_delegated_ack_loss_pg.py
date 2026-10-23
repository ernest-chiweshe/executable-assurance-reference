"""A15 delegated wrapper: injected post-commit ACK loss, with/without alert outage.

The named fault occurs after the real PostgreSQL transaction returns from
_commit_on. It is a synthetic acknowledgement error, not a killed transport.
Reconciliation uses a freshly constructed receiver and must not apply again.
"""
import json
import pytest
import psycopg
from regulated_core.target import Outcome
from test_delegated_draft import delegated_draft_fixture, TENANTS, BODY


@pytest.mark.parametrize("alert_unavailable", [False, True])
def test_delegated_committed_ack_loss_reconciles_without_another_effect(tmp_path, monkeypatch, alert_unavailable):
    fixture, assemble, authorize = delegated_draft_fixture(tmp_path)
    tenant = TENANTS[0]
    authorized, _ = authorize(tenant, "alpha")
    assert authorized.status == "authorized", authorized
    pool, _, _, _, _, receiver, budget, alerts = assemble(tenant)
    signed = authorized.permit
    applied = []
    effect_type = type(receiver._effect)
    original_apply = effect_type.apply_on

    def counted_apply(self, conn, output):
        state = original_apply(self, conn, output)
        applied.append(state)
        return state

    monkeypatch.setattr(effect_type, "apply_on", counted_apply)
    actual_commit = receiver._commit_on
    def commit_then_lose_ack(conn, permit, output):
        actual_commit(conn, permit, output)
        raise psycopg.OperationalError("delegated-committed-before-caller-ack")
    monkeypatch.setattr(receiver, "_commit_on", commit_then_lose_ack)
    if alert_unavailable:
        def unavailable(**kwargs):
            raise OSError("injected alert store outage")
        monkeypatch.setattr(alerts, "append", unavailable)
        with pytest.raises(OSError, match="injected alert store outage"):
            receiver.commit(signed, BODY)
    else:
        lost = receiver.commit(signed, BODY)
        assert lost.outcome is Outcome.UNKNOWN, lost
    with pool.connection() as conn:
        stored = [json.loads(bytes(row[0])) for row in conn.execute(
            "SELECT envelope FROM reference_alerts_v1").fetchall()]
        receipts = conn.execute("SELECT outcome FROM regulated_database_receipts_v1 WHERE tenant=%s AND nonce=%s",
                                (tenant, signed.permit.nonce)).fetchall()
    assert receipts == [("committed",)], receipts
    matching = [a['payload'] for a in stored if a['payload'].get('code') == 'TARGET_UNKNOWN'
                and a['payload'].get('decision_hash') == signed.permit.decision_record_hash]
    if alert_unavailable:
        assert matching == [], matching
    else:
        assert len(matching) == 1 and matching[0]['tenant_id'] == tenant
    assert len(applied) == 1
    fresh = assemble(tenant)[5]
    resolved = fresh.status(signed)
    assert resolved.outcome is Outcome.COMMITTED, resolved
    assert fresh.commit(signed, BODY).outcome is Outcome.COMMITTED
    assert len(applied) == 1
    assert budget.committed(tenant, "one-draft") == 1
    with pool.connection() as conn:
        assert conn.execute("SELECT body FROM reference_prepared_drafts_v1 WHERE tenant=%s", (tenant,)).fetchall() == [(BODY,)]
        assert conn.execute("SELECT count(*) FROM regulated_permit_uses_v1 WHERE tenant=%s AND nonce=%s",
                            (tenant, signed.permit.nonce)).fetchone()[0] == 1
    (tmp_path/'delegated-ack-evidence.json').write_text(json.dumps({
        'fault':'synthetic error after real transaction commit', 'alert_unavailable':alert_unavailable,
        'effect_calls':len(applied), 'reconciled':resolved.outcome.value,
        'limits':['local fixture identities and signing keys','no RLS claim','no real transport failure']},indent=2)+'\n')
