"""Observe real budget rows at signing without changing any authority check."""
from threading import Lock

from regulated_core.signing import Ed25519Signer


class BudgetSigningObserver:
    def __init__(self, allocator_pool):
        self.pool = allocator_pool
        self.signed = []
        self._lock = Lock()

    def observe(self, body):
        if not isinstance(body, dict) or "budget_reservation" not in body:
            return
        tenant, mission, reservation = body["tenant_id"], body["mission"], body["budget_reservation"]
        assert mission and reservation not in ("", "unbudgeted")
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
            rows = conn.execute(
                "SELECT kind, units, limit_units FROM regulated_mission_budget_events_v1 "
                "WHERE tenant=%s AND mission=%s AND reservation_id=%s",
                (tenant, mission, reservation)).fetchall()
        assert rows == [("reserve", body["budget_units"], 1)], rows
        with self._lock:
            self.signed.append((tenant, mission, reservation))

    def __call__(self, key_id):
        observer = self

        class ObservedSigner(Ed25519Signer):
            def sign(self, body):
                if key_id.endswith(":emission"):
                    observer.observe(body)
                return super().sign(body)

        return ObservedSigner(key_id)


def assert_recorded_budget_refusal(app, decision, code, *, tenant):
    """Check the gate's public refusal shape against its exact signed record."""
    assert not decision.allowed and decision.permit is None
    assert decision.evidence["decision"]["reason_codes"] == [code]
    record_hash = decision.evidence["evidence_head_hash"]
    matches = [entry for entry in app.stores.recorder.entries(tenant)
               if entry.record_hash == record_hash]
    assert len(matches) == 1
    assert matches[0].record.decision.reason_codes == (code,)
    assert app.stores.recorder.verify_entry(matches[0])
    assert app.stores.recorder.verify_chain(tenant)
