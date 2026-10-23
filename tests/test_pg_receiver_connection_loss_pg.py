"""A15 PostgreSQL receiver: a connection error raised inside the effect transaction is UNKNOWN, resolved by receipt.

The real effect runs, then a synthetic psycopg.OperationalError is raised before COMMIT (named point
"effect-applied-connection-error-injected"). This is an injected error, not a severed or terminated transport. The
transaction does not commit, so the claim, effect, budget and receipt all roll back together; the receiver answers
UNKNOWN, never COMMITTED or FAILED, and the exact-permit status lookup resolves NOT_COMMITTED with nothing applied.
Guards unchanged; actual retained decisions; isolated PostgreSQL.
"""
import psycopg

from regulated_core.target import Outcome
from versioned_cas_pg_fixture import BODY, OLD, prepared_cas_fixture, snapshot


def test_injected_connection_error_inside_the_effect_transaction_is_unknown_then_not_committed(tmp_path, monkeypatch):
    f = prepared_cas_fixture(tmp_path)
    kind = type(f["receiver"]._effect)
    actual = kind.apply_on
    applied = []

    def apply_then_lose_connection(self, conn, output):
        applied.append(actual(self, conn, output))
        raise psycopg.OperationalError("effect-applied-connection-error-injected")

    monkeypatch.setattr(kind, "apply_on", apply_then_lose_connection)
    lost = f["receiver"].commit(f["signed"], BODY)
    monkeypatch.undo()
    assert applied and lost.outcome is Outcome.UNKNOWN, lost
    assert "reconcile" in lost.detail
    assert snapshot(f)["state"] == (3, OLD) and snapshot(f)["uses"] == 0 and snapshot(f)["budget"] == 0
    resolved = f["receiver"].status(f["signed"])
    assert resolved.outcome is Outcome.NOT_COMMITTED, resolved
    assert snapshot(f)["state"] == (3, OLD)
