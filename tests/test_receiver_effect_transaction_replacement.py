import pytest
from regulated_core.permit import EmissionError
from regulated_core.budget import BudgetError
from regulated_core.target import Outcome
from test_receiver_commit_deadline_pg import _with_effect
from versioned_cas_pg_fixture import BODY, OLD, prepared_cas_fixture, snapshot

@pytest.mark.parametrize("error", [EmissionError, BudgetError])
@pytest.mark.parametrize("replacement", ["BEGIN", "BEGIN; SELECT 1/0", "BEGIN; SAVEPOINT regulated_effect_v1", "BEGIN; SAVEPOINT regulated_effect_v1; SELECT 1/0"])
def test_committed_effect_replaced_transaction_then_refusal_is_unknown(tmp_path, error, replacement):
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    def replace_and_refuse(conn):
        import psycopg
        conn.execute("COMMIT")
        try:
            conn.execute(replacement)
        except psycopg.Error:
            pass
        raise error("injected refusal after committing effect and replacing transaction")
    result = _with_effect(f, after=replace_and_refuse).commit(f["signed"], BODY)
    actual = snapshot(f)
    print("OBSERVED", result, actual)
    assert actual["state"] != (3, OLD), actual
    assert result.outcome is Outcome.UNKNOWN, (result, actual)
    assert "transaction" in result.detail and "reconcile" in result.detail, result
    assert "not_committed" not in actual["outcomes"], actual

@pytest.mark.parametrize("error", [EmissionError, BudgetError])
@pytest.mark.parametrize("abort_sql", [False, True])
def test_original_transaction_refusal_can_be_tombstoned(tmp_path, error, abort_sql):
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    def refuse(conn):
        import psycopg
        if abort_sql:
            try:
                conn.execute("SELECT 1/0")
            except psycopg.Error:
                pass
        raise error("injected refusal in original transaction")
    result = _with_effect(f, after=refuse).commit(f["signed"], BODY)
    actual = snapshot(f)
    assert result.outcome is Outcome.FAILED, (result, actual)
    assert actual == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}
