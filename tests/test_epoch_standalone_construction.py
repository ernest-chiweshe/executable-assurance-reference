"""Execute each standalone app's actual ledger construction expression.

Only the constructor expression is selected; no application authority or effect
guard is replaced. This does not execute schema setup or qualify PostgreSQL.
"""
import ast
import inspect

import pytest

from assurance_reference import demo, health
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger
from regulated_core.persistence_pg import PostgresRevocationLedger
from test_epoch_withdrawal_target import composition


@pytest.mark.parametrize("application", [demo, health], ids=["demo", "health"])
def test_standalone_actual_ledger_constructor_uses_shared_clock_without_io(application):
    tree = ast.parse(inspect.getsource(application.run))
    expressions = [keyword.value for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "ReferenceEngine"
        for keyword in node.keywords if keyword.arg == "revocation"]
    assert len(expressions) == 1
    app = composition()
    expression = ast.Expression(body=expressions[0])
    ledger = eval(compile(ast.fix_missing_locations(expression), application.__file__, "eval"),
                  vars(application), {"pool": app.pool, "clock": app.store.clock})
    assert isinstance(ledger, GuardedPostgresRevocationLedger)
    assert ledger.clock is app.store.clock and ledger._pool is app.pool
    assert type(ledger).epoch is PostgresRevocationLedger.epoch
    assert ledger._writers == {}
