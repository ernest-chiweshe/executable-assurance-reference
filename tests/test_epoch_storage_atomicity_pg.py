"""Synthetic receipt-storage failure on a fresh isolated schema.

An additional local CHECK constraint refuses receipt inserts. It never removes
or weakens an authority check. The real PostgreSQL error must roll back the
already-attempted epoch append and budget consume in their owned transaction.
"""
import os

import psycopg
from psycopg import sql

from test_epoch_supervisor_pg import app as supervisor_fixture
from regulated_core.target import Outcome

app = supervisor_fixture


def test_receipt_storage_failure_rolls_back_epoch_and_budget_and_stays_unknown(app):
    pending = app.begin()
    authorized = app.authorize(pending, app.approve(pending))
    assert app.roles.schema.startswith("test_reference_roles_")
    # Only the fresh provisioned fixture schema is changed, through its local
    # migration owner. Runtime role grants and existing constraints stay intact.
    with psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], connect_timeout=5) as connection:
        assert connection.execute(
            "SELECT current_database(),host(inet_server_addr())"
        ).fetchone() == ("factory_test", "127.0.0.1")
        connection.execute(sql.SQL(
            "ALTER TABLE {}.reference_epoch_withdrawal_receipts_v1 "
            "ADD CONSTRAINT fixture_receipt_storage_unavailable CHECK (false) NOT VALID"
        ).format(sql.Identifier(app.roles.schema)))

    result = app.engine.commit(authorized, pending.output, app.target)
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert "CheckViolation" in result.detail
    assert getattr(app.ledger._epoch_reader, "active", None) is None
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 0
    with app.roles.governor.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', %s, true)", (app.tenant,))
        assert connection.execute(
            "SELECT COUNT(*) FROM regulated_revocation_events_v1 WHERE tenant=%s",
            (app.tenant,)).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM reference_epoch_withdrawal_receipts_v1 WHERE tenant=%s",
            (app.tenant,)).fetchone()[0] == 0

    # Nonce claim and prepared governance log intentionally precede the owned
    # effect transaction. Absence of a receipt is not fabricated noncommit proof.
    assert app.uses.used(app.tenant, authorized.permit.permit.nonce)
    prepared, resolved = app.log.attempt(app.tenant, authorized.permit.permit.nonce)
    assert prepared is not None and resolved is None
    assert app.ledger.receipt(app.tenant, app.target.operation,
        authorized.permit.permit.nonce, pending.digest) is Outcome.UNKNOWN
    assert app.target.reconcile(authorized.permit).outcome is Outcome.UNKNOWN
    assert app.target.commit(authorized.permit, pending.output).outcome is Outcome.UNKNOWN
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert app.recorder.verify_chain(app.tenant)
