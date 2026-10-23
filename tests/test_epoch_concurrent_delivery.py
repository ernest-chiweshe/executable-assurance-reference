"""Concurrent ordinary signed withdrawals through intact target/store guards.

Two workers share the same configured local services and use separate database
connections. This is a thread-level delivery contract, not process-crash proof.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import time

import pytest

from test_epoch_supervisor_pg import app as supervisor_fixture
from regulated_core.target import Outcome

app = supervisor_fixture


def receive_together(app, attempts):
    ready = Barrier(len(attempts))

    def receive(item):
        pending, authorized = item
        ready.wait(timeout=15)
        return app.target.commit(authorized.permit, pending.output)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(attempts)) as workers:
        outcomes = list(workers.map(receive, attempts, timeout=15))
    assert time.monotonic() - started < 15, "ordinary delivery exceeded the local test bound"
    return outcomes


def event_counts(app):
    # Read-only observation under the existing governor role and tenant RLS.
    with app.roles.governor.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', %s, true)", (app.tenant,))
        epoch = connection.execute(
            "SELECT COUNT(*) FROM regulated_revocation_events_v1 WHERE tenant=%s",
            (app.tenant,)).fetchone()[0]
        receipt = connection.execute(
            "SELECT COUNT(*) FROM reference_epoch_withdrawal_receipts_v1 WHERE tenant=%s",
            (app.tenant,)).fetchone()[0]
        return epoch, receipt


def test_concurrent_exact_deliveries_settle_to_one_epoch_and_receipt(app):
    pending = app.begin()
    authorized = app.authorize(pending, app.approve(pending))
    outcomes = receive_together(app, [(pending, authorized)] * 2)
    assert any(result.outcome is Outcome.COMMITTED for result in outcomes), outcomes
    assert all(result.outcome in (Outcome.COMMITTED, Outcome.UNKNOWN) for result in outcomes), outcomes
    # Once both requests finish, retries and reconciliation must agree on the
    # original committed effect without incrementing again.
    assert app.target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.target.commit(authorized.permit, pending.output).outcome is Outcome.COMMITTED
    assert event_counts(app) == (1, 1)
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"] + 1
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 1
    assert app.recorder.verify_chain(app.tenant)


@pytest.mark.parametrize("workers", [2, 3])
def test_approved_requests_for_same_prior_epoch_have_one_effect(app, workers):
    attempts = []
    for _ in range(workers):
        pending = app.begin()
        attempts.append((pending, app.authorize(pending, app.approve(pending))))
    assert attempts[0][0].change["prior_epoch"] == attempts[1][0].change["prior_epoch"]
    outcomes = receive_together(app, attempts)
    assert sorted(result.outcome.value for result in outcomes) == sorted(
        [Outcome.COMMITTED.value] + [Outcome.FAILED.value] * (workers - 1)), outcomes
    assert event_counts(app) == (1, 1)
    assert app.ledger.epoch(app.tenant) == attempts[0][0].change["prior_epoch"] + 1
    for (pending, authorized), result in zip(attempts, outcomes):
        committed = result.outcome is Outcome.COMMITTED
        assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == int(committed)
        receipt = app.ledger.receipt(app.tenant, app.target.operation,
                                     authorized.permit.permit.nonce, pending.digest)
        assert receipt is (Outcome.COMMITTED if committed else Outcome.UNKNOWN)
    assert app.recorder.verify_chain(app.tenant)
