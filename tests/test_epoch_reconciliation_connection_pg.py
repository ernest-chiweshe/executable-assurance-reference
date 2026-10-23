"""Ordinary signed reconciliation and a synthetic claim/preparation boundary."""
import time

from regulated_core.target import Outcome
from test_epoch_supervisor_pg import app as supervisor_fixture

app = supervisor_fixture


def test_signed_reconcile_before_and_after_ordinary_commit_preserves_outcomes(app):
    pending = app.begin()
    authorized = app.authorize(pending, app.approve(pending))
    assert app.log._pool is not app.uses._pool
    started = time.monotonic()
    assert app.target.reconcile(authorized.permit).outcome is Outcome.NOT_COMMITTED
    assert time.monotonic() - started < 15
    assert not app.uses.used(app.tenant, authorized.permit.permit.nonce)
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    # Exercise committed reconciliation with a separate ordinary request.
    # The no-attempt observation above does not spend a nonce or create an effect.
    pending = app.begin()
    authorized = app.authorize(pending, app.approve(pending))
    result = app.engine.commit(authorized, pending.output, app.target)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 1
    assert app.recorder.verify_chain(app.tenant)


def test_signed_claim_without_preparation_remains_unknown_on_reconcile(app):
    pending = app.begin()
    authorized = app.authorize(pending, app.approve(pending))
    nonce = authorized.permit.permit.nonce
    # Observe the ordinary durable claim/preparation boundary with a valid permit.
    # No guard is replaced; no epoch write or fabricated noncommit proof follows.
    app.uses.consume(app.tenant, nonce)
    assert app.log.attempt(app.tenant, nonce) == (None, None)
    started = time.monotonic()
    result = app.target.reconcile(authorized.permit)
    assert time.monotonic() - started < 15
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert app.uses.used(app.tenant, nonce)
    assert app.log.attempt(app.tenant, nonce) == (None, None)
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 0
    assert app.recorder.verify_chain(app.tenant)
