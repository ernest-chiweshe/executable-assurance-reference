"""Original short-lived signed permits and historical receipts on the real clock.

No clock is advanced or replaced; the isolated fixture waits for normal expiry.
This qualifies the local database clock domain, not physical UTC accuracy.
"""
import time

from test_epoch_supervisor_pg import app as supervisor_fixture
from regulated_core.target import Outcome

app = supervisor_fixture


def wait_for_expiry(app, signed):
    deadline = time.monotonic() + 12
    while app.clock.now_us() < signed.permit.expires_at_us:
        assert time.monotonic() < deadline, "local fixture clock did not reach permit expiry"
        time.sleep(0.1)


def short_lived_authorization(app):
    pending = app.begin()
    # Ordinary public authorization request; the issuer signs the requested TTL.
    pending.params["permit_ttl_us"] = 5_000_000
    authorized = app.authorize(pending, app.approve(pending))
    assert authorized.permit.permit.expires_at_us - app.clock.now_us() > 1_000_000
    return pending, authorized


def test_uncommitted_withdrawal_expires_without_epoch_receipt_or_nonce_claim(app):
    pending, authorized = short_lived_authorization(app)
    wait_for_expiry(app, authorized.permit)
    result = app.target.commit(authorized.permit, pending.output)
    assert result.outcome is Outcome.FAILED
    assert authorized.permit.permit.clock_domain == app.clock.domain
    assert app.clock.now_us() >= authorized.permit.permit.expires_at_us
    assert "absolute window refused" in result.detail
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert not app.uses.used(app.tenant, authorized.permit.permit.nonce)
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 0
    assert app.ledger.receipt(app.tenant, app.target.operation,
        authorized.permit.permit.nonce, pending.digest) is Outcome.UNKNOWN
    assert app.recorder.verify_chain(app.tenant)


def test_original_committed_receipt_and_retry_survive_normal_permit_expiry(app):
    pending, authorized = short_lived_authorization(app)
    result = app.engine.commit(authorized, pending.output, app.target)
    assert result.outcome is Outcome.COMMITTED, result.detail
    wait_for_expiry(app, authorized.permit)
    assert app.ledger.receipt(app.tenant, app.target.operation,
        authorized.permit.permit.nonce, pending.digest) is Outcome.COMMITTED
    assert app.target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.target.commit(authorized.permit, pending.output).outcome is Outcome.COMMITTED
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"] + 1
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 1
    assert app.recorder.verify_chain(app.tenant)
