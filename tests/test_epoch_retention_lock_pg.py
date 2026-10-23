"""Observe the intact shared roster lock through ordinary review insertion."""
from contextlib import contextmanager

from assurance_reference.epoch_withdrawal_retention import retain_approved_withdrawal
from assurance_reference.local_roles import LocalPool
from test_epoch_supervisor_pg import app as supervisor_fixture

app = supervisor_fixture


def test_retention_keeps_roster_lock_until_review_transaction_finishes(app, monkeypatch):
    pending = app.begin()
    approved = app.approve(pending)
    connection = LocalPool.connection
    observations = []
    key = "regulated-governance-roster:" + app.installation

    class ObservedReceiver:
        def __init__(self, real):
            self.real = real

        def __getattr__(self, name):
            return getattr(self.real, name)

        def execute(self, query, params=None):
            result = self.real.execute(query, params)
            if isinstance(query, str) and query.startswith("INSERT INTO regulated_reviews_v1"):
                # Nonblocking observation on a separate restricted governor session.
                # No roster write or lock removal occurs.
                with connection(app.roles.governor) as probe, probe.transaction():
                    available = probe.execute(
                        "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                        (key,)).fetchone()[0]
                observations.append(available)
            return result

    @contextmanager
    def observed(pool):
        with connection(pool) as real:
            yield ObservedReceiver(real) if pool is app.roles.receiver else real

    with monkeypatch.context() as patch:
        patch.setattr(LocalPool, "connection", observed)
        retained = retain_approved_withdrawal(
            app.loader, tenant_id=app.tenant, change=pending.change,
            requester_id=app.requester, approved=approved)
    assert retained == pending.review_id
    assert observations == [False]
    with app.roles.governor.connection() as probe, probe.transaction():
        assert probe.execute(
            "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
            (key,)).fetchone()[0]
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert app.recorder.verify_chain(app.tenant)
