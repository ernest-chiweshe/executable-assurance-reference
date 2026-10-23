"""A15 on a PostgreSQL governance target: the effect commits, then its acknowledgement is lost.

The roster store's own transaction commits (effect, receipt and budget consumption together); only the return to
the caller fails, at the named point "committed-before-caller-ack". The target reports UNKNOWN, reconciliation by
the exact receipt resolves COMMITTED, and a repeated delivery returns the stored result with no second effect and no
second consumption. Guards are unchanged; synthetic governance office; isolated PostgreSQL.
"""
import hashlib
from dataclasses import replace

from regulated_core.target import Outcome
from test_roster_budget_pg import enact, next_target, reservation_events, roster_app  # noqa: F401


class LostAcknowledgement(ConnectionError):
    """The caller's connection fails after the store transaction has committed."""


def test_committed_governance_effect_with_lost_ack_is_unknown_then_committed_by_receipt(roster_app, monkeypatch):  # noqa: F811
    app, store, guard, first = roster_app
    actual_apply, applied = store.apply, []

    def apply(change):
        result = actual_apply(change)  # The store transaction commits here.
        applied.append(change)
        raise LostAcknowledgement("committed-before-caller-ack")

    monkeypatch.setattr(store, "apply", apply)
    result, target, authorized, output = enact(app, next_target(app, store, guard, first), first)
    monkeypatch.setattr(store, "apply", actual_apply)
    assert len(applied) == 1
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert store.current(first.installation) == replace(first, version=2)
    digest = hashlib.sha256(output).hexdigest()
    assert store.receipt("governance-office", target.operation, authorized.permit.permit.nonce, digest) \
        is Outcome.COMMITTED
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    mission = authorized.permit.permit.mission
    assert app.budget.committed("governance-office", mission) == 1
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
    assert app.budget.committed("governance-office", mission) == 1
    assert reservation_events(app, authorized.permit) == [("consume", 1), ("reserve", 1)]
    assert store.current(first.installation) == replace(first, version=2)
