"""Intact verifier dependency contracts over genuinely committed fixture history.

The only database writes are the ordinary reviewed fixture workflow. Negative
observations are supplied in memory at dependency boundaries; no stored signed
authority is edited and no validation guard is removed. Synthetic record views
below are not signed evidence and cannot establish chain authenticity.
"""
from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from regulated_core.persistence_pg import PersistenceError
from regulated_core.target import Outcome, effect_of, effect_destination
from test_roster_budget_pg import roster_app, enact, next_target  # noqa: F401


def history(store, installation):
    with store._pool.connection() as conn:
        return conn.execute(
            "SELECT version, roster_digest, body, tenant, operation, nonce, change_digest"
            " FROM regulated_governance_rosters_v1 WHERE installation=%s ORDER BY version",
            (installation,),
        ).fetchall()


def test_intact_roster_verifier_dependency_refusals_and_recovery(request, monkeypatch):
    app, store, guard, first = request.getfixturevalue("roster_app")
    result, target, authorized, output = enact(app, next_target(app, store, guard, first), first)
    assert result.outcome is Outcome.COMMITTED, result.detail
    verifier = store._proof_verifier
    expected = replace(first, version=2)
    rows = history(store, first.installation)
    receipt = ("governance-office", target.operation, authorized.permit.permit.nonce,
               hashlib.sha256(output).hexdigest())

    def positive():
        assert verifier.verify_rows(rows, first.installation)[-1][0] == expected
        assert store.current(first.installation) == expected
        assert store.receipt(*receipt) is Outcome.COMMITTED

    def refused(message):
        # Same intact verifier on an in-memory observation and on ordinary PG reads.
        with pytest.raises(PersistenceError, match=message):
            verifier.verify_rows(rows, first.installation)
        with pytest.raises(PersistenceError, match=message):
            store.current(first.installation)
        with pytest.raises(PersistenceError, match=message):
            store.receipt(*receipt)

    positive()
    # A trust dependency explicitly declines verification of unchanged bytes.
    with monkeypatch.context() as observation:
        calls = []

        def declines(body, signature):
            calls.append(signature.key_id)
            return False

        observation.setattr(verifier.bootstrap_trust, "verify", declines)
        refused("bootstrap authority does not verify")
        assert calls == [app.keys["identity"].key_id] * 3
    positive()

    # A known but unpinned bootstrap key is a configuration refusal, not a
    # fabricated signature: the originally committed proof is left untouched.
    assert app.trust.is_known(app.keys["monitor"].key_id)
    with monkeypatch.context() as observation:
        observation.setattr(verifier, "bootstrap_key_ids",
                            frozenset({app.keys["monitor"].key_id}))
        refused("bootstrap authority does not verify")
    positive()

    # Ordinary incomplete evidence-service observation; no row or permit edit.
    with monkeypatch.context() as observation:
        observation.setattr(app.recorder, "entries", lambda tenant: [])
        refused("decision is absent or differs")
    positive()

    decisions = verifier._decisions()
    decision_id = authorized.permit.permit.decision_record_id
    original = decisions[decision_id]
    bound = effect_of(original.record.action.destination)
    assert bound is not None
    records = [
        ("assertion-digest", replace(original.record, assertion_digest="synthetic:unavailable")),
        ("prior-state", replace(original.record, action=replace(original.record.action,
            destination=effect_destination({}, replace(bound, target_state="synthetic:unavailable"))))),
        ("mission", replace(original.record, action=replace(original.record.action,
            destination=effect_destination({}, replace(bound, mission="synthetic:unavailable"))))),
    ]
    for label, record in records:
        # Mock only the already-validated-record accessor. These unsigned views
        # test the downstream binding contract; they are not proof artifacts.
        observed = {**decisions, decision_id: SimpleNamespace(
            record_hash=original.record_hash, record=record)}
        with monkeypatch.context() as observation:
            observation.setattr(verifier, "_decisions", lambda: observed)
            refused("signed decision does not bind governed effect")
        positive()

    assert history(store, first.installation) == rows
    assert app.recorder.verify_chain("governance-office")
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 1
