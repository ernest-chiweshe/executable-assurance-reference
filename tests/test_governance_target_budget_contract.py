"""Intact synthetic receiving contracts with real signatures and budget checks.

The synthetic host writes reversible fixture state, not policy/roster authority.
These observations do not qualify PostgreSQL atomicity or tier-4 composition.
"""
from dataclasses import replace
from hashlib import sha256

import pytest

from regulated_core.governance_targets import GovernanceTarget, GovernanceLog, change_bytes
from regulated_core.governance_transaction import PostgresGovernanceBudget, run_governance_check
from regulated_core.persistence_pg import PostgresMissionBudget
from regulated_core.permit import EmissionError
from regulated_core.target import BoundEffect, Outcome, effect_destination
from test_governance_budget_binding import ScopedTransaction
from test_reference_host_budget_contract import composition


def fixture(tmp_path, *, failure=None):
    engine, request, signer, reserved, events, uses = composition(tmp_path, {"limit": 1, "units": 1}, engine_type="core")
    tenant = request["ctx"].tenant_id
    conn = ScopedTransaction("host-original-scope")
    state = {"value": "absent", "receipt": Outcome.UNKNOWN, "final_calls": 0}
    released = []

    class Budget(PostgresMissionBudget):
        def release(self, tenant_id, mission, reservation_id):
            reserved.release(tenant_id, mission, reservation_id)
            released.append((tenant_id, mission, reservation_id))
    binding = PostgresGovernanceBudget(Budget(pool=None))

    def receiving(signed):
        state["final_calls"] += 1
        if failure == "final" and state["final_calls"] == 2:
            raise EmissionError("ordinary approval no longer current")

    def transact(change):
        state["authority_proof"] = change.authority_proof
        if failure == "unknown-before":
            raise TimeoutError("ordinary acknowledgement unavailable")
        prior = list(conn.inserts)
        try:
            run_governance_check(change.final_check, conn)
            assert conn.tenant == "host-original-scope"
            state["value"] = "version-one"
            state["receipt"] = Outcome.COMMITTED
        except BaseException:
            conn.inserts[:] = prior
            raise
        if failure == "unknown-after":
            raise TimeoutError("ordinary acknowledgement lost after commit")

    options = dict(tenant_id=tenant, kind="fixture-state", subject="draft",
        authority=engine.targets, uses=uses, state=lambda: state["value"], apply=lambda change: None,
        log=GovernanceLog(), operation_name=request["action"].action_id, expect=lambda change, prior: "version-one",
        transact=transact, receipt=lambda *args: state["receipt"], receiving_check=receiving,
        budget_binding=binding, budget_transaction=True)
    target = GovernanceTarget(**options)
    output = change_bytes("fixture-state", "draft", {"version": 1})
    digest = sha256(output).hexdigest()
    request.update(target=target, output=output,
        assertion=replace(request["assertion"], content_digest=digest),
        action=replace(request["action"], destination=effect_destination({},
            BoundEffect(digest, target.target, target.current_state(), mission="synthetic:mission"))))
    authorized = engine.authorize_for_target(**request, nonce="governed-fixture")
    assert authorized.authorized
    return target, authorized.permit, output, conn, state, released, options


def test_consumption_and_final_check_precede_effect_and_replay_does_not_reconsume(tmp_path):
    target, signed, output, conn, state, released, _ = fixture(tmp_path)
    first = target.commit(signed, output)
    assert first.outcome is Outcome.COMMITTED
    assert state["authority_proof"] is signed
    assert state["value"] == "version-one" and state["final_calls"] == 2
    assert conn.inserts == [(signed.permit.tenant_id, signed.permit.mission, signed.permit.budget_reservation, 1, 1)]
    assert not released
    replay = target.commit(signed, output)
    assert replay.outcome is Outcome.COMMITTED and len(conn.inserts) == 1
    assert state["final_calls"] == 2 and not released


def test_final_refusal_rolls_back_synthetic_participant_and_releases_definite_failure(tmp_path):
    target, signed, output, conn, state, released, _ = fixture(tmp_path, failure="final")
    result = target.commit(signed, output)
    assert result.outcome is Outcome.FAILED
    assert not conn.inserts and state["value"] == "absent"
    assert released == [(signed.permit.tenant_id, signed.permit.mission, signed.permit.budget_reservation)]
    assert target.commit(signed, output).outcome is Outcome.FAILED
    assert not conn.inserts


@pytest.mark.parametrize("failure", ["unknown-before", "unknown-after"])
def test_unknown_retains_until_exact_receipt_proves_outcome(tmp_path, failure):
    target, signed, output, conn, state, released, _ = fixture(tmp_path, failure=failure)
    result = target.commit(signed, output)
    assert result.outcome is Outcome.UNKNOWN and not released
    assert target.commit(signed, output).outcome is Outcome.UNKNOWN and not released
    if failure == "unknown-before":
        assert target.reconcile(signed).outcome is Outcome.UNKNOWN and not released
        state["receipt"] = Outcome.NOT_COMMITTED
        assert target.reconcile(signed).outcome is Outcome.NOT_COMMITTED
        assert len(released) == 1 and not conn.inserts
    else:
        assert target.reconcile(signed).outcome is Outcome.COMMITTED
        assert len(conn.inserts) == 1 and not released
        assert target.commit(signed, output).outcome is Outcome.COMMITTED
        assert len(conn.inserts) == 1


def test_unattempted_and_wrong_bytes_do_not_release_reservation(tmp_path):
    target, signed, output, conn, state, released, _ = fixture(tmp_path)
    assert target.reconcile(signed).outcome is Outcome.NOT_COMMITTED
    assert not released
    assert target.commit(signed, b"unrelated ordinary draft").outcome is Outcome.FAILED
    assert not released and not conn.inserts
    assert target.commit(signed, output).outcome is Outcome.COMMITTED


@pytest.mark.parametrize("missing", ["transact", "receipt", "declaration"])
def test_budget_host_requires_explicit_transaction_and_receipt(tmp_path, missing):
    _, _, _, _, _, _, options = fixture(tmp_path)
    if missing == "declaration":
        options["budget_transaction"] = False
    else:
        options[missing] = None
    with pytest.raises(ValueError, match="explicit owned transaction and exact receipt"):
        GovernanceTarget(**options)
