"""Intact PostgreSQL contracts; execute only on the explicitly owned local cluster.

Prepared permits come from actual retained decisions, two independent fixture
reviewers, the existing preparation writer and original issuer. No guard is
removed. Synthetic identities/single local login do not qualify credential
custody or RLS separation. Collection alone is not runtime evidence.
"""
import pytest

from assurance_reference.versioned_cas import VersionedRowEffect
from regulated_core.database_receiver_pg import PostgresTargetReceiver
from regulated_core.permit import EmissionError
from regulated_core.target import Outcome
from versioned_cas_pg_fixture import BODY, OLD, OPERATION, prepared_cas_fixture, snapshot


def test_reviewed_cas_commits_exact_state_and_replay_has_no_second_effect(tmp_path):
    f = prepared_cas_fixture(tmp_path)
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": [], "budget": 0}
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.COMMITTED, result
    expected = {"state": (4, BODY), "uses": 1, "outcomes": ["committed"], "budget": 1}
    assert snapshot(f) == expected and f["observations"]
    assert f["receiver"].observe(f["signed"]).outcome is Outcome.COMMITTED
    assert f["receiver"].commit(f["signed"], BODY).outcome is Outcome.COMMITTED
    assert snapshot(f) == expected


def test_uncomposed_cas_refuses_and_rolls_back_claim_and_budget(tmp_path):
    f = prepared_cas_fixture(tmp_path)
    bare = PostgresTargetReceiver(
        pool=f["pool"], authority=f["authority"],
        effect=VersionedRowEffect(f["tenant"], f["target"], OPERATION, 3))
    result = bare.commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "requires composed admission" in result.detail
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}


def test_stale_cas_revision_refuses_without_settlement(tmp_path):
    # An ordinary stale host CAS revision, with a current permit and actual review.
    f = prepared_cas_fixture(tmp_path, expected_revision=2)
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "revision changed or row absent" in result.detail and f["observations"]
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}


def test_receiver_refuses_other_output_before_host_admission(tmp_path):
    f = prepared_cas_fixture(tmp_path)
    result = f["receiver"].commit(f["signed"], b"different synthetic bytes")
    assert result.outcome is Outcome.FAILED, result
    assert "effect bytes differ" in result.detail
    assert not f["observations"]
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": [], "budget": 0}


def test_current_reviewer_membership_refusal_preserves_state(tmp_path):
    f = prepared_cas_fixture(tmp_path)
    # Ordinary synthetic host membership transition, after valid grant and issuance.
    with f["pool"].connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_root_members SET enabled=false "
                     "WHERE tenant=%s AND subject='supervisor'", (f["tenant"],))
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "current CAS reviewer membership refused" in result.detail
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}


@pytest.mark.parametrize("case", ["reuse", "other-output", "next-transaction", "other-connection"])
def test_pg_transaction_proof_refusal_without_delivering_any_effect(tmp_path, case):
    f = prepared_cas_fixture(tmp_path)
    admission = f["receiver"]._admission
    # Proof-only observations use SELECT/locks. They do not call the effect or
    # bypass the receiver to perform a write. No permit or mission unit is spent.
    with f["pool"].connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
            admission.lock_current_on(conn, f["signed"], f["target"])
            if case == "reuse":
                admission.require_effect_on(conn, BODY)
                with pytest.raises(EmissionError, match="one-use database admission proof required"):
                    admission.require_effect_on(conn, BODY)
            elif case == "other-output":
                with pytest.raises(EmissionError, match="exact effect bytes"):
                    admission.require_effect_on(conn, b"different synthetic bytes")
            elif case == "other-connection":
                with f["pool"].connection() as other, other.transaction():
                    other.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
                    with pytest.raises(EmissionError, match="one-use database admission proof required"):
                        admission.require_effect_on(other, BODY)
                admission.require_effect_on(conn, BODY)
        if case == "next-transaction":
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
                with pytest.raises(EmissionError, match="another transaction"):
                    admission.require_effect_on(conn, BODY)
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": [], "budget": 0}

def test_elapsed_database_time_refuses_before_cas_and_rolls_back_settlement(tmp_path):
    f = prepared_cas_fixture(tmp_path, admission_window_us=5_000_000)
    original = f["receiver"]._effect

    class DelayedEffect:
        # Ordinary synthetic dependency latency. Every original admission/CAS
        # guard is retained, and the full receiver owns claim and rollback.
        tenant_id = original.tenant_id
        target = original.target
        operation = original.operation

        def current_state_on(self, conn):
            return original.current_state_on(conn)

        def apply_on(self, conn, output):
            conn.execute("SELECT pg_sleep(%s)", (5.1,))
            return original.apply_on(conn, output)

    receiver = PostgresTargetReceiver(
        pool=f["pool"], authority=f["authority"], effect=DelayedEffect(),
        admission=f["receiver"]._admission,
    )
    result = receiver.commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "database admission expired before effect" in result.detail
    assert f["observations"]
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}
