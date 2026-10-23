"""Real signed tier-4 transitions through unchanged governance checks.

All actors and approvals are synthetic. Faults add an error after the actual
receiving callback; no guard, role, RLS policy or authority check is disabled.
"""
import hashlib
import os
from contextlib import contextmanager

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
from assurance_reference.packs import verify_bundles
from partitioned_governance_fixture import GovernedFixture
from regulated_core.target import Outcome
from regulated_core.governance_transaction import GovernanceTransactionCheck


def after_receiving(check, after):
    """Add an ordinary host observation/failure after every intact final check."""
    def final():
        if isinstance(check, GovernanceTransactionCheck):
            check.final_check()
        else:
            check()
        after()
    if isinstance(check, GovernanceTransactionCheck):
        return GovernanceTransactionCheck(check.consume_on, final)
    return final


@pytest.fixture
def governed():
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = GovernedFixture(roles)
    app.first, app.second = (item["reference"] for item in verify_bundles()["bundles"])
    app.pack_id = app.first.partition("#")[0]
    for reference in (app.first, app.second):
        result, _, _, _ = app.enact("governance-office", {"activate": reference, "at": "synthetic fixture"})
        assert result.outcome is Outcome.COMMITTED, result.detail
    return app


def private_rows(app, tenant):
    with app.roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.pack_tenant',%s,true)", (tenant,))
        rows = conn.execute("SELECT pack_id,tenant_id,revision,payload,state_digest "
                            "FROM reference_pack_tenants_v1 ORDER BY pack_id,tenant_id").fetchall()
        assert all(row[1] == tenant for row in rows)
        return rows


def reservation_events(app, signed):
    """Read the exact signed reservation through the allocator's tenant scope."""
    permit = signed.permit
    with app.roles.allocator.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (permit.tenant_id,))
        return conn.execute(
            "SELECT kind, units FROM regulated_mission_budget_events_v1 "
            "WHERE tenant=%s AND mission=%s AND reservation_id=%s ORDER BY kind",
            (permit.tenant_id, permit.mission, permit.budget_reservation),
        ).fetchall()


def lifecycle_state(app):
    with app.roles.governor.connection() as conn:
        common = [conn.execute(query).fetchall() for query in (
            "SELECT * FROM reference_pack_shared_v1 ORDER BY pack_id",
            "SELECT * FROM reference_pack_installation_retries_v1 ORDER BY pack_id",
            "SELECT * FROM reference_pack_retry_index_v1 ORDER BY pack_id,key_digest")]
    return common + [private_rows(app, tenant) for tenant in
                     ("governance-office", "other-office", "school-a", "school-b")]


def test_signed_cross_tenant_pin_preserves_attribution_and_receipt_replay(governed):
    app = governed
    result, target, authorized, output = app.enact(
        "governance-office", {"pin": app.first, "tenant": "school-a"})
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.packs.active(app.pack_id).reference == app.second
    assert app.packs.activation_for("school-a", app.pack_id).reference == app.first
    assert app.packs.activation_for("school-b", app.pack_id).reference == app.second
    key = ("governance-office", target.operation, authorized.permit.permit.nonce,
           hashlib.sha256(output).hexdigest())
    assert app.packs.governance_receipt(*key) is Outcome.COMMITTED
    school, office = private_rows(app, "school-a"), private_rows(app, "governance-office")
    assert school[0][3]["pin"] == app.first.partition("#")[2]
    assert school[0][3]["governance_receipts"] == []
    assert office[0][3]["pin"] is None
    assert list(key) in office[0][3]["governance_receipts"]
    assert private_rows(app, "school-b") == []
    mission = authorized.permit.permit.mission
    assert app.budget.committed("governance-office", mission) == 3
    before = lifecycle_state(app)
    # Existing receiving receipt protocol: the same signed permit is replayed.
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert lifecycle_state(app) == before
    assert app.budget.committed("governance-office", mission) == 3
    reopened = PartitionedActivationLedger("", pool=app.roles.receiver, guard=app.packs.governance_guard)
    assert reopened.resolve_record("school-a", app.pack_id).reference == app.first
    assert reopened.governance_receipt(app.pack_id, key)


def test_guarded_retry_is_exact_and_pack_wide_collision_refuses(governed, monkeypatch):
    app = governed
    actual_pin = app.packs.ledger.pin
    callbacks = []

    def retrying_pin(*args, **kwargs):
        actual_callback = kwargs["before_commit"]

        receiving_check = after_receiving(actual_callback, lambda: callbacks.append("checked"))
        kwargs.update(idempotency_key="fixture-pack-wide-retry", before_commit=receiving_check)
        result = actual_pin(*args, **kwargs)
        assert actual_pin(*args, **kwargs) == result
        return result

    # Calls the unmodified guarded public operation twice; never enters a guard
    # context directly or replaces an authority check.
    monkeypatch.setattr(app.packs.ledger, "pin", retrying_pin)
    result, _, _, _ = app.enact("governance-office", {"pin": app.first, "tenant": "school-a"})
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert callbacks == ["checked"]
    before = lifecycle_state(app)
    result, target, authorized, output = app.enact(
        "other-office", {"pin": app.first, "tenant": "school-b"})
    # Preserve the original target's uncertainty classification for LifecycleError.
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert callbacks == ["checked"] and lifecycle_state(app) == before
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 3
    assert app.packs.activation_for("school-b", app.pack_id).reference == app.second
    assert app.packs.governance_receipt("other-office", target.operation,
        authorized.permit.permit.nonce, hashlib.sha256(output).hexdigest()) is Outcome.UNKNOWN


def test_failure_after_actual_receiving_check_rolls_back_every_lifecycle_write(governed, monkeypatch):
    app = governed
    actual_pin = app.packs.ledger.pin
    callbacks = []

    def failing_pin(*args, **kwargs):
        actual_callback = kwargs["before_commit"]

        def fail_after_check():
            callbacks.append("checked")
            raise ValueError("synthetic refusal after original receiving check")

        kwargs.update(idempotency_key="fixture-refused-retry",
                      before_commit=after_receiving(actual_callback, fail_after_check))
        return actual_pin(*args, **kwargs)

    monkeypatch.setattr(app.packs.ledger, "pin", failing_pin)
    before = lifecycle_state(app)
    result, target, authorized, output = app.enact(
        "governance-office", {"pin": app.first, "tenant": "school-a"})
    # An application error is conservatively UNKNOWN even when this fixture
    # independently proves transaction rollback. Only the original final-check
    # refusal protocol may classify its own pre-write denial as FAILED.
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert target.reconcile(authorized.permit).outcome is Outcome.UNKNOWN
    assert callbacks == ["checked"] and lifecycle_state(app) == before
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 2
    assert reservation_events(app, authorized.permit) == [("reserve", authorized.permit.permit.budget_units)]
    assert private_rows(app, "school-a") == []
    assert app.packs.activation_for("school-a", app.pack_id).reference == app.second
    assert app.packs.governance_receipt("governance-office", target.operation,
        authorized.permit.permit.nonce, hashlib.sha256(output).hexdigest()) is Outcome.UNKNOWN


def test_fault_after_private_insert_rolls_back_shared_and_both_tenant_rows(governed, monkeypatch):
    app = governed
    pool = app.packs.ledger._pool
    real_connection = pool.connection
    writes = []

    class FaultingConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, query, params=None):
            result = self.connection.execute(query, params)
            if isinstance(query, str) and query.startswith("INSERT INTO reference_pack_tenants_v1"):
                writes.append(params[1])
                if params[1] == "school-a":
                    raise ValueError("synthetic failure after actual private SQL write")
            return result

    @contextmanager
    def connection_with_fault():
        with real_connection() as conn:
            yield FaultingConnection(conn)

    before = lifecycle_state(app)
    monkeypatch.setattr(pool, "connection", connection_with_fault)
    result, target, authorized, output = app.enact(
        "governance-office", {"pin": app.first, "tenant": "school-a"})
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert target.reconcile(authorized.permit).outcome is Outcome.UNKNOWN
    assert writes == ["governance-office", "school-a"]
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 2
    assert reservation_events(app, authorized.permit) == [("reserve", authorized.permit.permit.budget_units)]
    assert lifecycle_state(app) == before
    assert app.packs.governance_receipt("governance-office", target.operation,
        authorized.permit.permit.nonce, hashlib.sha256(output).hexdigest()) is Outcome.UNKNOWN
