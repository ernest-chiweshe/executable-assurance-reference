"""Intact reviewed roster changes under real PG roles and signed first state.

Actors, identity credentials, clearance custody and retention are synthetic.
The current stored roster supplies reporting lines. This tests local transaction
atomicity; it does not establish production governance independence.
"""
import hashlib
import os
import time
from types import SimpleNamespace

from assurance_reference.roster_authority import RosterAuthorityVerifier
from assurance_reference.roster_tenancy import tenant_roster_store
from contextlib import contextmanager
from dataclasses import replace

import pytest

from assurance_reference.governance_targets import roster_target
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from factory.pg_session import SessionBoundPool
from partitioned_governance_fixture import GovernedFixture
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.governance_roster import GovernanceRoster, RosterMember, RosterDirectory, roster_change_bytes
from regulated_core.governance_targets import issue_bootstrap
from regulated_core.persistence_pg import PostgresRosterStore, PersistenceError
from regulated_core.target import Outcome
from test_partitioned_governance import after_receiving, reservation_events


@pytest.fixture
def roster_app():
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    guard = GovernanceGuard()
    installation = "synthetic:roster-budget"
    directory = SimpleNamespace(reporting_line=lambda tenant, subject:
                                RosterDirectory(store, installation).reporting_line(tenant, subject))
    app = GovernedFixture(roles, directory=directory)
    verifier = RosterAuthorityVerifier(tenant="governance-office", installation=installation,
        authority=app.engine.targets, recorder=app.recorder, bootstrap_trust=app.trust,
        bootstrap_key_ids=frozenset({app.keys["identity"].key_id}))
    store = tenant_roster_store(SessionBoundPool(roles.governor), guard=guard, proof_verifier=verifier)
    first = GovernanceRoster(installation, 1, tuple(
        RosterMember("reviewer-" + name, frozenset({"governance-approver"}), "line-" + name)
        for name in ("a", "b")), frozenset({app.keys["monitor"].key_id}), True)
    target = roster_target(store, installation, budget=app.budget, tenant_id="governance-office",
        authority=app.engine.targets, uses=app.uses, log=app.log, guard=guard,
        bootstrap_trust=app.trust, bootstrap_key_ids=frozenset({app.keys["identity"].key_id}))
    output = roster_change_bytes(first)
    signed = issue_bootstrap(app.keys["identity"], tenant_id="governance-office",
                             kind="governance-roster", subject=installation, output=output)
    assert target.bootstrap(signed, output).outcome is Outcome.COMMITTED
    assert store.current(installation) == first
    return app, store, guard, first


def next_target(app, store, guard, first):
    return roster_target(store, first.installation, budget=app.budget, tenant_id="governance-office",
        authority=app.engine.targets, uses=app.uses, log=app.log, guard=guard)


def enact(app, target, first, *, permit_ttl_us=60_000_000):
    return app.enact_target("governance-office", target, roster_change_bytes(replace(first, version=2)),
                            mission="fixture:roster-budget", permit_ttl_us=permit_ttl_us)


def test_reviewed_roster_effect_budget_and_receipt_commit_once(roster_app):
    app, store, guard, first = roster_app
    result, target, authorized, output = enact(app, next_target(app, store, guard, first), first)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert store.current(first.installation) == replace(first, version=2)
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 1
    assert reservation_events(app, authorized.permit) == [("consume", 1), ("reserve", 1)]
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 1
    assert store.receipt("governance-office", target.operation, authorized.permit.permit.nonce,
                         hashlib.sha256(output).hexdigest()) is Outcome.COMMITTED


@pytest.mark.parametrize("fault", ["after-final-check", "after-roster-insert"])
def test_roster_host_failure_rolls_back_effect_receipt_and_consume_keeps_reservation(roster_app, monkeypatch, fault):
    app, store, guard, first = roster_app
    observations = []
    if fault == "after-final-check":
        actual_apply = store.apply

        def fail():
            observations.append("checked")
            raise ValueError("synthetic storage failure after intact receiving check")

        def apply(change):
            return actual_apply(replace(change, final_check=after_receiving(change.final_check, fail)))
        monkeypatch.setattr(store, "apply", apply)
    else:
        real_connection = store._pool.connection

        class FaultingConnection:
            def __init__(self, conn):
                self.conn = conn

            def __getattr__(self, name):
                return getattr(self.conn, name)

            def execute(self, query, params=None):
                result = self.conn.execute(query, params)
                if isinstance(query, str) and query.startswith("INSERT INTO regulated_governance_rosters_v1"):
                    observations.append("inserted")
                    raise ValueError("synthetic storage failure after actual roster insert")
                return result

        @contextmanager
        def connection():
            with real_connection() as conn:
                yield FaultingConnection(conn)
        monkeypatch.setattr(store._pool, "connection", connection)
    result, target, authorized, output = enact(app, next_target(app, store, guard, first), first)
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert observations == (["checked"] if fault == "after-final-check" else ["inserted"])
    assert store.current(first.installation) == first
    assert store.receipt("governance-office", target.operation, authorized.permit.permit.nonce,
                         hashlib.sha256(output).hexdigest()) is Outcome.UNKNOWN
    assert target.reconcile(authorized.permit).outcome is Outcome.UNKNOWN
    assert app.budget.committed("governance-office", authorized.permit.permit.mission) == 0
    assert reservation_events(app, authorized.permit) == [("reserve", authorized.permit.permit.budget_units)]


def test_committed_roster_reopens_after_permit_expiry_and_evidence_outage_fails_closed(roster_app, monkeypatch):
    app, store, guard, first = roster_app
    result, target, authorized, output = enact(app, next_target(app, store, guard, first), first,
                                              permit_ttl_us=8_000_000)
    assert result.outcome is Outcome.COMMITTED, result.detail
    remaining = authorized.permit.permit.expires_at_us - app.clock.now_us()
    if remaining >= 0:
        time.sleep(remaining / 1_000_000 + 0.02)
    assert app.clock.now_us() > authorized.permit.permit.expires_at_us
    reopened = PostgresRosterStore(pool=store._pool, guard=guard, proof_verifier=store._proof_verifier)
    assert reopened.current(first.installation) == replace(first, version=2)
    key = ("governance-office", target.operation, authorized.permit.permit.nonce,
           hashlib.sha256(output).hexdigest())
    assert reopened.receipt(*key) is Outcome.COMMITTED

    def unavailable(*args):
        raise PersistenceError("synthetic evidence storage unavailable")
    monkeypatch.setattr(app.recorder, "entries", unavailable)
    with pytest.raises(PersistenceError):
        reopened.current(first.installation)
    with pytest.raises(PersistenceError):
        reopened.receipt(*key)
