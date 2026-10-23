"""B-F7b: two authority tenants keep separate roster chains on one schema under forced row-level security.

Each tenant bootstraps its own installation's roster through the signed governance target, writing only through
the restricted governor login. Then, as that login: each tenant's setting sees only its own chain; a row naming
the other tenant cannot be inserted under one tenant's setting; one tenant's store cannot read or extend the other
tenant's installation. The primary key spans installations, so an attempt to bootstrap the other tenant's
installation is refused by a unique violation: that refusal reveals that the installation exists (an existence
signal, not its content), which is recorded here as an observed limit.
"""
import os
from types import SimpleNamespace

import psycopg
import pytest

from assurance_reference.governance_targets import roster_target
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.roster_authority import RosterAuthorityVerifier
from assurance_reference.roster_tenancy import tenant_roster_store
from factory.pg_session import SessionBoundPool
from partitioned_governance_fixture import GovernedFixture
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.governance_roster import GovernanceRoster, RosterDirectory, RosterMember, roster_change_bytes
from regulated_core.governance_targets import issue_bootstrap
from regulated_core.persistence_pg import PersistenceError
from regulated_core.target import Outcome

A, B = ("office-a", "synthetic:roster-a"), ("office-b", "synthetic:roster-b")


def _roster(app, installation):
    return GovernanceRoster(installation, 1, tuple(
        RosterMember("reviewer-" + name, frozenset({"governance-approver"}), "line-" + name)
        for name in ("a", "b")), frozenset({app.keys["monitor"].key_id}), True)


def _chain(app, roles, guard, tenant, installation):
    verifier = RosterAuthorityVerifier(tenant=tenant, installation=installation, authority=app.engine.targets,
                                       recorder=app.recorder, bootstrap_trust=app.trust,
                                       bootstrap_key_ids=frozenset({app.keys["identity"].key_id}))
    store = tenant_roster_store(SessionBoundPool(roles.governor), guard=guard, proof_verifier=verifier)
    target = roster_target(store, installation, budget=app.budget, tenant_id=tenant, authority=app.engine.targets,
                           uses=app.uses, log=app.log, guard=guard, bootstrap_trust=app.trust,
                           bootstrap_key_ids=frozenset({app.keys["identity"].key_id}))
    return store, target


def _bootstrap(app, target, tenant, installation):
    first = _roster(app, installation)
    output = roster_change_bytes(first)
    signed = issue_bootstrap(app.keys["identity"], tenant_id=tenant, kind="governance-roster",
                             subject=installation, output=output)
    return first, target.bootstrap(signed, output)


@pytest.fixture
def two_chains():
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    guard = GovernanceGuard()
    stores = {}
    directory = SimpleNamespace(reporting_line=lambda tenant, subject: RosterDirectory(
        stores[tenant], dict((A, B))[tenant]).reporting_line(tenant, subject))
    app = GovernedFixture(roles, directory=directory)
    chains = {}
    for tenant, installation in (A, B):
        store, target = _chain(app, roles, guard, tenant, installation)
        stores[tenant] = store
        first, result = _bootstrap(app, target, tenant, installation)
        assert result.outcome is Outcome.COMMITTED, (tenant, result.detail)
        chains[tenant] = (store, first)
    return roles, app, guard, chains


def _visible(roles, tenant):
    with roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
        return sorted(conn.execute("SELECT tenant, installation FROM regulated_governance_rosters_v1").fetchall())


def test_each_tenant_sees_only_its_own_roster_chain(two_chains):
    roles, _, _, chains = two_chains
    assert _visible(roles, A[0]) == [A]
    assert _visible(roles, B[0]) == [B]
    assert chains[A[0]][0].current(A[1]) == chains[A[0]][1]
    assert chains[B[0]][0].current(B[1]) == chains[B[0]][1]
    # A store bound to one tenant's installation refuses another installation outright.
    for tenant, other in ((A[0], B[1]), (B[0], A[1])):
        with pytest.raises(PersistenceError, match="installation differs"):
            chains[tenant][0].current(other)


def test_a_row_naming_the_other_tenant_cannot_be_written_under_one_tenants_setting(two_chains):
    roles, *_ = two_chains
    with roles.governor.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant', %s, true)", (A[0],))
                conn.execute("INSERT INTO regulated_governance_rosters_v1"
                             " (installation, version, roster_digest, body, tenant, operation, nonce, change_digest)"
                             " VALUES (%s, 2, %s, '{}', %s, 'governance-roster', 'forged', %s)",
                             (B[1], "0" * 64, B[0], "1" * 64))
        for statement in ("UPDATE regulated_governance_rosters_v1 SET body = body",
                          "DELETE FROM regulated_governance_rosters_v1"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("SELECT set_config('app.tenant', %s, true)", (A[0],))
                    conn.execute(statement)
    assert _visible(roles, B[0]) == [B]


def test_one_tenant_cannot_bootstrap_the_other_tenants_installation(two_chains):
    roles, app, guard, _ = two_chains
    store, target = _chain(app, roles, guard, A[0], B[1])  # tenant A aiming at B's installation
    _, result = _bootstrap(app, target, A[0], B[1])
    assert result.outcome is not Outcome.COMMITTED, result
    assert _visible(roles, B[0]) == [B] and _visible(roles, A[0]) == [A]
    print("\nObserved refusal detail (existence signal recorded as a limit):", result.detail)
