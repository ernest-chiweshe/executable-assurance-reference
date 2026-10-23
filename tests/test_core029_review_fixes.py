"""CORE-029 independent code review (T-035): one test per blocking finding and per surviving-mutant gap.

Isolated PostgreSQL; synthetic tenants. A restore is emulated as rows written without firing triggers.
"""
import os
import secrets
import uuid

import psycopg
import pytest
from psycopg import sql

import assurance_reference.local_sessions as local_sessions_module
import assurance_reference.project_entry as project_entry_module
import regulated_core.persistence_pg as persistence_module
from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import LocalAuthorityRoles, provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.project_entry import issue_api_key, revoke_api_key
from assurance_reference.recovery_ceremony import EPOCH_JUMP, CeremonyRefused, provision_recovery_login
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from regulated_core.delegation import GrantRevocation
from regulated_core.authority_fence_pg import lock_current_authority
from regulated_core.budget import BudgetError
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGrantStore, PostgresMissionBudget, PostgresRevocationLedger
from test_recovery_ceremony import _ceremony, _wait_out_quarantine, held, make_held  # noqa: F401


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def _floor_row(roles):
    with _admin(roles) as admin:
        return admin.execute("SELECT highwater_us, hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                             (roles.domain,)).fetchone()


# B2: the hold time is the server's, and the clock login cannot plant one.
def test_the_clock_login_cannot_set_a_hold_and_a_detected_hold_is_never_before_the_floor():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    with roles.clock.connection() as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connection.transaction():
                connection.execute("UPDATE reference_clock_floor_v1 SET hold_at_us = 1, hold_reason = 'planted'")
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    early = clock.read()
    later = clock.read()
    with _admin(roles) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (early.now_us - 1, roles.domain))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
    highwater, hold_at = _floor_row(roles)
    assert hold_at >= later.now_us  # never earlier than what this process saw of the lost timeline


# B6: each negative-authority write ticks the sentinel after its commit.
@pytest.mark.parametrize("site", ["revocation", "delegation", "session", "api-key"])
def test_each_negative_authority_write_ticks_after_its_commit(site, monkeypatch):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    seen = []

    def committed_probe():
        # The hook runs after the write's commit: a separate connection already sees the row.
        with _admin(roles) as admin:
            admin.execute("SELECT set_config('app.tenant', 'tenant-a', false)")
            seen.append(admin.execute(probe_sql).fetchone()[0])

    module = {"revocation": persistence_module, "delegation": persistence_module,
              "session": local_sessions_module, "api-key": project_entry_module}[site]
    monkeypatch.setattr(module, "authority_write_committed", committed_probe)
    if site == "revocation":
        probe_sql = "SELECT count(*) FROM regulated_revocation_events_v1"
        PostgresRevocationLedger(pool=roles.governor).revoke("tenant-a", actor="admin", reason="t",
                                                              now_us=clock.read().now_us)
    elif site == "delegation":
        probe_sql = "SELECT count(*) FROM regulated_delegation_revocations_v1"
        # No runtime login holds INSERT on delegation revocations (role contract); the write site is the store's.
        from assurance_reference.local_roles import LocalPool
        owner = LocalPool(os.environ["FACTORY_TEST_DB_URL"], roles.schema, "grant-owner")
        PostgresGrantStore(pool=owner).revoke(
            "tenant-a", GrantRevocation("0" * 64, "admin", "t", clock.read().now_us))
        owner.close()
    elif site == "session":
        probe_sql = "SELECT count(*) FROM reference_sessions_v1 WHERE revoked"
        sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
        sessions.provision_identity("tenant-a", "p", "p.local", "fictional-password-001")
        identity = sessions.authenticate("tenant-a", sessions.login("tenant-a", "p.local", "fictional-password-001"))
        sessions.revoke(identity)
    else:
        probe_sql = "SELECT count(*) FROM reference_api_keys_v1 WHERE revoked_at_us IS NOT NULL"
        from assurance_reference.local_roles import LocalPool
        owner = LocalPool(os.environ["FACTORY_TEST_DB_URL"], roles.schema, "api-owner")
        token = issue_api_key(owner, tenant="tenant-a", scopes=("read",), issued_at_us=clock.read().now_us)
        assert revoke_api_key(owner, token, revoked_at_us=clock.read().now_us)
        owner.close()
    assert seen == [1], seen


# B6: the recovery login is never one of the runtime pools.
def test_the_recovery_login_is_never_a_runtime_pool():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    from assurance_reference.local_roles import LocalPool
    owner = LocalPool(os.environ["FACTORY_TEST_DB_URL"], roles.schema, "recovery-owner")
    recovery = provision_recovery_login(owner, os.environ["FACTORY_TEST_DB_URL"])
    runtime = {pool.role for pool in vars(roles).values() if hasattr(pool, "role")}
    assert recovery.role not in runtime
    assert all(not role.startswith("ref_recovery_") for role in runtime)
    assert set(LocalAuthorityRoles.__dataclass_fields__) == {"schema", "domain", *(
        name for name in LocalAuthorityRoles.__dataclass_fields__ if name not in ("schema", "domain"))}
    recovery.close()
    owner.close()


# B5 and B6 on the ceremony, using the held fixture of test_recovery_ceremony.
def _seed_authority(admin, roles):
    admin.execute("SET session_replication_role = replica")  # rows already in the backup
    admin.execute("INSERT INTO regulated_delegation_grants_v1 (tenant, grant_digest, parent_digest, body, signature)"
                  " VALUES ('tenant-a', %s, '', '{}', '{}')", ("1" * 64,))
    admin.execute("INSERT INTO reference_identities_v1 (tenant, principal, username, salt, password_hash, active)"
                  " VALUES ('tenant-a', 'p', 'p.local', '\\x00', '\\x00', true)")
    admin.execute("INSERT INTO reference_sessions_v1 (tenant, reference, principal, expires_at_us, revoked)"
                  " VALUES ('tenant-a', 'r1', 'p', 9223372036854775807, false)")
    admin.execute("INSERT INTO reference_api_keys_v1 (key_id, tenant, secret_sha256, scopes, issued_at_us)"
                  " VALUES (%s, 'tenant-a', %s, '[\"read\"]', 1)", ("k" * 32, "2" * 64))
    admin.execute("INSERT INTO projectos_states (tenant_id, namespace, project_id, revision, state)"
                  " VALUES ('tenant-z', 'health', 'p1', 1, '{}')")


def _close(pools):
    for pool in pools:
        pool.close()


def test_the_ceremony_revokes_every_grant_session_and_api_key(tmp_path):
    (roles, clock, authority, signer, _, hold_at, witnessed, _), pools = make_held(tmp_path, _seed_authority)
    _wait_out_quarantine(hold_at, clock)
    summary = authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    assert summary["delegation_revocations"] == 1 and summary["sessions_revoked"] == 1
    assert summary["api_keys_revoked"] == 1
    with _admin(roles) as admin:
        assert admin.execute("SELECT count(*) FROM regulated_delegation_revocations_v1").fetchone()[0] == 1
        assert admin.execute("SELECT bool_and(revoked) FROM reference_sessions_v1").fetchone()[0] is True
        assert admin.execute("SELECT count(*) FROM reference_api_keys_v1 WHERE revoked_at_us IS NULL"
                             ).fetchone()[0] == 0
    _close(pools)


def test_the_ceremony_rechecks_the_hold_inside_its_transaction(held, monkeypatch):  # noqa: F811
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    ceremony = _ceremony(signer, roles, hold_at - 1, witnessed)  # names a hold that is not the current one
    monkeypatch.setattr(type(authority), "_hold", lambda self: hold_at - 1)  # the pre-check is fooled
    with pytest.raises(CeremonyRefused, match="hold changed during the ceremony"):
        authority.resume(ceremony)
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_the_ceremony_finds_tenant_id_tables_and_refuses_an_unreadable_tenant_table(tmp_path):
    (roles, clock, authority, signer, _, hold_at, witnessed, _), pools = make_held(tmp_path, _seed_authority)
    _wait_out_quarantine(hold_at, clock)
    with _admin(roles) as admin:  # a tenant table created after the recovery login was provisioned
        admin.execute("CREATE TABLE late_tenant_rows (tenant text)")
    with pytest.raises(CeremonyRefused, match="cannot see every tenant column"):
        authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    with _admin(roles) as admin:
        admin.execute("DROP TABLE late_tenant_rows")
    summary = authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    assert "tenant-z" in summary["tenants"]  # found through a tenant_id column
    _close(pools)


# Design test (R2B-DESIGN step 4): a permit at a lost epoch is refused after the ceremony.
LOST_EPOCH = 2  # the backup holds epoch 1; the lost tail revoked once more, to epoch 2, and issued a permit there


def _seed_epoch(admin, roles):
    PostgresRevocationLedger(pool=roles.governor).revoke("tenant-a", actor="admin", reason="in the backup",
                                                         now_us=1)


def _fence(roles, epoch):
    with roles.receiver.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
        lock_current_authority(connection, tenant_id="tenant-a", expected_epoch=epoch)


def test_a_permit_at_a_lost_epoch_is_refused_after_the_ceremony(tmp_path):
    (roles, clock, authority, signer, _, hold_at, witnessed, _), pools = make_held(tmp_path, _seed_epoch)
    _wait_out_quarantine(hold_at, clock)
    authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    ledger = PostgresRevocationLedger(pool=roles.governor)
    assert ledger.epoch("tenant-a") == 1 + EPOCH_JUMP
    with pytest.raises(EmissionError, match="revoked"):
        _fence(roles, LOST_EPOCH)
    # Without the jump the next revocation would re-create the lost epoch; with it, it cannot.
    ledger.revoke("tenant-a", actor="admin", reason="after resumption", now_us=clock.read().now_us)
    assert ledger.epoch("tenant-a") == 2 + EPOCH_JUMP
    with pytest.raises(EmissionError, match="revoked"):
        _fence(roles, LOST_EPOCH)
    _fence(roles, 2 + EPOCH_JUMP)  # a permit at the current epoch still passes
    _close(pools)


# Design test (R2B-DESIGN, "Budget needs no replay"): capacity cannot grow across the rollback.
def _seed_budget(admin, roles):
    budget = PostgresMissionBudget(pool=roles.receiver, allocator_pool=roles.allocator)
    for reservation in ("r-lost-consume", "r-prepared"):
        budget.reserve("tenant-a", "m", reservation_id=reservation, units=1, limit=2)
    admin.execute("SET session_replication_role = replica")
    admin.execute("INSERT INTO regulated_preparations_v1 (tenant, nonce, mission, reservation_id,"
                  " preparation_digest, body, signature) VALUES ('tenant-a', 'n-prepared', 'm', 'r-prepared',"
                  " %s, '{\"draft\": {}}', '{}')", ("3" * 64,))


def test_budget_capacity_cannot_grow_across_the_rollback(tmp_path):
    (roles, clock, authority, signer, _, hold_at, witnessed, _), pools = make_held(tmp_path, _seed_budget)
    _wait_out_quarantine(hold_at, clock)
    authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    budget = PostgresMissionBudget(pool=roles.receiver, allocator_pool=roles.allocator)
    # The lost tail consumed r-lost-consume; its reserve row survived and still counts against the limit.
    with pytest.raises(BudgetError, match="exceeded"):
        budget.reserve("tenant-a", "m", reservation_id="r-new", units=1, limit=2)
    # A prepared reservation cannot be returned without a not-committed receipt, which the restore did not bring.
    with pytest.raises(psycopg.errors.CheckViolation, match="prepared authority prevents reservation release"):
        budget.release("tenant-a", "m", "r-prepared")
    with pytest.raises(BudgetError, match="exceeded"):
        budget.reserve("tenant-a", "m", reservation_id="r-new", units=1, limit=2)
    _close(pools)
