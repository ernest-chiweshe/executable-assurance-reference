"""Guarded contracts under actual restricted database logins; no guard changes."""

import os

import psycopg
import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import PostgresMissionBudget


@pytest.mark.parametrize("dsn", ["dbname=factory", "dbname=factory_test",
                                "host=192.0.2.1 dbname=factory_test"])
def test_provisioning_refuses_other_databases_before_connect(dsn):
    with pytest.raises(ValueError, match="loopback factory_test"):
        provision_local_roles(dsn)


@pytest.fixture(scope="module")
def roles():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test is required; no skipped qualification"
    return provision_local_roles(dsn)


def test_runtime_logins_cannot_own_schema_edit_grants_or_assume_other_roles(roles):
    pools = [roles.receiver, roles.allocator, roles.recorder, roles.governor,
             roles.clock, roles.alerts, roles.session_reader, roles.session_issuer, roles.project_state,
             roles.education_reader, roles.education_governor, roles.monitor_ingress]
    seen = set()
    for pool in pools:
        with pool.connection() as connection:
            seen.add(connection.execute("SELECT session_user").fetchone()[0])
            assert connection.execute(
                "SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication "
                "FROM pg_roles WHERE rolname=session_user"
            ).fetchone() == (False, False, False, False, False)
            assert not connection.execute(
                "SELECT pg_has_role(session_user,nspowner,'MEMBER') FROM pg_namespace "
                "WHERE nspname=current_schema()"
            ).fetchone()[0]
            for table in ("regulated_budget_writer_roles_v1", "regulated_preparation_writers_v1"):
                assert not connection.execute(
                    "SELECT has_table_privilege(session_user,%s,'INSERT,UPDATE,DELETE,TRUNCATE')",
                    (table,),
                ).fetchone()[0]
            for other in pools:
                if other is not pool:
                    assert not connection.execute("SELECT pg_has_role(session_user,%s,'MEMBER')",
                                                  (other.role,)).fetchone()[0]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute("CREATE TABLE forbidden_authority (value integer)")
    assert len(seen) == 12


def test_monitor_ingress_can_only_append_heartbeats_without_receiver_write_access(roles):
    with roles.monitor_ingress.connection() as connection:
        assert connection.execute(
            "SELECT has_table_privilege(session_user,'regulated_monitor_heartbeats_v2','INSERT')"
        ).fetchone() == (True,)
        for column in ("installation", "monitor_id", "sequence", "beat_at_us", "signature"):
            assert connection.execute(
                "SELECT has_column_privilege(session_user,'regulated_monitor_heartbeats_v2',%s,'SELECT')",
                (column,),
            ).fetchone() == (column in {"installation", "monitor_id", "sequence"},)
        for table in ("regulated_monitor_heartbeats_v2", "regulated_permit_uses_v1",
                      "regulated_mission_budget_events_v1", "regulated_database_receipts_v1"):
            privileges = "SELECT,UPDATE,DELETE,TRUNCATE"
            if table != "regulated_monitor_heartbeats_v2":
                privileges += ",INSERT"
            assert connection.execute(
                "SELECT has_table_privilege(session_user,%s,%s)", (table, privileges),
            ).fetchone() == (False,)
    with roles.receiver.connection() as connection:
        assert connection.execute(
            "SELECT has_table_privilege(session_user,'regulated_monitor_heartbeats_v2',"
            "'INSERT,UPDATE,DELETE,TRUNCATE')"
        ).fetchone() == (False,)


def test_budget_reserve_consume_release_duties_and_tenant_visibility(roles):
    allocator = PostgresMissionBudget(pool=roles.allocator)
    receiver = PostgresMissionBudget(pool=roles.receiver)
    allocator.reserve("school-a", "lesson", reservation_id="r1", units=1, limit=1)
    for pool in (roles.receiver, roles.recorder, roles.governor):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            PostgresMissionBudget(pool=pool).release("school-a", "lesson", "r1")
    # Governor now consumes in its own governed effect transaction; allocator/recorder may not.
    for pool in (roles.allocator, roles.recorder):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            PostgresMissionBudget(pool=pool).consume("school-a", "lesson", "r1")
    receiver.consume("school-a", "lesson", "r1")
    assert receiver.committed("school-a", "lesson") == 1
    assert receiver.committed("school-b", "lesson") == 0
    with roles.receiver.connection() as connection:
        assert connection.execute("SELECT count(*) FROM regulated_mission_budget_events_v1").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("TRUNCATE regulated_mission_budget_events_v1")


def test_durable_clock_has_separate_floor_writer(roles):
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    first, second = clock.read(), clock.read()
    assert first.domain == roles.domain == second.domain
    assert second.now_us >= first.now_us
    with roles.receiver.connection() as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE reference_clock_floor_v1 SET highwater_us=0")
