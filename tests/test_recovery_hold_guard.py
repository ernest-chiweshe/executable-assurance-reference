"""R-2b stage 3: while a recovery hold is set, every authority table refuses writes (deny by default).

The guard is one statement-level trigger per table; only the floor and alerts are allowlisted. A rollback is emulated
as a restore writes rows (triggers bypassed), then detected by a running clock, which sets the hold.
"""
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.clock_floor import HOLD_ALLOWLIST, HOLD_GUARD, DurableClock
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from test_a19_permit_expiry_isolated_pg import _short_lived_permit


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def _unguarded(roles):
    with _admin(roles) as admin:
        return sorted(row[0] for row in admin.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
            " AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND t.tgname = %s)",
            (HOLD_GUARD,)).fetchall())


def _hold(roles):
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    early = clock.read()
    clock.read()
    with _admin(roles) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (early.now_us - 1, roles.domain))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_every_table_except_the_allowlist_is_guarded_after_provisioning():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    assert _unguarded(roles) == sorted(HOLD_ALLOWLIST)


def test_every_table_is_still_guarded_after_composing_a_host_and_issuing(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    _short_lived_permit(host, tmp_path)  # exercises lazily created stores, if any
    assert _unguarded(roles) == sorted(HOLD_ALLOWLIST)


def test_writes_are_refused_during_a_hold_and_allowed_before(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    with roles.receiver.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
        connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES ('tenant-a', 'before-hold')")
    _hold(roles)
    with roles.receiver.connection() as connection:
        with pytest.raises(psycopg.DatabaseError, match="recovery hold") as refused:
            with connection.transaction():
                connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
                connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce)"
                                   " VALUES ('tenant-a', 'during-hold')")
        assert refused.value.sqlstate == "RH001"
    with _admin(roles) as admin:
        for statement in ("DELETE FROM regulated_permit_uses_v1", "TRUNCATE regulated_permit_uses_v1",
                          "UPDATE regulated_revocation_events_v1 SET reason = reason"):
            with pytest.raises(psycopg.DatabaseError, match="recovery hold") as refused:
                admin.execute(statement)
            assert refused.value.sqlstate == "RH001"
        assert admin.execute("SELECT count(*) FROM regulated_permit_uses_v1").fetchone()[0] == 1
