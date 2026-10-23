"""R-2b stage 1: the durable clock floor detects a database that went backwards and holds the whole cluster.

A restore writes rows without firing triggers, as pg_restore does; it is emulated here with
session_replication_role = replica on an isolated test cluster.
"""

import os
import subprocess
import sys
import uuid

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.clock_floor import DurableClock, ROLLBACK_REASON, provision_floor
from assurance_reference.local_roles import LocalPool
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock


@pytest.fixture
def floor():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped database qualification"
    assert conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    pool = LocalPool(dsn, schema, "hold-test")
    with pool.connection() as connection:
        domain = connection.execute("SELECT 'pg:' || system_identifier::text FROM pg_control_system()").fetchone()[0]
    source = DbClock(pool, domain)
    provision_floor(pool, source)
    yield dsn, schema, pool, source
    pool.close()


def _admin(dsn, schema):
    connection = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    return connection


def _row(dsn, schema, domain):
    with _admin(dsn, schema) as admin:
        return admin.execute("SELECT highwater_us, hold_at_us, hold_reason FROM reference_clock_floor_v1"
                             " WHERE domain = %s", (domain,)).fetchone()


def _restore_floor(dsn, schema, domain, value):
    """Write an older floor the way a restore does: rows written without firing triggers."""
    with _admin(dsn, schema) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s", (value, domain))


def test_no_hold_in_normal_operation(floor):
    dsn, schema, pool, source = floor
    clock = DurableClock(source, floor_pool=pool)
    readings = [clock.read().now_us for _ in range(3)]
    assert readings == sorted(readings)
    assert _row(dsn, schema, source.domain)[1:] == (None, None)


def test_rollback_under_a_running_process_holds_and_restores_the_floor(floor):
    dsn, schema, pool, source = floor
    clock = DurableClock(source, floor_pool=pool)
    before = clock.read()
    later = clock.read()
    _restore_floor(dsn, schema, source.domain, before.now_us - 1)
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
    highwater, hold_at, reason = _row(dsn, schema, source.domain)
    assert hold_at is not None and reason == ROLLBACK_REASON
    assert highwater >= later.now_us  # the largest committed floor is restored, never left regressed
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()  # and it stays held


def test_the_hold_reaches_a_process_that_never_saw_the_later_floor(floor):
    dsn, schema, pool, source = floor
    clock = DurableClock(source, floor_pool=pool)
    early = clock.read()
    clock.read()
    _restore_floor(dsn, schema, source.domain, early.now_us - 1)
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
    # A separate operating-system process has no memory of the later floor; the hold in the row stops it.
    probe = (
        "import sys\n"
        "from assurance_reference.clock_floor import DurableClock\n"
        "from assurance_reference.local_roles import LocalPool\n"
        "from regulated_core.clock import ClockError\n"
        "from regulated_core.clock_pg import DbClock\n"
        "pool = LocalPool(sys.argv[1], sys.argv[2], 'hold-probe')\n"
        "try:\n"
        "    DurableClock(DbClock(pool, sys.argv[3]), floor_pool=pool).read()\n"
        "    print('READ')\n"
        "except ClockError as exc:\n"
        "    print('REFUSED', exc)\n"
        "pool.close()\n"
    )
    out = subprocess.run([sys.executable, "-B", "-c", probe, dsn, schema, source.domain],
                         capture_output=True, text=True, timeout=120, env=dict(os.environ))
    assert out.stdout.startswith("REFUSED recovery hold"), (out.stdout, out.stderr)


def test_a_process_with_no_later_memory_does_not_detect_alone(floor):
    """The stated limit: detection needs a process that committed a later floor (or the witnesses)."""
    dsn, schema, pool, source = floor
    clock = DurableClock(source, floor_pool=pool)
    early = clock.read()
    clock.read()
    _restore_floor(dsn, schema, source.domain, early.now_us - 1)
    probe = (
        "import sys\n"
        "from assurance_reference.clock_floor import DurableClock\n"
        "from assurance_reference.local_roles import LocalPool\n"
        "from regulated_core.clock_pg import DbClock\n"
        "pool = LocalPool(sys.argv[1], sys.argv[2], 'hold-probe')\n"
        "DurableClock(DbClock(pool, sys.argv[3]), floor_pool=pool).read()\n"
        "print('READ')\n"
        "pool.close()\n"
    )
    out = subprocess.run([sys.executable, "-B", "-c", probe, dsn, schema, source.domain],
                         capture_output=True, text=True, timeout=120, env=dict(os.environ))
    assert out.stdout.strip() == "READ", (out.stdout, out.stderr)
    assert _row(dsn, schema, source.domain)[1] is None


def test_sql_cannot_lower_the_floor_or_clear_a_hold(floor):
    dsn, schema, pool, source = floor
    clock = DurableClock(source, floor_pool=pool)
    early = clock.read()
    clock.read()
    with _admin(dsn, schema) as admin:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="cannot decrease"):
            admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                          (early.now_us - 1, source.domain))
    _restore_floor(dsn, schema, source.domain, early.now_us - 1)
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
    with _admin(dsn, schema) as admin:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="cannot be changed"):
            admin.execute("UPDATE reference_clock_floor_v1 SET hold_at_us = NULL, hold_reason = NULL"
                          " WHERE domain = %s", (source.domain,))
    assert _row(dsn, schema, source.domain)[1] is not None
