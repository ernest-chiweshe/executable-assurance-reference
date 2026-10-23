"""R-2b stage 3b: detection beyond the clock reads of a busy process.

A mandatory heartbeat lets an idle process detect a rollback within its interval; a sentinel file keeps the process
high-water across a restart on the same host; a post-commit sentinel tick after a negative-authority write (here a
revocation) makes a restore to just before that write detectable. A restore is emulated as rows written without
firing triggers.
"""
import os
import time

import psycopg
import pytest
from psycopg import sql

import assurance_reference.clock_floor as clock_floor
from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import PostgresRevocationLedger


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def _restore(roles, floor_us, *statements):
    with _admin(roles) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (floor_us, roles.domain))
        for statement, params in statements:
            admin.execute(statement, params)


def _hold_at(roles):
    with _admin(roles) as admin:
        return admin.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                             (roles.domain,)).fetchone()[0]


def _forget_process_memory():
    with clock_floor._SENTINEL_LOCK:
        clock_floor._HIGHWATER.clear()


def test_an_idle_process_detects_a_rollback_through_its_heartbeat():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    early = clock.read()
    clock.read()
    clock.start_heartbeat(0.2)
    try:
        _restore(roles, early.now_us - 1)
        deadline = time.monotonic() + 10
        while _hold_at(roles) is None:
            assert time.monotonic() < deadline, "the heartbeat did not detect the rollback"
            time.sleep(0.1)
    finally:
        clock.stop_heartbeat()
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_the_sentinel_file_keeps_the_high_water_across_a_restart(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    sentinel = tmp_path / "sentinel.json"
    first = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock, sentinel_file=sentinel)
    early = first.read()
    first.sentinel_tick()  # reads and persists
    assert sentinel.exists()
    _forget_process_memory()  # a restart: nothing in memory
    _restore(roles, early.now_us - 1)
    restarted = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock, sentinel_file=sentinel)
    with pytest.raises(ClockError, match="recovery hold"):
        restarted.read()
    assert _hold_at(roles) is not None


def test_a_restore_to_just_before_a_revocation_is_detected_by_its_post_commit_tick():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    snapshot = clock.read()  # the backup is taken here: floor = snapshot
    PostgresRevocationLedger(pool=roles.governor).revoke("tenant-a", actor="admin", reason="test",
                                                          now_us=snapshot.now_us)
    # The restore loses the revocation and puts the floor back to the backup's value.
    _restore(roles, snapshot.now_us,
             ("DELETE FROM regulated_revocation_events_v1 WHERE tenant = %s", ("tenant-a",)))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
