"""Exercise reference timestamp defenses with retained PostgreSQL evidence."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import replace

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.demo import SchemaConnections
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action,
    ActionEffect,
    Actor,
    Assertion,
    Decision,
    Ed25519Signer,
    PolicyContext,
    PolicyRef,
    TrustDirectory,
)
from regulated_core.clock import ClockError, ClockReading
from regulated_core.persistence_pg import migrate


class FixtureClock:
    """Controlled input for the new recorder; no system clock is changed."""

    domain = "test:recording-time"

    def __init__(self):
        self.value = 10_000_000

    def read(self):
        return ClockReading(self.domain, self.value)

    def read_on(self, connection):
        return self.read()

    def now_us(self):
        return self.value


@pytest.fixture
def recording_case(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; database qualification must not skip"
    assert conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        assert connection.execute("SELECT current_database()").fetchone()[0] == "factory_test"
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    (tmp_path / "retained-schema.json").write_text(json.dumps({"schema": schema}), encoding="utf-8")
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    clock = FixtureClock()
    signer = Ed25519Signer("test:evidence")
    trust = TrustDirectory()
    trust.register_signer(signer)
    recorder = ReferenceDecisionRecorder(signer, trust, pool=pool, clock=clock)
    args = (
        Assertion("sample", "test-tenant", "course:lesson", "a" * 64),
        Action("course:review", ActionEffect.REVERSIBLE),
        PolicyContext(
            "test-tenant",
            Actor("reviewer", "test-tenant", frozenset()),
            "education:review",
            "recording-test",
            clock.value,
        ),
        PolicyRef("course", "test-policy", "1.0"),
        Decision.deny("REVIEW_PENDING", "standalone recorder test"),
    )
    return recorder, clock, pool, signer, trust, args


def test_recorder_preserves_prepared_hash_and_refuses_stale_time(recording_case):
    recorder, clock, _, _, _, args = recording_case
    stale = list(args)
    stale[2] = replace(args[2], now_us=1)
    with pytest.raises(ClockError, match="age bound"):
        recorder.record(*stale)
    assert recorder.entries("test-tenant") == ()
    prepared, prepared_hash = recorder.make_record(*args)
    entry = recorder.record(*args)
    assert entry.record == prepared
    assert entry.record_hash == prepared_hash
    assert entry.record.decided_at_us == clock.value
    assert recorder.entries("test-tenant") == (entry,)


def test_durable_predecessor_time_survives_new_recorder(recording_case):
    recorder, clock, pool, signer, trust, args = recording_case
    entry = recorder.record(*args)
    restored = ReferenceDecisionRecorder(signer, trust, pool=pool, clock=clock)
    earlier_args = list(args)
    earlier_args[2] = replace(args[2], now_us=clock.value - 1)
    record, record_hash = restored.make_record(*earlier_args)
    with pytest.raises(ClockError, match="precedes the durable"):
        restored.append(record, record_hash)
    assert restored.entries("test-tenant") == (entry,)
    clock.value += 1
    later = restored.record(*args)
    assert later.seq == 1
    assert later.prev_hash == entry.chain_hash()
    assert restored.verify_chain("test-tenant")


def test_age_and_future_bounds_do_not_advance_head(recording_case):
    recorder, clock, _, _, _, args = recording_case
    for recording_time in (clock.value - recorder.max_record_age_us - 1, clock.value + 1):
        candidate = list(args)
        candidate[2] = replace(args[2], now_us=recording_time)
        record, record_hash = recorder.make_record(*candidate)
        with pytest.raises(ClockError, match="age bound"):
            recorder.append(record, record_hash)
        assert recorder.entries("test-tenant") == ()
    assert recorder.record(*args).seq == 0


def test_transaction_append_path_enforces_age_bound(recording_case):
    recorder, _, pool, _, _, args = recording_case
    stale = list(args)
    stale[2] = replace(args[2], now_us=1)
    record, record_hash = recorder.make_record(*stale)
    with pytest.raises(ClockError, match="age bound"):
        with pool.connection() as connection, connection.transaction():
            connection.execute("SELECT set_config('app.tenant', %s, true)", ("test-tenant",))
            recorder._append_on(connection, record, record_hash)
    assert recorder.entries("test-tenant") == ()
