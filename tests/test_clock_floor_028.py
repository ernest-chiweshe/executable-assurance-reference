"""CORE-028: the floor read and the pool reset fold into fewer round trips with identical statements and guarantees."""

import os
import uuid
from contextlib import contextmanager

import psycopg
import pytest
from psycopg import _connection_base, _pipeline_base, sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.pq import TransactionStatus

from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.local_roles import LocalPool
from regulated_core.clock import ClockError, ClockReading
from regulated_core.clock_pg import DbClock


def _pool():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped database qualification"
    assert conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    return dsn, schema, LocalPool(dsn, schema, "floor-test")


@pytest.fixture
def exact_case():
    dsn, schema, pool = _pool()
    with pool.connection() as connection:
        domain = connection.execute("SELECT 'pg:' || system_identifier::text FROM pg_control_system()").fetchone()[0]
    source = DbClock(pool, domain)
    provision_floor(pool, source)
    yield dsn, schema, pool, source, DurableClock(source, floor_pool=pool)
    pool.close()


class Recorder:
    """Records, at the psycopg boundary, every statement sent and every pipeline sync, without changing them."""

    def __init__(self, monkeypatch):
        self.events = []
        exec_command = _connection_base.BaseConnection._exec_command
        execute = psycopg.Cursor.execute
        sync = _pipeline_base.BasePipeline._enqueue_sync
        recorder = self

        def _exec(conn, command, *args, **kwargs):
            text = command if isinstance(command, (bytes, str)) else command.as_bytes(conn)
            text = text.decode() if isinstance(text, bytes) else text
            recorder.events.append(("pipelined" if conn._pipeline else "direct", text[:32]))
            return exec_command(conn, command, *args, **kwargs)

        def _execute(cursor, query, *args, **kwargs):
            text = query if isinstance(query, str) else query.as_string(cursor._conn)
            recorder.events.append(("pipelined" if cursor._conn._pipeline else "direct", text.strip()[:32]))
            return execute(cursor, query, *args, **kwargs)

        def _sync(pipeline, *args, **kwargs):
            recorder.events.append(("sync", ""))
            return sync(pipeline, *args, **kwargs)

        monkeypatch.setattr(_connection_base.BaseConnection, "_exec_command", _exec)
        monkeypatch.setattr(psycopg.Cursor, "execute", _execute)
        monkeypatch.setattr(_pipeline_base.BasePipeline, "_enqueue_sync", _sync)

    def statements(self):
        return [text for mode, text in self.events if mode != "sync"]

    def round_trips(self):
        return sum(1 for mode, _ in self.events if mode in ("direct", "sync"))


# One floor read followed by the pool reset, exactly in this order.
EXPECTED = ["BEGIN", "SET LOCAL lock_timeout = '5s'", "SET LOCAL statement_timeout = '5", "SELECT highwater_us, hold_at_us,",
            None, "UPDATE reference_clock_floor_v1 ", "COMMIT", "DISCARD ALL", "SET search_path TO"]


def test_floor_read_sends_the_same_statements_in_two_round_trips(exact_case, monkeypatch):
    _, _, _, _, clock = exact_case
    clock.read()  # warm the pool
    recorder = Recorder(monkeypatch)
    before = clock.read()
    after = clock.read()
    assert after.now_us >= before.now_us
    statements = recorder.statements()
    assert len(statements) == 2 * len(EXPECTED), statements
    for actual, wanted in zip(statements, EXPECTED * 2):
        if wanted is not None:
            assert actual.startswith(wanted), (actual, wanted)
    # Nothing is sent outside a pipeline: a read costs two syncs and its reset one.
    assert not [e for e in recorder.events if e[0] == "direct"], recorder.events
    assert recorder.round_trips() == 2 * 3


def test_failed_update_commits_nothing_and_returns_no_reading(exact_case):
    dsn, schema, pool, source, clock = exact_case
    before = clock.read()
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        admin.execute("CREATE FUNCTION refuse_floor_update() RETURNS trigger LANGUAGE plpgsql AS "
                      "$$ BEGIN RAISE EXCEPTION 'injected floor update failure'; END $$")
        admin.execute("CREATE TRIGGER refuse_floor_update BEFORE UPDATE ON reference_clock_floor_v1 "
                      "FOR EACH ROW EXECUTE FUNCTION refuse_floor_update()")
        try:
            with pytest.raises(ClockError, match="unavailable"):
                clock.read()
            stored = admin.execute("SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s",
                                   (source.domain,)).fetchone()[0]
            assert stored == before.now_us  # the failed read committed nothing
        finally:
            admin.execute("DROP TRIGGER refuse_floor_update ON reference_clock_floor_v1")
            admin.execute("DROP FUNCTION refuse_floor_update()")
    # The pool connection came back clean and the floor still advances.
    with pool.connection() as connection:
        assert connection.info.transaction_status is TransactionStatus.IDLE
    assert clock.read().now_us >= before.now_us


def test_incomplete_commit_is_refused_by_the_post_condition(exact_case, monkeypatch):
    _, _, pool, _, clock = exact_case
    clock.read()
    execute = psycopg.Cursor.execute

    def swallow_commit(cursor, query, *args, **kwargs):
        if isinstance(query, str) and query.strip() == "COMMIT":
            query = "SELECT 1"  # the transaction stays open: the reading must not be returned
        return execute(cursor, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, "execute", swallow_commit)
    with pytest.raises(ClockError, match="commit did not complete"):
        clock.read()
    monkeypatch.undo()
    with pool.connection() as connection:
        assert connection.info.transaction_status is TransactionStatus.IDLE
    assert clock.read().now_us > 0


def test_pool_reset_sends_both_statements_in_one_pipeline(monkeypatch):
    _, schema, pool = _pool()
    with pool.connection() as connection:
        connection.execute("SELECT 1")
    recorder = Recorder(monkeypatch)
    with pool.connection() as connection:
        connection.execute("SET search_path TO pg_catalog")
    tail = recorder.events[-3:]
    assert [mode for mode, _ in tail] == ["pipelined", "pipelined", "sync"], recorder.events
    assert tail[0][1].startswith("DISCARD ALL") and tail[1][1].startswith("SET search_path TO")
    with pool.connection() as connection:
        assert connection.execute("SHOW search_path").fetchone()[0].strip('"') == schema
        assert connection.info.transaction_status is TransactionStatus.IDLE
    pool.close()


def _stored(dsn, schema, domain):
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        return connection.execute("SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s",
                                  (domain,)).fetchone()[0]


def test_commit_reported_as_rollback_is_refused(exact_case, monkeypatch):
    dsn, schema, _, source, clock = exact_case
    before = clock.read()
    execute = psycopg.Cursor.execute

    def abort_instead(cursor, query, *args, **kwargs):
        if isinstance(query, str) and query.strip() == "COMMIT":
            query = "ROLLBACK"  # the session ends idle, but nothing was committed
        return execute(cursor, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, "execute", abort_instead)
    with pytest.raises(ClockError, match="commit did not complete"):
        clock.read()
    monkeypatch.undo()
    assert _stored(dsn, schema, source.domain) == before.now_us


def test_floor_connection_must_be_idle_on_entry(exact_case):
    dsn, schema, _, source, _ = exact_case

    class BusyPool:
        @contextmanager
        def connection(self):
            with psycopg.connect(dsn, autocommit=False, connect_timeout=5,
                                 options=f"-c search_path={schema}") as connection:
                connection.execute("SELECT 1")  # leaves an open transaction
                yield connection

    with pytest.raises(ClockError, match="not idle"):
        DurableClock(source, floor_pool=BusyPool()).read()


class _CustomClock:
    """A connection-bound source that is not the exact DbClock."""

    domain = "test:custom"

    def __init__(self, value):
        self.value = value
        self.on_read = None

    def read(self):
        return ClockReading(self.domain, self.value)

    def now_us(self):
        return self.value

    def read_on(self, connection):
        if self.on_read is not None:
            self.on_read(connection)
        return self.read()


@pytest.mark.parametrize("kind", ["schema", "local"])
def test_custom_source_cannot_commit_the_floor_transaction(kind):
    dsn, schema, local = _pool()
    pool = SchemaConnections(dsn, schema) if kind == "schema" else local
    source = _CustomClock(100)
    provision_floor(pool, source)
    clock = DurableClock(source, floor_pool=pool)

    def commit_then_race(connection):
        connection.commit()  # would release the row lock if it were allowed
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as other:
            other.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            other.execute("SET lock_timeout = '1s'")
            other.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                          (10_000, source.domain))

    source.value, source.on_read = 200, commit_then_race
    with pytest.raises(ClockError, match="unavailable"):
        clock.read()
    assert _stored(dsn, schema, source.domain) == 100
    local.close()


def test_custom_source_cannot_roll_back_the_floor_transaction():
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)

    def roll_back(connection):
        try:
            connection.execute("SELECT 1/0").fetchone()
        except psycopg.Error:
            connection.rollback()

    source.value, source.on_read = 300, roll_back
    with pytest.raises(ClockError, match="unavailable"):
        DurableClock(source, floor_pool=pool).read()
    assert _stored(dsn, schema, source.domain) == 100
    pool.close()


def test_custom_source_samples_outside_pipeline_mode():
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)

    def stream(connection):
        assert connection._pipeline is None
        assert [row[0] for row in connection.cursor().stream("SELECT 1")] == [1]

    source.value, source.on_read = 300, stream
    assert DurableClock(source, floor_pool=pool).read().now_us == 300
    assert _stored(dsn, schema, source.domain) == 300
    pool.close()


@pytest.mark.parametrize("kind", ["schema", "local"])
def test_custom_source_cannot_end_the_floor_transaction_with_sql(kind):
    dsn, schema, local = _pool()
    pool = SchemaConnections(dsn, schema) if kind == "schema" else local
    source = _CustomClock(100)
    provision_floor(pool, source)
    clock = DurableClock(source, floor_pool=pool)

    def commit_sql_then_race(connection):
        connection.execute("COMMIT")  # SQL text, not commit(): psycopg's guard does not see it
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as other:
            other.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            other.execute("SET lock_timeout = '1s'")
            other.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                          (10_000, source.domain))

    source.value, source.on_read = 200, commit_sql_then_race
    with pytest.raises(ClockError, match="ended the floor transaction"):
        clock.read()
    assert _stored(dsn, schema, source.domain) == 10_000  # the concurrent floor is never lowered
    local.close()


@pytest.mark.parametrize("statements", [["ROLLBACK"], ["COMMIT", "BEGIN"], ["ROLLBACK", "BEGIN", "SELECT 1"]])
def test_custom_source_cannot_replace_the_floor_transaction(statements):
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)

    def replace(connection):
        for statement in statements:
            connection.execute(statement)

    source.value, source.on_read = 300, replace
    with pytest.raises(ClockError, match="ended the floor transaction"):
        DurableClock(source, floor_pool=pool).read()
    assert _stored(dsn, schema, source.domain) == 100
    with pool.connection() as connection:
        assert connection.info.transaction_status is TransactionStatus.IDLE
    pool.close()


def test_custom_source_refused_on_a_busy_floor_connection():
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)

    class BusyPool:
        @contextmanager
        def connection(self):
            with psycopg.connect(dsn, autocommit=False, connect_timeout=5,
                                 options=f"-c search_path={schema}") as connection:
                connection.execute("SELECT 1")  # leaves an open transaction
                yield connection

    source.value = 500
    with pytest.raises(ClockError, match="not idle"):
        DurableClock(source, floor_pool=BusyPool()).read()
    assert _stored(dsn, schema, source.domain) == 100
    pool.close()


def test_exact_read_ends_its_own_transaction_after_a_failure(exact_case):
    dsn, schema, _, source, _ = exact_case

    class KeptConnection:
        """A pool that hands out one connection and never cleans it up."""

        def __init__(self):
            self.kept = psycopg.connect(dsn, autocommit=True, connect_timeout=5,
                                        options=f"-c search_path={schema}")

        @contextmanager
        def connection(self):
            yield self.kept

    pool = KeptConnection()
    unprovisioned = DurableClock(DbClock(pool, "pg:1"), floor_pool=pool)
    with pytest.raises(ClockError, match="provisioned"):
        unprovisioned.read()  # raises between the two pipelines
    assert pool.kept.info.transaction_status is TransactionStatus.IDLE
    clock = DurableClock(source, floor_pool=pool)
    assert clock.read().now_us > 0  # no lock or open transaction was left behind
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as other:
        other.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        other.execute("SELECT 1 FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE NOWAIT",
                      (source.domain,))
    pool.kept.close()


def _raise_floor_elsewhere(dsn, schema, domain):
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as other:
        other.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        other.execute("SET lock_timeout = '1s'")
        other.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (10_000, domain))


def test_custom_source_cannot_swap_in_a_new_transaction_with_an_id():
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)

    def swap(connection):
        connection.execute("COMMIT")
        connection.execute("BEGIN")
        connection.execute("SELECT pg_current_xact_id()")  # the new transaction gets an id of its own
        _raise_floor_elsewhere(dsn, schema, source.domain)

    source.value, source.on_read = 300, swap
    with pytest.raises(ClockError, match="ended the floor transaction"):
        DurableClock(source, floor_pool=pool).read()
    assert _stored(dsn, schema, source.domain) == 10_000
    pool.close()


def test_custom_source_cannot_end_the_floor_transaction_during_the_caller_read():
    dsn, schema, pool = _pool()
    source = _CustomClock(100)
    provision_floor(pool, source)
    seen = []

    def end_kept_floor_connection(connection):
        seen.append(connection)
        if len(seen) == 2:  # the caller read: the floor connection was kept from the first call
            seen[0].execute("COMMIT")
            _raise_floor_elsewhere(dsn, schema, source.domain)

    source.value, source.on_read = 300, end_kept_floor_connection
    with pool.connection() as caller:
        with pytest.raises(ClockError, match="ended the floor transaction"):
            DurableClock(source, floor_pool=pool).read_on(caller)
    assert seen[1] is caller
    assert _stored(dsn, schema, source.domain) == 10_000
    pool.close()


def test_exact_read_ends_its_own_transaction_when_commit_does_not_complete(exact_case, monkeypatch):
    dsn, schema, _, source, _ = exact_case
    kept = psycopg.connect(dsn, autocommit=True, connect_timeout=5, options=f"-c search_path={schema}")

    class KeptConnection:
        @contextmanager
        def connection(self):
            yield kept

    execute = psycopg.Cursor.execute

    def swallow_commit(cursor, query, *args, **kwargs):
        if isinstance(query, str) and query.strip() == "COMMIT":
            query = "SELECT 1"  # the transaction would stay open with its row lock
        return execute(cursor, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, "execute", swallow_commit)
    with pytest.raises(ClockError, match="commit did not complete"):
        DurableClock(source, floor_pool=KeptConnection()).read()
    monkeypatch.undo()
    assert kept.info.transaction_status is TransactionStatus.IDLE
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as other:
        other.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        other.execute("SELECT 1 FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE NOWAIT",
                      (source.domain,))
    kept.close()
