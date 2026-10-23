"""A durable floor for readers sharing one host-configured clock store."""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager, nullcontext, suppress
from pathlib import Path
from typing import Any

from psycopg import Error
from psycopg.pq import TransactionStatus

from regulated_core.clock import (ClockError, ClockReading, ConnectionClock, read_clock,
                                  register_authority_write_hook)
from regulated_core.clock_pg import DbClock


def provision_floor(pool: Any, source: ConnectionClock) -> None:
    """Explicit bootstrap; existing floors are never reset by provisioning.

    This is a host operation, not a repair performed by normal clock reads.
    The store must be shared by all readers covered by the host's clock claim.
    """
    with pool.connection() as connection, connection.transaction():
        connection.execute(
            "CREATE TABLE IF NOT EXISTS reference_clock_floor_v1 ("
            "domain text PRIMARY KEY, highwater_us bigint NOT NULL CHECK (highwater_us >= 0))"
        )
        # The recovery hold lives in the floor row itself, so every reader on the
        # cluster sees it at its next read without another round trip.
        connection.execute("ALTER TABLE reference_clock_floor_v1 ADD COLUMN IF NOT EXISTS hold_at_us bigint")
        connection.execute("ALTER TABLE reference_clock_floor_v1 ADD COLUMN IF NOT EXISTS hold_reason text")
        # Through SQL the floor only rises; floor rows are never deleted or truncated; a hold is set only by the
        # owner-defined hold function (which computes its time server-side) and cleared only by the recovery
        # login. Created only if absent: install_recovery_guard re-creates these with the recovery exemption,
        # and re-provisioning must not strip it.
        if connection.execute("SELECT to_regprocedure('reference_clock_floor_guard_v1()') IS NULL").fetchone()[0]:
            _install_floor_guard(connection, None)
        reading = read_clock(source, connection=connection)
        connection.execute(
            "INSERT INTO reference_clock_floor_v1 (domain, highwater_us) VALUES (%s, %s)"
            " ON CONFLICT (domain) DO NOTHING",
            (reading.domain, reading.now_us),
        )


def _install_floor_guard(connection: Any, recovery_login: str | None) -> None:
    from psycopg import sql
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    exempt = sql.Literal(recovery_login) if recovery_login else sql.SQL("NULL")
    connection.execute(sql.SQL(
        "CREATE OR REPLACE FUNCTION reference_clock_floor_guard_v1() RETURNS trigger LANGUAGE plpgsql"
        " SET search_path = pg_catalog, {schema}, pg_temp AS $$"
        " DECLARE owner_name name;"
        " BEGIN"
        "  IF TG_OP = 'TRUNCATE' OR TG_OP = 'DELETE' THEN"
        "   RAISE EXCEPTION 'clock floor rows are never deleted' USING ERRCODE = '42501';"
        "  END IF;"
        "  IF NEW.highwater_us < OLD.highwater_us THEN"
        "   RAISE EXCEPTION 'clock floor cannot decrease' USING ERRCODE = '42501';"
        "  END IF;"
        "  IF NEW.hold_at_us IS DISTINCT FROM OLD.hold_at_us OR NEW.hold_reason IS DISTINCT FROM OLD.hold_reason THEN"
        "   SELECT pg_get_userbyid(c.relowner) INTO owner_name FROM pg_class c WHERE c.oid = TG_RELID;"
        "   IF OLD.hold_at_us IS NULL THEN"
        "    IF current_user IS DISTINCT FROM owner_name THEN"
        "     RAISE EXCEPTION 'a recovery hold is set only by the hold function' USING ERRCODE = '42501';"
        "    END IF;"
        "   ELSIF session_user IS DISTINCT FROM {exempt} THEN"
        "    RAISE EXCEPTION 'recovery hold cannot be changed' USING ERRCODE = '42501';"
        "   END IF;"
        "  END IF;"
        "  RETURN NEW;"
        " END $$").format(schema=sql.Identifier(schema), exempt=exempt))
    connection.execute("DROP TRIGGER IF EXISTS reference_clock_floor_guard_v1 ON reference_clock_floor_v1")
    connection.execute("CREATE TRIGGER reference_clock_floor_guard_v1 BEFORE UPDATE OR DELETE ON reference_clock_floor_v1"
                       " FOR EACH ROW EXECUTE FUNCTION reference_clock_floor_guard_v1()")
    connection.execute("DROP TRIGGER IF EXISTS reference_clock_floor_no_truncate_v1 ON reference_clock_floor_v1")
    connection.execute("CREATE TRIGGER reference_clock_floor_no_truncate_v1 BEFORE TRUNCATE ON reference_clock_floor_v1"
                       " FOR EACH STATEMENT EXECUTE FUNCTION reference_clock_floor_guard_v1()")
    # The hold time is computed by the server: never earlier than the clock, the floor or the witnessed bound
    # the caller reports (a caller can only lengthen the quarantine). The first hold wins.
    connection.execute(sql.SQL(
        "CREATE OR REPLACE FUNCTION reference_clock_floor_hold_v1(p_domain text, p_reason text, p_bound bigint)"
        " RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, {schema}, pg_temp AS $$"
        "  UPDATE {schema}.reference_clock_floor_v1 SET"
        "   hold_at_us = COALESCE(hold_at_us, GREATEST((extract(epoch FROM pg_catalog.clock_timestamp())*1000000)::bigint,"
        "                                              highwater_us, COALESCE(p_bound, 0))),"
        "   hold_reason = COALESCE(hold_reason, p_reason)"
        "  WHERE domain = p_domain RETURNING hold_at_us"
        " $$").format(schema=sql.Identifier(schema)))
    connection.execute("REVOKE ALL ON FUNCTION reference_clock_floor_hold_v1(text, text, bigint) FROM PUBLIC")


# Tables that stay writable while a recovery hold is set: the floor carries its own guard, and
# alerts report the hold itself; no authority derives from them.
HOLD_ALLOWLIST = frozenset({"reference_clock_floor_v1", "reference_alerts_v1"})
HOLD_GUARD = "reference_recovery_hold_v1"


def install_recovery_guard(owner: Any, *, recovery_login: str | None = None) -> list[str]:
    """Refuse every write to every other table in the schema while a hold is set (deny by default).

    Idempotent; call again after any later migration so new tables are guarded too. One statement-level
    trigger per table covers INSERT, UPDATE, DELETE and TRUNCATE at no extra round trip. Only the named
    recovery login (the resumption ceremony's) is exempt. The hold check is an unlocked read: a statement
    whose snapshot predates the hold's commit (any statement in READ COMMITTED that started before it, or any
    statement of a REPEATABLE READ/SERIALIZABLE transaction whose snapshot predates it) can still write.
    The schema owner and superusers can remove or bypass the guards; they are outside this contract.
    """
    from psycopg import sql
    with owner.connection() as connection, connection.transaction():
        schema = connection.execute("SELECT current_schema()").fetchone()[0]
        exempt = sql.Literal(recovery_login) if recovery_login else sql.SQL("NULL")
        connection.execute(sql.SQL(
            "CREATE OR REPLACE FUNCTION reference_recovery_hold_guard_v1() RETURNS trigger LANGUAGE plpgsql"
            " SECURITY DEFINER SET search_path = pg_catalog, {schema}, pg_temp AS $$"
            " BEGIN"
            "  IF session_user = {exempt} THEN RETURN NULL; END IF;"
            "  IF EXISTS (SELECT 1 FROM {schema}.reference_clock_floor_v1 WHERE hold_at_us IS NOT NULL) THEN"
            "   RAISE EXCEPTION 'recovery hold: authority writes are refused' USING ERRCODE = 'RH001';"
            "  END IF;"
            "  RETURN NULL;"
            " END $$").format(schema=sql.Identifier(schema), exempt=exempt))
        tables = [row[0] for row in connection.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
            " ORDER BY c.relname").fetchall()]
        _install_floor_guard(connection, recovery_login)
        guarded = []
        for table in tables:
            if table in HOLD_ALLOWLIST:
                continue
            name = sql.Identifier(table)
            connection.execute(sql.SQL("DROP TRIGGER IF EXISTS {} ON {}").format(sql.Identifier(HOLD_GUARD), name))
            connection.execute(sql.SQL(
                "CREATE TRIGGER {} BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {}"
                " FOR EACH STATEMENT EXECUTE FUNCTION reference_recovery_hold_guard_v1()"
            ).format(sql.Identifier(HOLD_GUARD), name))
            # Fires even under session_replication_role = replica.
            connection.execute(sql.SQL("ALTER TABLE {} ENABLE ALWAYS TRIGGER {}").format(name, sql.Identifier(HOLD_GUARD)))
            guarded.append(table)
    return guarded


# Largest floor this process has committed, per floor store (domain, database,
# schema). A stored floor below it means the database went backwards under this
# process: a rollback or a restore that kept the system identifier.
_SENTINEL_LOCK = threading.Lock()
_HIGHWATER: dict[tuple[str, str, str], int] = {}
# One lock per sentinel path in this process, and an OS file lock across processes: every reader and writer of a
# path runs alone, so no domain's high-water can be lost to another writer's replace (review finding 4e180f93).
_PATH_LOCKS: dict[str, threading.Lock] = {}


def _replace_with_retry(staging: Path, target: Path) -> None:
    """os.replace, retried briefly on Windows sharing violations (a scanner or indexer holding the file open)."""
    for attempt in range(40):
        try:
            os.replace(staging, target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == 39:
                raise
            time.sleep(0.05)


SENTINEL_LOCK_TIMEOUT_S = 30.0
_CONTENTION_ERRNOS = {13, 11, 35, 36}  # EACCES, EAGAIN/EWOULDBLOCK (Linux/macOS), EDEADLK (Windows locking)


def _os_try_lock(handle) -> bool:
    """One non-blocking attempt. False means another holder; any other failure raises at once."""
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as failed:
        if isinstance(failed, BlockingIOError) or failed.errno in _CONTENTION_ERRNOS:
            return False
        raise


def _os_unlock(handle) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _sentinel_path_lock(path: Path, timeout_s: float | None = None):
    """Exclusive use of a sentinel path, in this process and across processes, for at most ``timeout_s``.

    Availability contract: contention is waited out up to the timeout, then ClockError; any other lock failure
    raises ClockError at once. Callers therefore never hang: the constructor fails closed, and the heartbeat
    records the failure (see DurableClock.sentinel_failures) and tries again on its next beat.
    """
    deadline = time.monotonic() + (SENTINEL_LOCK_TIMEOUT_S if timeout_s is None else timeout_s)
    with _SENTINEL_LOCK:
        lock = _PATH_LOCKS.setdefault(os.path.normcase(str(path.resolve())), threading.Lock())
    if not lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
        raise ClockError("sentinel file lock not acquired in time (in-process holder)")
    try:
        with open(path.with_name(path.name + ".lock"), "a+b") as handle:
            try:
                while not _os_try_lock(handle):
                    if time.monotonic() >= deadline:
                        raise ClockError("sentinel file lock not acquired in time (another process holds it)")
                    time.sleep(0.01)
            except OSError as failed:
                raise ClockError(f"sentinel file lock unavailable: {failed}") from failed
            try:
                yield
            finally:
                _os_unlock(handle)
    finally:
        lock.release()

ROLLBACK_REASON = "database state regressed below a committed floor"
WITNESS_REASON = "restored floor predates the latest witnessed head"


class DurableClock:
    """Publish readings only after a separate floor transaction commits.

    The floor pool must provide a separate connection from any caller transaction.
    Sampling happens after taking the floor row lock, so concurrent readers are
    ordered by sampling rather than by when their requests started. A caller's
    rollback cannot undo a returned reading's floor. Runtime reads never create a
    missing row. Database administration and physical UTC accuracy remain outside
    this contract; this floor cannot prevent effects after physical expiry.
    Each read opens a separate connection and serializes on one row: a reference
    correctness tradeoff, not a qualified high-throughput clock service.
    """

    def __init__(self, source: ConnectionClock, *, floor_pool: Any,
                 max_permit_lifetime_us: int | None = None, sentinel_file: str | Path | None = None,
                 arming: Any = None, recovery_not_used_reason: str | None = None) -> None:
        if not isinstance(source, ConnectionClock):
            raise TypeError("a connection-bound authority clock is required")
        if max_permit_lifetime_us is not None and (type(max_permit_lifetime_us) is not int
                                                   or max_permit_lifetime_us <= 0):
            raise ValueError("a maximum permit lifetime must be a positive number of microseconds")
        ClockReading(source.domain, 0)
        self.source = source
        self.floor_pool = floor_pool
        self._domain = source.domain
        # Receivers reading through this clock refuse longer-lived permits; the recovery
        # quarantine is this bound after the hold.
        self.max_permit_lifetime_us = max_permit_lifetime_us
        # The process high-water survives a restart on this host when a sentinel file is configured.
        self._sentinel_file = Path(sentinel_file) if sentinel_file is not None else None
        self._sentinel_lock = threading.Lock()
        self._heartbeat: threading.Thread | None = None
        self._stop = threading.Event()
        if self._sentinel_file is not None:
            with _sentinel_path_lock(self._sentinel_file):
                stored = (json.loads(self._sentinel_file.read_text(encoding="utf-8"))
                          if self._sentinel_file.exists() else [])
            for domain, database, schema, value in stored:
                if type(value) is not int:
                    raise ClockError("sentinel file is malformed")
                with _SENTINEL_LOCK:
                    key = (domain, database, schema)
                    _HIGHWATER[key] = max(_HIGHWATER.get(key, 0), value)
        # With arming configured, the first read checks the stored floor against the witnesses' latest head
        # time; until that succeeds every read refuses (unarmed means held for this process).
        self._arming = arming
        self._armed = arming is None
        if recovery_not_used_reason is not None and (
                not isinstance(recovery_not_used_reason, str) or not 1 <= len(recovery_not_used_reason) <= 256
                or recovery_not_used_reason != recovery_not_used_reason.strip()):
            raise ValueError("recovery non-use needs a short explicit reason")
        self.recovery_not_used_reason = recovery_not_used_reason
        register_authority_write_hook(self)

    @property
    def domain(self) -> str:
        return self._domain

    def read(self) -> ClockReading:
        return self._read(None)

    def read_on(self, connection: Any) -> ClockReading:
        if connection is None:
            raise ClockError("a caller connection is required")
        return self._read(connection)

    def now_us(self) -> int:
        return self.read().now_us

    @property
    def recovery_configured(self) -> bool:
        """The full R-2b profile: a lifetime bound, witness arming, a running heartbeat and a sentinel file."""
        return (self.max_permit_lifetime_us is not None and self._arming is not None
                and self._heartbeat is not None and self._heartbeat.is_alive()
                and self._sentinel_file is not None)

    @property
    def sentinel_failures(self) -> int:
        """Heartbeat beats whose sentinel write failed (lock timeout, I/O error). Logged; never silent."""
        return getattr(self, "_sentinel_failures", 0)

    def sentinel_tick(self) -> None:
        """One floor read after a committed negative-authority write: a later rollback past it is detected."""
        try:
            self.read()
        finally:
            self._persist()

    def start_heartbeat(self, interval_s: float = 1.0) -> None:
        """Read the floor at least every ``interval_s`` so an idle process still detects a rollback.

        The interval is the detection bound stated for R-2b. Readings and refusals are not returned anywhere;
        a detected rollback is recorded as the hold in the floor row.
        """
        if type(interval_s) not in (int, float) or not 0 < interval_s <= 60:
            raise ValueError("a heartbeat interval between 0 and 60 seconds is required")
        if self._heartbeat is not None:
            raise ValueError("the heartbeat is already running")
        self._stop.clear()

        def beat() -> None:
            while not self._stop.wait(interval_s):
                try:
                    self.read()
                except Exception:
                    pass  # a hold, an unavailable floor or a closed pool: the next beat tries again
                try:
                    self._persist()
                except Exception as failed:  # counted and logged; the next beat tries again
                    self._sentinel_failures = getattr(self, "_sentinel_failures", 0) + 1
                    import logging
                    logging.getLogger("assurance_reference.recovery").warning(
                        "sentinel file write failed (%d so far): %s", self._sentinel_failures, failed)

        self._heartbeat = threading.Thread(target=beat, name="durable-clock-heartbeat", daemon=True)
        self._heartbeat.start()

    def stop_heartbeat(self) -> None:
        if self._heartbeat is not None:
            self._stop.set()
            self._heartbeat.join(timeout=10)
            self._heartbeat = None

    def _persist(self) -> None:
        """Write the high-water only when it rose; other domains' rows in the same file are kept."""
        if self._sentinel_file is None:
            return
        with _SENTINEL_LOCK:
            mine = {key: value for key, value in _HIGHWATER.items() if key[0] == self.domain}
        with self._sentinel_lock, _sentinel_path_lock(self._sentinel_file):
            if mine == getattr(self, "_persisted", None):
                return
            rows = {}
            if self._sentinel_file.exists():
                for domain, database, schema, value in json.loads(self._sentinel_file.read_text(encoding="utf-8")):
                    rows[(domain, database, schema)] = value
            for key, value in mine.items():
                rows[key] = max(rows.get(key, 0), value)
            staging = self._sentinel_file.with_name(f"{self._sentinel_file.name}.{os.getpid()}.{id(self)}.tmp")
            with open(staging, "w", encoding="utf-8") as handle:
                json.dump(sorted([*key, value] for key, value in rows.items()), handle)
                handle.flush()
                os.fsync(handle.fileno())
            _replace_with_retry(staging, self._sentinel_file)
            self._persisted = mine

    def _read_for_ceremony(self) -> ClockReading:
        """For ResumptionAuthority only, after it verified the signed ceremony: an existing hold does not refuse it.

        A new regression detected by this read still refuses. The reading is published only after its floor
        commit, like every other reading; the ceremony itself is verified and applied elsewhere.
        """
        return self._read(None, ceremony=True)

    def _read(self, caller: Any, *, ceremony: bool = False) -> ClockReading:
        source = self.source
        witnessed = None if self._armed else self._arming.lower_bound(self.domain)
        # The exact DbClock path sends one explicit transaction in two pipelines
        # on the pool's autocommit connection: BEGIN, the timeouts, the row lock
        # and the queued sample share one round trip; the UPDATE and COMMIT share
        # the other. PostgreSQL executes queued statements in order, so the
        # sample still follows the lock. No other code runs on the floor
        # connection in between. Any other source runs inside psycopg's
        # transaction() and samples outside pipeline mode; because a source can
        # end a transaction with SQL text as well as with commit() or rollback(),
        # the floor's transaction id is re-checked after the source has run.
        exact = type(source) is DbClock
        try:
            with self.floor_pool.connection() as connection:
                if connection is caller:
                    raise ClockError("clock floor must commit independently of the caller")
                if connection.info.transaction_status is not TransactionStatus.IDLE:
                    raise ClockError("clock floor connection is not idle")
                sampled = None
                committed = None
                try:
                    with nullcontext() if exact else connection.transaction():
                        with connection.pipeline():
                            if exact:
                                connection.execute("BEGIN")
                            connection.execute("SET LOCAL lock_timeout = '5s'")
                            connection.execute("SET LOCAL statement_timeout = '5s'")
                            cursor = connection.execute(
                                "SELECT highwater_us, hold_at_us, hold_reason, current_database(),"
                                " current_schema() FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE",
                                (self.domain,),
                            )
                            if exact:
                                sampled = source._queue_read_on(connection)
                            else:
                                locked_by = connection.execute("SELECT pg_current_xact_id_if_assigned()")
                        row = cursor.fetchone()
                        if row is None:
                            raise ClockError("clock floor has not been explicitly provisioned")
                        floor, held, store = row[0], row[1] is not None, (self.domain, row[3], row[4])
                        hold_reason = row[2]
                        with _SENTINEL_LOCK:
                            seen = _HIGHWATER.get(store)
                        rolled_back = seen is not None and floor < seen
                        predates_witness = witnessed is not None and floor < witnessed
                        stored = (source._finish_read(sampled) if exact
                                  else read_clock(source, connection=connection))
                        reading = stored if caller is None else read_clock(source, connection=caller)
                        if stored.domain != self.domain or reading.domain != self.domain:
                            raise ClockError("clock source changed its configured domain")
                        regressed = stored.now_us < floor or reading.now_us < max(floor, stored.now_us)
                        # A detected rollback commits the hold with this transaction;
                        # the floor is restored to the largest value ever committed.
                        new_floor = max(floor, seen or 0, stored.now_us, reading.now_us)
                        # The server computes the hold time; the bound passed is the largest value this process
                        # knows the lost timeline reached (it can only lengthen the quarantine).
                        bound = max(seen or 0, witnessed or 0)
                        if held:
                            hold = (None, None)
                        elif rolled_back:
                            hold = (bound, ROLLBACK_REASON)
                        elif predates_witness:
                            hold = (bound, WITNESS_REASON)
                        else:
                            hold = (None, None)
                        if not exact:
                            # The row lock assigned this transaction its id; a source
                            # that ended or replaced the transaction cannot keep it.
                            holder = locked_by.fetchone()[0]
                            current = connection.execute("SELECT pg_current_xact_id_if_assigned()").fetchone()[0]
                            if holder is None or current != holder:
                                raise ClockError("clock source ended the floor transaction")
                        # Retain every larger observed value even when a later sample
                        # regresses. Raise only after this transaction commits.
                        with connection.pipeline() if exact else nullcontext():
                            connection.execute(
                                "UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                                (new_floor, self.domain),
                            )
                            if hold[1] is not None:
                                connection.execute("SELECT reference_clock_floor_hold_v1(%s, %s, %s)",
                                                   (self.domain, hold[1], hold[0]))
                            if exact:
                                committed = connection.execute("COMMIT")
                    # The reading is published only once the floor commit has
                    # completed: the server must report COMMIT (an aborted
                    # transaction reports ROLLBACK) and the session must be idle.
                    if exact and (committed.statusmessage != "COMMIT"
                                  or connection.info.transaction_status is not TransactionStatus.IDLE):
                        raise ClockError("clock floor commit did not complete")
                except BaseException:
                    # transaction() rolls back the other path; the explicit
                    # transaction is ended here rather than left to the pool.
                    if exact and connection.info.transaction_status is not TransactionStatus.IDLE:
                        with suppress(Error):
                            connection.rollback()
                    raise
        except Error as exc:
            raise ClockError("durable clock floor is unavailable") from exc
        with _SENTINEL_LOCK:
            _HIGHWATER[store] = max(_HIGHWATER.get(store, 0), new_floor)
        if (held and not ceremony) or rolled_back or predates_witness:
            raise ClockError("recovery hold: " + (hold_reason or hold[1] or ROLLBACK_REASON))
        self._armed = True
        if regressed:
            raise ClockError("authority clock regressed below the durable floor")
        return reading
