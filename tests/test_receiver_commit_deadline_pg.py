"""R-1b: the server refuses, inside COMMIT, a database effect whose deadline has passed after the last check.

The stall between the receiver's last Python check and COMMIT is produced by wrapping that last check: it returns
its genuine pre-deadline reading and then either waits past the deadline or raises the durable floor to it. Only
the deferred trigger can then refuse. Isolated PostgreSQL; the receiver runs under its fixture login.
"""
import time

import pytest

import regulated_core.database_receiver_pg as receiver_module
from regulated_core.database_receiver_pg import PostgresTargetReceiver
from regulated_core.target import Outcome
from versioned_cas_pg_fixture import BODY, OLD, prepared_cas_fixture, snapshot


def _stall_last_check(monkeypatch, then):
    """The receiver calls require_permit_clock at admission and after the effect; stall after the second call."""
    original = receiver_module.require_permit_clock
    calls = []

    def wrapped(permit, clock, **kwargs):
        reading = original(permit, clock, **kwargs)
        calls.append(reading)
        if len(calls) == 2:
            then(permit, reading)
        return reading

    monkeypatch.setattr(receiver_module, "require_permit_clock", wrapped)
    return calls


def _receipt(f):
    with f["pool"].connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
        return conn.execute("SELECT outcome, deadline_us, clock_domain FROM regulated_database_receipts_v1"
                            " WHERE tenant=%s AND nonce=%s", (f["tenant"], f["nonce"])).fetchall()


def test_a_committed_receipt_carries_its_deadline_and_domain(tmp_path):
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.COMMITTED, result
    [(outcome, deadline, domain)] = _receipt(f)
    assert outcome == "committed" and domain == f["authority"].clock.domain
    assert 0 < deadline <= f["signed"].permit.expires_at_us


def test_a_stall_past_the_deadline_before_commit_is_refused_by_the_server(tmp_path, monkeypatch):
    f = prepared_cas_fixture(tmp_path, admission_window_us=3_000_000)

    def wait_past(permit, reading):
        deadline = min(permit.expires_at_us, reading.now_us + 3_000_000)
        time.sleep(max(0, deadline - reading.now_us) / 1e6 + 0.3)

    calls = _stall_last_check(monkeypatch, wait_past)
    result = f["receiver"].commit(f["signed"], BODY)
    assert len(calls) == 2  # the Python checks both passed; only the trigger could refuse
    assert result.outcome is Outcome.FAILED, result
    assert "authority expired at database commit" in result.detail
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}


def test_a_floor_at_exactly_the_deadline_is_refused(tmp_path, monkeypatch):
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    admitted = []
    admit = PostgresTargetReceiver._admit_on

    def recording_admit(self, conn, signed):
        admitted.append(admit(self, conn, signed))  # the exact deadline the receiver will store
        return admitted[-1]

    monkeypatch.setattr(PostgresTargetReceiver, "_admit_on", recording_admit)

    def raise_floor_to_deadline(permit, reading):
        with f["pool"].connection() as conn, conn.transaction():
            conn.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                         (admitted[-1], f["authority"].clock.domain))

    _stall_last_check(monkeypatch, raise_floor_to_deadline)
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "authority expired at database commit" in result.detail
    assert snapshot(f)["uses"] == 0 and snapshot(f)["budget"] == 0


def _with_effect(f, before=None, after=None):
    original = f["receiver"]._effect

    class Effect:
        tenant_id, target, operation = original.tenant_id, original.target, original.operation

        def current_state_on(self, conn):
            return original.current_state_on(conn)

        def apply_on(self, conn, output):
            if before:
                before(conn)
            state = original.apply_on(conn, output)
            if after:
                after(conn)
            return state

    return PostgresTargetReceiver(pool=f["pool"], authority=f["authority"], effect=Effect(),
                                  admission=f["receiver"]._admission)


def test_set_constraints_immediate_in_host_effect_code_does_not_bypass_the_check(tmp_path, monkeypatch):
    f = prepared_cas_fixture(tmp_path, admission_window_us=3_000_000)
    receiver = _with_effect(f, before=lambda conn: conn.execute("SET CONSTRAINTS ALL IMMEDIATE"))

    def wait_past(permit, reading):
        time.sleep(3.3)

    _stall_last_check(monkeypatch, wait_past)
    result = receiver.commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "authority expired at database commit" in result.detail
    assert snapshot(f)["uses"] == 0


def test_host_effect_code_that_commits_the_transaction_is_unknown_never_tombstoned(tmp_path):
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    receiver = _with_effect(f, after=lambda conn: conn.execute("COMMIT"))  # writes the effect, then commits it
    result = receiver.commit(f["signed"], BODY)
    assert result.outcome is Outcome.UNKNOWN, result
    assert "ended or replaced" in result.detail
    assert "not_committed" not in snapshot(f)["outcomes"]  # the reservation is not released


@pytest.mark.parametrize("domain", ["pg:another-cluster", None])
def test_a_committed_receipt_naming_another_clock_domain_is_refused_by_the_server(tmp_path, monkeypatch, domain):
    # The deadline must be judged on this cluster's clock: a receipt carrying another domain's (or no) clock
    # domain cannot commit, whatever its deadline.
    from psycopg import sql as _sql
    from regulated_core.canonical import digest_hex
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    original = PostgresTargetReceiver._finish

    def finish(self, conn, signed, outcome, state="", deadline_us=None, schema=None):
        if outcome is not Outcome.COMMITTED:
            return original(self, conn, signed, outcome, state, deadline_us, schema)
        p = signed.permit
        table = (_sql.SQL("{}.regulated_database_receipts_v1").format(_sql.Identifier(schema)) if schema
                 else _sql.SQL("regulated_database_receipts_v1"))
        conn.execute(_sql.SQL("INSERT INTO {} (tenant,nonce,permit_digest,outcome,target_state,deadline_us,"
                              "clock_domain) VALUES (%s,%s,%s,%s,%s,%s,%s)").format(table),
                     (p.tenant_id, p.nonce, digest_hex(p.signed_body()), outcome.value, state, deadline_us, domain))

    monkeypatch.setattr(PostgresTargetReceiver, "_finish", finish)
    result = f["receiver"].commit(f["signed"], BODY)
    assert result.outcome is Outcome.FAILED, result
    assert "database commit" in result.detail  # the receiver reports every RC1B0 refusal this way
    assert snapshot(f)["state"] == (3, OLD) and snapshot(f)["uses"] == 0


def test_a_missing_durable_floor_at_commit_is_refused_by_the_server(tmp_path, monkeypatch):
    # The floor row for this cluster vanishes between the last Python check and COMMIT (as a restore that predates
    # the floor would leave it): the server must refuse rather than judge on the bare cluster clock.
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)

    def drop_floor(permit, reading):
        with f["pool"].connection() as conn, conn.transaction():
            conn.execute("SET LOCAL session_replication_role = replica")  # a restore writes without triggers
            conn.execute("DELETE FROM reference_clock_floor_v1 WHERE domain = %s", (f["authority"].clock.domain,))

    calls = _stall_last_check(monkeypatch, drop_floor)
    result = f["receiver"].commit(f["signed"], BODY)
    assert len(calls) == 2
    assert result.outcome is Outcome.FAILED, result
    assert snapshot(f)["state"] == (3, OLD) and snapshot(f)["uses"] == 0


def test_a_receiver_session_not_at_read_committed_cannot_commit(tmp_path, monkeypatch):
    # A pool whose sessions default to REPEATABLE READ: the commit must be refused, never judged on an old snapshot.
    from contextlib import contextmanager
    f = prepared_cas_fixture(tmp_path, admission_window_us=30_000_000)
    receiver = f["receiver"]
    pool = receiver._pool
    original = type(pool).connection

    @contextmanager
    def repeatable(self, *args, **kwargs):
        with original(self, *args, **kwargs) as conn:
            conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            if conn.info.transaction_status != 0:
                conn.commit()
            yield conn

    monkeypatch.setattr(type(pool), "connection", repeatable)
    result = receiver.commit(f["signed"], BODY)
    monkeypatch.undo()
    print("REPEATABLE-READ refusal:", result.detail)
    assert result.outcome is Outcome.FAILED, result
    assert snapshot(f)["state"] == (3, OLD) and snapshot(f)["uses"] == 0
