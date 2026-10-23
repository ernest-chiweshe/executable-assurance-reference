"""Synthetic connection observations with real record/hash/signature checks.

These contracts do not qualify PostgreSQL locking, RLS, durability or concurrency.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import json
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

import pytest
from psycopg.pq import TransactionStatus

from assurance_reference.decision_transaction import locked_decision_transaction
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (Action, ActionEffect, Actor, Assertion, Decision,
                            Ed25519Signer, PolicyContext, PolicyRef, TrustDirectory)
from regulated_core.canonical import digest_hex
from regulated_core.clock import ClockError, ClockReading


class ObservedConnection:
    def __init__(self):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.events, self.rows = [], []
        self.isolation = "read committed"

    @contextmanager
    def transaction(self):
        prior = list(self.rows)
        self.info.transaction_status = TransactionStatus.INTRANS
        self.events.append("begin")
        try:
            yield self
        except BaseException:
            self.rows = prior
            self.events.append("rollback")
            raise
        else:
            self.events.append("commit")
        finally:
            self.info.transaction_status = TransactionStatus.IDLE

    def execute(self, sql, params=()):
        if sql == "SHOW transaction_isolation":
            value = (self.isolation,)
        elif sql.startswith("SELECT set_config"):
            self.events.append("tenant")
            value = None
        elif sql.startswith("SELECT pg_advisory_xact_lock"):
            self.events.append("lock")
            assert params == ("regulated-evidence-v1:fixture",)
            value = None
        elif sql.startswith("SELECT seq, entry_hash, envelope"):
            value = self.rows[-1] if self.rows else None
        elif sql.startswith("INSERT INTO regulated_decision_evidence_v1"):
            tenant, seq, entry_hash, raw = params
            assert tenant == "fixture"
            self.rows.append((seq, entry_hash, json.loads(raw)))
            self.events.append("insert")
            value = None
        else:
            raise AssertionError(sql)
        return SimpleNamespace(fetchone=lambda: value)


class ObservedClock:
    domain = "fixture:decision-transaction"

    def __init__(self, connection):
        self.connection = connection

    def read(self):
        raise AssertionError("decision recording must use its owned connection")

    def now_us(self):
        return self.read().now_us

    def read_on(self, connection):
        assert connection is self.connection
        assert connection.info.transaction_status == TransactionStatus.INTRANS
        connection.events.append("clock")
        return ClockReading(self.domain, 1000)


@pytest.fixture
def setup():
    conn = ObservedConnection()
    pool = SimpleNamespace(connection=lambda: nullcontext(conn))
    clock = ObservedClock(conn)
    signer, trust = Ed25519Signer("fixture:decision-evidence"), TrustDirectory()
    trust.register_signer(signer)
    recorder = ReferenceDecisionRecorder(signer, trust, pool=pool, clock=clock)
    context = PolicyContext("fixture", Actor("reviewer", "fixture", frozenset()),
                            "review", "request", 7)
    return conn, recorder, context


def record(scope, ctx):
    return scope.record(Assertion("synthetic", "fixture", "course:lesson", "a" * 64),
                        Action("course:review", ActionEffect.REVERSIBLE), ctx,
                        PolicyRef("course", "fixture", "1"),
                        Decision.deny("REVIEW_PENDING", "Synthetic ordinary refusal"))


def test_time_chosen_after_lock_before_hash_and_commit(setup):
    conn, recorder, original = setup
    with locked_decision_transaction(recorder, "fixture") as scope:
        ctx = scope.context(original)
        assert original.now_us == 7 and ctx.now_us == 1000
        envelope = record(scope, ctx)
        assert envelope.record.decided_at_us == 1000
        assert envelope.record_hash == digest_hex(envelope.record)
        assert scope.verify_entry(envelope)
        assert conn.events[:4] == ["begin", "tenant", "lock", "clock"]
        assert "commit" not in conn.events
    assert conn.events[-1] == "commit"
    assert recorder.verify_entry(envelope)
    with pytest.raises(ClockError, match="not active"):
        record(scope, ctx)


@pytest.mark.parametrize("change", ["tenant", "time"])
def test_context_mismatch_refuses_before_append(setup, change):
    conn, recorder, original = setup
    with locked_decision_transaction(recorder, "fixture") as scope:
        ctx = scope.context(original)
        bad = replace(ctx, tenant_id="another", actor=replace(ctx.actor, tenant_id="another")) if change == "tenant" else replace(ctx, now_us=999)
        with pytest.raises(ClockError, match="locked reading"):
            record(scope, bad)
        assert conn.rows == []
        with pytest.raises(ClockError, match="locked tenant"):
            scope.context(replace(original, tenant_id="another", actor=replace(original.actor, tenant_id="another")))


def test_exception_rolls_back_and_invalidates_recorder_view(setup):
    conn, recorder, original = setup
    with pytest.raises(RuntimeError, match="ordinary callback failure"):
        with locked_decision_transaction(recorder, "fixture") as scope:
            ctx = scope.context(original)
            record(scope, ctx)
            raise RuntimeError("ordinary callback failure")
    assert conn.rows == [] and conn.events[-1] == "rollback"
    with pytest.raises(ClockError, match="not active"):
        scope.verify_entry(None)


def test_view_cannot_cross_threads(setup):
    conn, recorder, original = setup
    with locked_decision_transaction(recorder, "fixture") as scope:
        ctx = scope.context(original)
        with ThreadPoolExecutor(max_workers=1) as worker:
            with pytest.raises(ClockError, match="owning thread"):
                worker.submit(record, scope, ctx).result()
        assert conn.rows == []


@pytest.mark.parametrize("state", ["already-active", "wrong-isolation"])
def test_ownership_and_isolation_refuse_before_clock(setup, state):
    conn, recorder, _ = setup
    if state == "already-active":
        conn.info.transaction_status = TransactionStatus.INTRANS
    else:
        conn.isolation = "repeatable read"
    with pytest.raises(ClockError):
        with locked_decision_transaction(recorder, "fixture"):
            raise AssertionError("must not enter")
    assert "clock" not in conn.events and not conn.rows


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("operation", ["context", "record", "verify"])
def test_exited_view_stays_invalid_when_connection_enters_another_transaction(setup, fails, operation):
    conn, recorder, original = setup
    try:
        with locked_decision_transaction(recorder, "fixture") as scope:
            ctx = scope.context(original)
            envelope = record(scope, ctx)
            if fails:
                raise RuntimeError("ordinary transaction failure")
    except RuntimeError:
        assert fails
    # Pool reuse can make the same connection INTRANS again; the old view
    # must still have ended regardless of this new owner's connection state.
    with conn.transaction():
        with pytest.raises(ClockError, match="not active"):
            if operation == "context":
                scope.context(original)
            elif operation == "record":
                record(scope, ctx)
            else:
                scope.verify_entry(envelope)
