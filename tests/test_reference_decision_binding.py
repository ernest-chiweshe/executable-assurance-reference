"""Intact reference engine composition with synthetic SQL observations.

Real policy, capability, evidence signatures, budget and permit guards run.
PostgreSQL isolation, RLS and concurrent availability require separate validation.
"""
from contextlib import contextmanager, nullcontext
import hashlib
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from assurance_reference.alerts import AlertJournal
from assurance_reference.engine import ReferenceEngine
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry,
    PolicyContext, PolicyRegistry, PreflightAuthority, TrustDirectory, VerificationTrustStore,
)
from regulated_core.clock import ClockReading
from regulated_core.permit import InMemoryPermitUseStore
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, effect_destination
from test_decision_transaction_contract import ObservedConnection
from test_education_record_outage import CountingSigner
from test_prepermit_retention import BudgetedCoursePolicy
from test_reference_retention_contract import UnusedAlertPool


class Connection(ObservedConnection):
    fail_commit = False
    on_lock = None

    def execute(self, sql, params=()):
        result = super().execute(sql, params)
        if sql.startswith("SELECT pg_advisory_xact_lock") and self.on_lock is not None:
            self.on_lock()
            self.on_lock = None
        return result

    @contextmanager
    def transaction(self):
        with super().transaction():
            yield self
            if self.fail_commit:
                self.fail_commit = False
                raise RuntimeError("synthetic database commit failure")


class Clock:
    domain = "fixture:binding"

    def __init__(self, conn):
        self.conn, self.value = conn, 1000

    def read(self):
        assert self.conn.info.transaction_status == TransactionStatus.IDLE
        self.conn.events.append("live-clock")
        return ClockReading(self.domain, self.value)

    def now_us(self):
        return self.read().now_us

    def read_on(self, connection):
        assert connection is self.conn
        assert connection.info.transaction_status == TransactionStatus.INTRANS
        connection.events.append("clock")
        return ClockReading(self.domain, self.value)


@pytest.fixture
def composed(tmp_path):
    conn, trust = Connection(), TrustDirectory()
    clock = Clock(conn)
    keys = {r: Ed25519Signer("binding:" + r) for r in
            ("evidence", "approval", "identity", "preflight", "alert")}
    signer = CountingSigner("binding:permit")
    for key in (*keys.values(), signer):
        trust.register_signer(key)
    recorder = ReferenceDecisionRecorder(keys["evidence"], trust,
        pool=SimpleNamespace(connection=lambda: nullcontext(conn)), clock=clock)
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(BudgetedCoursePolicy())
    operation = "course:render-lesson"
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(keys["preflight"], intended, trust)
    uses = InMemoryPermitUseStore()
    engine = ReferenceEngine(alerts=AlertJournal(UnusedAlertPool(), keys["alert"], trust),
        registry=registry, recorder=recorder, verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, keys["approval"], IdentityVerifier(trust, keys["identity"].key_id)),
        emission=EmissionAuthority(signer, trust, uses), preflight=preflight, clock=clock)
    target = FilesystemTargetAdapter(path=tmp_path / "draft.txt", tenant_id="fixture",
        authority=engine.targets, uses=uses, operation_name=operation)
    body = b"Ordinary reversible synthetic course draft."
    digest = hashlib.sha256(body).hexdigest()
    cap = preflight.authorize(tenant_id="fixture", vertical="course", action_id=operation,
        risk_tier=1, correlation_id="draft", now_us=0, ttl_us=1000, nonce="cap")
    params = dict(vertical="course", capability=cap,
        assertion=Assertion("draft", "fixture", "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination({},
            BoundEffect(digest, target.target, target.current_state(), mission="binding:mission"))),
        ctx=PolicyContext("fixture", Actor("author", "fixture", frozenset()), "draft", "draft", 7),
        output=body, target=target, permit_ttl_us=1000)

    def retain():
        assert conn.info.transaction_status == TransactionStatus.IDLE
        assert conn.events[-1] == "commit"
        assert conn.rows and signer.calls == 0
        conn.events.append("retained")
    params["retain_before_permit"] = retain
    return conn, clock, engine, params, signer


def test_actual_pipeline_commits_before_retention_and_live_issuance(composed):
    conn, clock, engine, params, signer = composed
    result = engine.authorize_for_target(**params, nonce="first")
    assert result.authorized and signer.calls == 1
    assert result.ctx.now_us == result.envelope.record.decided_at_us == 1000
    assert params["ctx"].now_us == 7
    assert conn.events.index("commit") < conn.events.index("retained")
    assert "live-clock" in conn.events[conn.events.index("retained") + 1:]
    assert not hasattr(engine, "_decision_scope")
    assert isinstance(engine._recorder, ReferenceDecisionRecorder)
    assert not params["target"].path.exists()


def test_capability_expiring_while_waiting_for_lock_is_recorded_refusal(composed):
    conn, clock, engine, params, signer = composed
    conn.on_lock = lambda: setattr(clock, "value", 2000)
    result = engine.authorize_for_target(**params, nonce="expired")
    assert not result.authorized and result.permit is None
    assert result.envelope.record.decision.reason_codes == ("PREFLIGHT_INVALID",)
    assert result.envelope.record.decided_at_us == 2000
    assert signer.calls == 0 and "retained" not in conn.events
    assert conn.events[-1] == "commit"


def test_expiry_during_retention_uses_live_clock_and_new_refusal_transaction(composed):
    conn, clock, engine, params, signer = composed
    original = params["retain_before_permit"]
    def retain():
        original()
        clock.value = 2000
    params["retain_before_permit"] = retain
    result = engine.authorize_for_target(**params, nonce="expired-later")
    assert not result.authorized and result.permit is None
    assert result.envelope.record.decision.reason_codes == ("AUTHORITY_WINDOW_CLOSED",)
    assert result.envelope.record.decided_at_us == 2000
    assert conn.events.count("commit") == 2
    assert not params["target"].path.exists()


def test_commit_failure_releases_unissued_reservation(composed):
    conn, clock, engine, params, signer = composed
    conn.fail_commit = True
    with pytest.raises(RuntimeError, match="database commit failure"):
        engine.authorize_for_target(**params, nonce="failed")
    assert not conn.rows and signer.calls == 0 and "retained" not in conn.events
    result = engine.authorize_for_target(**params, nonce="recovered")
    assert result.authorized and signer.calls == 1


def test_gate_refusal_uses_locked_time_and_preserves_caller(composed):
    conn, clock, engine, params, signer = composed
    env = engine.record_refusal(assertion=params["assertion"], action=params["action"],
        ctx=params["ctx"], code="REVIEW_PENDING", reason="Ordinary pending review")
    assert env.record.decided_at_us == 1000 and params["ctx"].now_us == 7
    assert signer.calls == 0 and conn.events[-1] == "commit"
