"""Benign alert persistence tests; no target effects or host clock changes."""

import json
import os
import uuid

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, AlertUnavailable, provision_alerts
from assurance_reference.demo import SchemaConnections
from regulated_core import Ed25519Signer, TrustDirectory
from regulated_core import (
    Action,
    ActionEffect,
    Actor,
    ApprovalWorkflow,
    Assertion,
    Decision,
    EmissionAuthority,
    IdentityVerifier,
    IntendedUseRegistry,
    PolicyContext,
    PolicyRef,
    PolicyRegistry,
    PreflightAuthority,
    VerificationTrustStore,
)
from regulated_core.clock import ClockError, ClockReading
from regulated_core.engine import TargetAuthorization
from regulated_core.persistence_pg import PostgresPermitUseStore, migrate
from regulated_core.permit import EmissionError
from regulated_core.target import Outcome, TargetRef, TargetResult
from assurance_reference.engine import ReferenceEngine
from assurance_reference.recorder import ReferenceDecisionRecorder


@pytest.fixture
def alert_case(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; database checks must not skip"
    assert conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        assert connection.execute("SELECT current_database()").fetchone()[0] == "factory_test"
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    (tmp_path / "retained-schema.json").write_text(json.dumps({"schema": schema}), encoding="utf-8")
    pool = SchemaConnections(dsn, schema)
    signer = Ed25519Signer("test:alert")
    trust = TrustDirectory()
    trust.register_signer(signer)
    return pool, signer, trust


def alert_fields():
    return dict(
        tenant_id="synthetic-school",
        decision_hash="a" * 64,
        permit_hash="b" * 64,
        code="TARGET_UNKNOWN",
        outcome="unknown",
    )


def test_signed_alert_survives_reconstruction_and_caller_rollback(alert_case):
    pool, signer, trust = alert_case
    provision_alerts(pool)
    journal = AlertJournal(pool, signer, trust)

    class RollBackCaller(Exception):
        pass

    with pytest.raises(RollBackCaller):
        with pool.connection() as caller, caller.transaction():
            alert_id = journal.append(**alert_fields())
            raise RollBackCaller
    # Neither append nor verification accepts a clock dependency. Unknown time
    # stays unknown in the signed record, even after reconstructing the reader.
    retained = AlertJournal(pool, signer, trust).read(alert_id, tenant_id="synthetic-school")
    assert retained["payload"]["authority_time_us"] is None
    assert retained["payload"]["requires_reconciliation"] is True
    assert retained["payload"]["decision_hash"] == "a" * 64
    assert retained["payload"]["permit_hash"] == "b" * 64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    serialized = json.dumps(retained["payload"], sort_keys=True, separators=(",", ":")).encode()
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
        bytes.fromhex(retained["signature"]["value"]), serialized
    )


def test_missing_alert_store_is_not_silently_created(alert_case):
    pool, signer, trust = alert_case
    with pytest.raises(AlertUnavailable):
        AlertJournal(pool, signer, trust).append(**alert_fields())
    with pool.connection() as connection:
        assert connection.execute("SELECT to_regclass('reference_alerts_v1')").fetchone()[0] is None


def test_untrusted_alert_signer_cannot_report_success(alert_case):
    pool, signer, _ = alert_case
    provision_alerts(pool)
    with pytest.raises(AlertUnavailable):
        AlertJournal(pool, signer, TrustDirectory()).append(**alert_fields())
    with pool.connection() as connection:
        assert connection.execute("SELECT count(*) FROM reference_alerts_v1").fetchone()[0] == 0


@pytest.fixture
def outcome_case(alert_case):
    """Real engine/recorder with a signed fixture; no target or effect is invoked."""
    pool, alert_signer, trust = alert_case
    provision_alerts(pool)
    migrate(pool)

    class FixtureClock:
        domain = "test:outcome-alert"
        unavailable = False

        def read(self):
            if self.unavailable:
                raise ClockError("synthetic unavailable clock")
            return ClockReading(self.domain, 100_000_000)

        def read_on(self, connection):
            return self.read()

        def now_us(self):
            return self.read().now_us

    clock = FixtureClock()
    signers = {
        role: Ed25519Signer("test:" + role)
        for role in ("evidence", "approval", "identity", "emission", "preflight")
    }
    for signer in signers.values():
        trust.register_signer(signer)
    journal = AlertJournal(pool, alert_signer, trust)
    recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    engine = ReferenceEngine(
        alerts=journal,
        registry=PolicyRegistry(),
        recorder=recorder,
        verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(
            trust, signers["approval"], IdentityVerifier(trust, "test:identity")
        ),
        emission=EmissionAuthority(signers["emission"], trust, PostgresPermitUseStore(pool=pool)),
        preflight=PreflightAuthority(signers["preflight"], IntendedUseRegistry(), trust),
        clock=clock,
    )
    tenant = "synthetic-school"
    assertion = Assertion("fixture", tenant, "course:lesson", "a" * 64)
    action = Action("test:record-outcome", ActionEffect.REVERSIBLE)
    ctx = PolicyContext(
        tenant, Actor("reviewer", tenant, frozenset()), "test", "test-alert", clock.now_us()
    )
    policy = PolicyRef("course", "fixture", "1")
    envelope = recorder.record(
        assertion, action, ctx, policy, Decision.allow("FIXTURE", "no effect")
    )
    permit = engine.targets.issue(
        envelope,
        b"fixture",
        target=TargetRef("test", "no-effect"),
        operation="test:record-outcome",
        expected_target_state="absent",
        principal="reviewer",
        approval_ref="fixture",
        qualification_digests=(),
        ttl_us=1_000_000,
        nonce=uuid.uuid4().hex,
    )
    authorization = TargetAuthorization(
        True, "", "allow", envelope, permit, assertion, action, ctx, policy
    )
    return engine, authorization, clock, pool, journal


def retained_alerts(pool, journal):
    with pool.connection() as connection:
        ids = connection.execute("SELECT alert_id FROM reference_alerts_v1").fetchall()
    return [journal.read(row[0], tenant_id="synthetic-school")["payload"] for row in ids]


def test_unknown_outcome_retains_alert_and_decision(outcome_case):
    engine, authorization, _, pool, journal = outcome_case
    result = engine._record_outcome(
        authorization, TargetResult(Outcome.UNKNOWN, "synthetic uncertainty"), reconciled=False
    )
    assert result.outcome is Outcome.UNKNOWN
    assert result.envelope.record.decision.reason_codes == ("OUTCOME_UNKNOWN",)
    alerts = retained_alerts(pool, journal)
    assert len(alerts) == 1
    assert alerts[0]["code"] == "TARGET_UNKNOWN"
    assert alerts[0]["decision_hash"] == authorization.envelope.record_hash


@pytest.mark.parametrize("outcome", [Outcome.UNKNOWN, Outcome.COMMITTED])
def test_unavailable_clock_does_not_erase_outcome_alert(outcome_case, outcome):
    engine, authorization, clock, pool, journal = outcome_case
    clock.unavailable = True
    with pytest.raises(EmissionError, match="clock"):
        engine._record_outcome(authorization, TargetResult(outcome), reconciled=False)
    alerts = retained_alerts(pool, journal)
    assert len(alerts) == 1
    assert alerts[0]["code"] == (
        "TARGET_UNKNOWN" if outcome is Outcome.UNKNOWN else "OUTCOME_RECORDING_FAILED"
    )
    assert alerts[0]["outcome"] == outcome.value
    assert alerts[0]["authority_time_us"] is None
