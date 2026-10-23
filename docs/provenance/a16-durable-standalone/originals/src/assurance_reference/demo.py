"""Produce an instructor-approved synthetic lesson and retained authority evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg

from factory.projectos.synthetic import EDUCATION, propose
from assurance_reference.application_binding import check_binding
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.alerts import AlertJournal, provision_alerts

from regulated_core import (
    Action,
    ActionEffect,
    Actor,
    ApprovalWorkflow,
    Assertion,
    CoursePolicy,
    Ed25519Signer,
    EmissionAuthority,
    IdentityVerifier,
    IntendedUse,
    IntendedUseRegistry,
    PolicyContext,
    PolicyRegistry,
    PreflightAuthority,
    TrustDirectory,
    VerificationTrustStore,
    canonical_bytes,
    issue_credential,
)
from regulated_core.clock_pg import DbClock
from regulated_core.models import DecisionKind
from regulated_core.persistence_pg import (
    PostgresPermitUseStore, PostgresMissionBudget,
    migrate,
)
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination

LESSON = propose(EDUCATION)


class SchemaConnections:
    """Open connections pinned to this run's newly created test schema."""

    def __init__(self, dsn: str, schema: str) -> None:
        self.dsn = dsn
        self.schema = schema

    @contextmanager
    def connection(self):
        """Yield a bounded connection without sharing tenant session state."""
        with psycopg.connect(
            self.dsn,
            autocommit=True,
            connect_timeout=5,
            options=f"-c search_path={self.schema}",
        ) as connection:
            yield connection


def run(output: Path, dsn: str) -> dict:
    """Retain an isolated local demonstration; refuse any non-test database."""
    check_binding(EDUCATION, CoursePolicy.ref)
    if conninfo_to_dict(dsn).get("dbname") != "factory_test":
        raise ValueError("the demonstration requires the standing factory_test database")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    schema = "test_reference_" + uuid.uuid4().hex
    pool = SchemaConnections(dsn, schema)
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        if connection.execute("SELECT current_database()").fetchone()[0] != "factory_test":
            raise ValueError("connected database is not factory_test")
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    # Retain ownership immediately, including if a later step fails.
    (output / "run.json").write_bytes(
        canonical_bytes(
            {
                "schema": schema,
                "database": "factory_test",
                "clock_domain": domain,
                "status": "STARTED",
                "schema_retained": True,
            }
        )
        + b"\n"
    )
    migrate(pool)
    # This isolated demonstration owns one synthetic login and schema. It is
    # not the restricted production allocator/receiver credential composition.
    with pool.connection() as connection:
        connection.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                           "SELECT session_user::text,kind FROM "
                           "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
    budget = PostgresMissionBudget(pool=pool)
    provision_alerts(pool)
    source_clock = DbClock(pool, domain)
    provision_floor(pool, source_clock)
    clock = DurableClock(source_clock, floor_pool=pool)
    trust = TrustDirectory()
    signers = {
        role: Ed25519Signer("demo:" + role)
        for role in ("evidence", "approval", "identity", "emission", "preflight", "alert")
    }
    for signer in signers.values():
        trust.register_signer(signer)
    recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    uses = PostgresPermitUseStore(pool=pool)
    approvals = ApprovalWorkflow(
        trust, signers["approval"], IdentityVerifier(trust, "demo:identity")
    )
    registry = PolicyRegistry()
    registry.register(CoursePolicy())
    intended = IntendedUseRegistry()
    operation = "course:publish-lesson"
    intended.declare(IntendedUse("course", operation, 2))
    preflight = PreflightAuthority(signers["preflight"], intended, trust)
    engine = ReferenceEngine(
        budget=budget, default_mission_budget={"limit": 1, "units": 1},
        retention=LocalRetentionStore(output / "retention"),
        alerts=AlertJournal(pool, signers["alert"], trust),
        registry=registry,
        recorder=recorder,
        verification_trust=VerificationTrustStore(trust),
        approvals=approvals,
        emission=EmissionAuthority(signers["emission"], trust, uses),
        preflight=preflight,
        clock=clock,
    )
    tenant = "synthetic-school"
    target = FilesystemTargetAdapter(
        path=output / "lesson.txt",
        tenant_id=tenant,
        authority=engine.targets,
        uses=uses,
        operation_name=operation, budget=budget,
    )
    now = clock.now_us()
    ttl = 60_000_000
    assertion = Assertion(
        assertion_id="fractions-lesson",
        tenant_id=tenant,
        content_type="course:lesson",
        content_digest=hashlib.sha256(LESSON).hexdigest(),
    )
    context = PolicyContext(
        tenant_id=tenant,
        actor=Actor("lesson-author", tenant, frozenset()),
        purpose="education:lesson-review",
        correlation_id="lesson-review",
        now_us=now,
    )
    action = Action(
        operation,
        ActionEffect.EXTERNAL,
        destination=effect_destination(
            {},
            BoundEffect(hashlib.sha256(LESSON).hexdigest(), target.target, target.current_state(),
                        mission="synthetic:lesson-publication"),
        ),
    )
    capability = preflight.authorize(
        tenant_id=tenant,
        vertical="course",
        action_id=operation,
        risk_tier=2,
        correlation_id=context.correlation_id,
        now_us=now,
        ttl_us=ttl,
        nonce="lesson-capability",
    )
    parameters = dict(
        vertical="course",
        capability=capability,
        assertion=assertion,
        action=action,
        ctx=context,
        output=LESSON,
        target=target,
        permit_ttl_us=ttl,
        nonce="lesson-release",
    )
    refused = engine.authorize_for_target(**parameters)
    if refused.authorized or target.path.exists():
        raise RuntimeError("missing approval did not refuse the effect")
    decision = next(
        entry
        for entry in reversed(recorder.entries(tenant))
        if entry.record.decision.kind is DecisionKind.REQUIRE_APPROVAL
    )
    requirement = decision.record.decision.approval
    request = approvals.open(
        request_id="instructor-review",
        requester_id=context.actor.actor_id,
        tenant_id=tenant,
        assertion_id=assertion.assertion_id,
        decision_record_id=decision.record.record_id,
        decision_record_hash=decision.record_hash,
        requirement=requirement,
        now_us=clock.now_us(),
    )
    credential = issue_credential(
        signers["identity"],
        actor_id="synthetic-instructor",
        tenant_id=tenant,
        kind="role:instructor",
        expires_at_us=now + ttl,
    )
    reviewer = Actor("synthetic-instructor", tenant, frozenset(), (credential,))
    grant = approvals.grant(request, reviewer, clock.now_us())
    certificate = approvals.finalize(request, [grant], clock.now_us())
    authorized = engine.authorize_for_target(
        **parameters,
        approval_cert=certificate,
        approval_evidence=decision,
    )
    if not authorized.authorized or authorized.permit is None:
        raise RuntimeError("approved lesson refused: " + authorized.reason)
    if target.path.exists() or not recorder.verify_entry(authorized.envelope):
        raise RuntimeError("prior evidence or no-effect-before-commit check failed")
    result = engine.commit(authorized, LESSON, target)
    if result.outcome is not Outcome.COMMITTED or target.path.read_bytes() != LESSON:
        raise RuntimeError("lesson effect was not certified: " + result.detail)
    restored = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    entries = restored.entries(tenant)
    if not restored.verify_chain(tenant) or not PostgresPermitUseStore(pool=pool).used(
        tenant, "lesson-release"
    ):
        raise RuntimeError("retained evidence or spent nonce could not be reread")
    retry_started_at = clock.now_us()
    retry = engine.authorize_for_target(
        **parameters,
        approval_cert=certificate,
        approval_evidence=decision,
    )
    if retry.authorized or target.path.read_bytes() != LESSON:
        raise RuntimeError("spent nonce did not refuse repeat authorization")
    entries = restored.entries(tenant)
    expected_decisions = [
        (DecisionKind.REQUIRE_APPROVAL, ("PUBLISH_REVIEW",)),
        (DecisionKind.DENY, ("APPROVAL_MISSING",)),
        (DecisionKind.REQUIRE_APPROVAL, ("PUBLISH_REVIEW",)),
        (DecisionKind.ALLOW, ("OUTCOME_COMMITTED",)),
        (DecisionKind.DENY, ("PERMIT_REPLAY",)),
    ]
    if [
        (e.record.decision.kind, e.record.decision.reason_codes) for e in entries
    ] != expected_decisions:
        raise RuntimeError("retained decision sequence or replay refusal reason differs")
    times = [e.record.decided_at_us for e in entries]
    if times != sorted(times):
        raise RuntimeError("retained recording times are not nondecreasing")
    if entries[-1].record.decided_at_us < retry_started_at:
        raise RuntimeError("replay refusal retained the earlier request timestamp")
    bundle = {
        "source_commit": "6bba989aeca27575b971c78a103cbf3745cfda6a",
        "artifact_sha256": hashlib.sha256(LESSON).hexdigest(),
        "public_keys": {
            signer.key_id: signer.public_key_bytes.hex() for signer in signers.values()
        },
        "approval": certificate,
        "permit": authorized.permit,
        "entries": entries,
        "limits": [
            "Synthetic instructor; no real human approval or credential service",
            "Local in-process signing; no HSM or WORM custody",
            "Same-process adapter reconstruction; no crash-recovery qualification",
            "Test database administrator; role isolation is not demonstrated",
            "No mission budget declared by the inherited course policy",
            "Physical expiry guarantee remains open",
        ],
    }
    (output / "evidence.json").write_bytes(canonical_bytes(bundle) + b"\n")
    summary = {
        "status": "PASS",
        "schema": schema,
        "schema_retained": True,
        "database": "factory_test",
        "clock_domain": domain,
        "missing_approval_refused": True,
        "approved_artifact_exact": True,
        "evidence_chain_verified": True,
        "evidence_entries": len(entries),
        "spent_nonce_reread": True,
        "repeat_authorization_refused": True,
        "replay_reason": "PERMIT_REPLAY",
        "recording_times_nondecreasing": True,
        "clock_floor_scope": "participants sharing this retained run schema",
        "alert_scope": "signed local outbox; no external delivery or crash-gap guarantee",
        "retry_started_at_us": retry_started_at,
        "artifact": "lesson.txt",
        "evidence": "evidence.json",
        "independent_acceptance": "PENDING",
    }
    (output / "run.json").write_bytes(canonical_bytes(summary) + b"\n")
    return summary


def main() -> None:
    """Run only with explicit output and configured test database access."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    if not dsn:
        parser.error("FACTORY_TEST_DB_URL is required; database qualification cannot skip")
    print(json.dumps(run(args.output, dsn), indent=2))


if __name__ == "__main__":
    main()
