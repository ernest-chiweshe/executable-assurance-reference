"""A synthetic Health approval workflow; no clinical validation or patient delivery."""

from __future__ import annotations

import argparse
import hashlib
import os
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg

from factory.projectos.synthetic import HEALTH, propose
from assurance_reference.application_binding import check_binding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action,
    ActionEffect,
    Actor,
    ApprovalError,
    ApprovalWorkflow,
    Assertion,
    ConfidenceEvidence,
    DataClass,
    DecisionKind,
    Ed25519Signer,
    EmissionAuthority,
    HealthPolicy,
    IdentityVerifier,
    IntendedUse,
    IntendedUseRegistry,
    PolicyContext,
    PolicyRegistry,
    PreflightAuthority,
    ProducerLineage,
    TrustDirectory,
    VerificationResult,
    VerificationTrustStore,
    canonical_bytes,
    digest_hex,
    issue_credential,
    sign_verification,
)
from regulated_core.clock_pg import DbClock
from regulated_core.input_evidence import DecisionInputs
from regulated_core.models import Outcome as VerificationOutcome
from regulated_core.persistence_pg import PostgresPermitUseStore, PostgresMissionBudget, migrate
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination
from regulated_core.verticals.health import (
    CLINICAL_VALIDITY,
    DESTINATION,
    MIN_NECESSARY,
    PHI_SAFETY,
    PURPOSE,
    SEND,
    SOURCE_FIDELITY,
    TENANT_ISO,
)

HANDOUT = propose(HEALTH)

CHECKS = (
    PHI_SAFETY,
    PURPOSE,
    MIN_NECESSARY,
    DESTINATION,
    TENANT_ISO,
    SOURCE_FIDELITY,
    CLINICAL_VALIDITY,
)


def run(output: Path, dsn: str) -> dict:
    """Retain a new isolated run against the standing test database only."""
    check_binding(HEALTH, HealthPolicy.ref, verifiers=CHECKS)
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
    (output / "run.json").write_bytes(
        canonical_bytes(
            {
                "schema": schema,
                "schema_retained": True,
                "status": "STARTED",
            }
        )
        + b"\n"
    )
    migrate(pool)
    # Explicit single-login synthetic provisioning in this isolated test schema.
    # Restricted allocator/receiver credential separation is qualified elsewhere.
    with pool.connection() as connection:
        connection.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                           "SELECT session_user::text,kind FROM "
                           "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
    budget = PostgresMissionBudget(pool=pool)
    provision_alerts(pool)
    primary = DbClock(pool, domain)
    provision_floor(pool, primary)
    clock = DurableClock(primary, floor_pool=pool)
    trust = TrustDirectory()
    signers = {
        role: Ed25519Signer("health-demo:" + role)
        for role in (
            "evidence",
            "approval",
            "identity",
            "emission",
            "preflight",
            "alert",
        )
    }
    check_signers = {
        name: Ed25519Signer("health-demo:check:" + str(i)) for i, name in enumerate(CHECKS)
    }
    for signer in (*signers.values(), *check_signers.values()):
        trust.register_signer(signer)
    recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    uses = PostgresPermitUseStore(pool=pool)
    approvals = ApprovalWorkflow(
        trust, signers["approval"], IdentityVerifier(trust, "health-demo:identity")
    )
    registry = PolicyRegistry()
    registry.register(HealthPolicy())
    intended = IntendedUseRegistry()
    intended.declare(IntendedUse("health", SEND, 3))
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
    tenant = "synthetic-clinic"
    target = FilesystemTargetAdapter(
        path=output / "appointment-checklist.txt",
        tenant_id=tenant,
        authority=engine.targets,
        uses=uses,
        operation_name=SEND, budget=budget,
    )
    now, ttl = clock.now_us(), 60_000_000
    content_hash = hashlib.sha256(HANDOUT).hexdigest()
    # A real cipher round trip over synthetic data, not a deployed custody claim.
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, HANDOUT, tenant.encode())
    if AESGCM(key).decrypt(nonce, encrypted, tenant.encode()) != HANDOUT:
        raise RuntimeError("synthetic encrypted payload did not round trip")
    (output / "synthetic-payload.aesgcm").write_bytes(nonce + encrypted)
    # The ephemeral key is not retained or exported. This run does not qualify
    # encrypted-archive recovery. Useful approved output is the separate handout.
    del key
    assertion = Assertion(
        "appointment-checklist",
        tenant,
        "health:patient-education",
        content_hash,
        data_classes=frozenset({DataClass.PHI}),
        payload_ref="local:aesgcm:synthetic-payload.aesgcm",
        lineage=ProducerLineage(
            "synthetic-template",
            "health-demo",
            "no-model",
            content_hash,
            digest_hex(HealthPolicy.ref),
            content_hash,
        ),
        confidence=ConfidenceEvidence(
            "0.95", "synthetic-exact-template-fixture", "health-demo:fixture-v1", now
        ),
        attributes={"scope": "synthetic workflow only; no clinical calibration"},
    )
    # These signed fixture attestations exercise the authority plumbing. They
    # are deliberately not offered as accredited privacy/clinical verifiers.
    verifications = tuple(
        sign_verification(
            check_signers[name],
            assertion_id=assertion.assertion_id,
            content_digest=content_hash,
            tenant_id=tenant,
            result=VerificationResult(
                name,
                VerificationOutcome.PASS,
                check_signers[name].key_id,
                "synthetic-fixture-v1",
                ("SYNTHETIC_TEMPLATE_ONLY",),
            ),
            verified_at_us=now,
        )
        for name in CHECKS
    )
    assertion = replace(assertion, verifications=verifications)
    ctx = PolicyContext(
        tenant,
        Actor("workflow-operator", tenant, frozenset()),
        "health:synthetic-education",
        "health-demo",
        now,
    )
    action = Action(
        SEND,
        ActionEffect.EXTERNAL,
        effect_destination(
            {},
            BoundEffect(
                content_hash,
                target.target,
                target.current_state(),
                mission="synthetic:health-handout",
            ),
        ),
    )
    capability = preflight.authorize(
        tenant_id=tenant,
        vertical="health",
        action_id=SEND,
        risk_tier=3,
        correlation_id=ctx.correlation_id,
        now_us=now,
        ttl_us=ttl,
        nonce="health-capability",
    )
    parameters = dict(
        vertical="health",
        capability=capability,
        assertion=assertion,
        action=action,
        ctx=ctx,
        output=HANDOUT,
        target=target,
        permit_ttl_us=ttl,
        nonce="health-release",
    )
    missing_checks = engine.authorize_for_target(
        **dict(parameters, assertion=replace(assertion, verifications=verifications[1:]))
    )
    if missing_checks.authorized or missing_checks.envelope.record.decision.reason_codes != (
        "PRIVACY_CONTROL_MISSING",
    ):
        raise RuntimeError("missing Health checks were not refused")
    if target.path.exists():
        raise RuntimeError("a missing privacy check produced an effect")
    for changed, reason in (
        (
            replace(assertion, confidence=replace(assertion.confidence, score="0.94")),
            "CONFIDENCE_NOT_ESTABLISHED",
        ),
        (replace(assertion, payload_ref=""), "PLAINTEXT_IN_RECORD"),
    ):
        refused = engine.authorize_for_target(**dict(parameters, assertion=changed))
        if (
            refused.authorized
            or refused.permit is not None
            or target.path.exists()
            or refused.envelope.record.decision.reason_codes != (reason,)
        ):
            raise RuntimeError("Health evidence boundary did not refuse: " + reason)
    missing_approval = engine.authorize_for_target(**parameters)
    if missing_approval.authorized or target.path.exists():
        raise RuntimeError("missing Health approval did not refuse delivery")
    decision = next(
        e
        for e in reversed(recorder.entries(tenant))
        if e.record.decision.kind is DecisionKind.REQUIRE_APPROVAL
    )
    request = approvals.open(
        request_id="health-review",
        requester_id=ctx.actor.actor_id,
        tenant_id=tenant,
        assertion_id=assertion.assertion_id,
        decision_record_id=decision.record.record_id,
        decision_record_hash=decision.record_hash,
        requirement=decision.record.decision.approval,
        now_us=clock.now_us(),
    )
    grants = []
    for role in ("clinician", "privacy-officer"):
        actor_id = "synthetic-" + role
        credential = issue_credential(
            signers["identity"],
            actor_id=actor_id,
            tenant_id=tenant,
            kind="role:" + role,
            expires_at_us=now + ttl,
        )
        actor = Actor(actor_id, tenant, frozenset(), (credential,))
        grants.append(approvals.grant(request, actor, clock.now_us()))
    try:
        approvals.finalize(request, grants[:1], clock.now_us())
    except ApprovalError as exc:
        if str(exc) != "quorum not met: 1/2":
            raise RuntimeError("single approver refused for an unexpected reason") from exc
    else:
        raise RuntimeError("one reviewer unexpectedly satisfied dual approval")
    both_roles = Actor(
        "synthetic-dual-role",
        tenant,
        frozenset(),
        tuple(
            issue_credential(
                signers["identity"],
                actor_id="synthetic-dual-role",
                tenant_id=tenant,
                kind="role:" + role,
                expires_at_us=now + ttl,
            )
            for role in ("clinician", "privacy-officer")
        ),
    )
    repeated_grant = approvals.grant(request, both_roles, clock.now_us())
    try:
        approvals.finalize(request, [repeated_grant, repeated_grant], clock.now_us())
    except ApprovalError as exc:
        if str(exc) != "quorum not met: 1/2":
            raise RuntimeError("duplicate reviewer refused for an unexpected reason") from exc
    else:
        raise RuntimeError("one person counted as two approvers")
    requester = replace(
        ctx.actor,
        credentials=(
            issue_credential(
                signers["identity"],
                actor_id=ctx.actor.actor_id,
                tenant_id=tenant,
                kind="role:clinician",
                expires_at_us=now + ttl,
            ),
        ),
    )
    try:
        approvals.grant(request, requester, clock.now_us())
    except ApprovalError as exc:
        if str(exc) != "requester may not approve their own action":
            raise RuntimeError("requester refused for an unexpected reason") from exc
    else:
        raise RuntimeError("requester approved their own action")
    if target.path.exists():
        raise RuntimeError("approval refusal produced a target effect")
    certificate = approvals.finalize(request, grants, clock.now_us())
    # A second synthetic tenant has its own valid checks and capability. Tenant
    # A's genuine certificate must still confer no authority on that request.
    other_tenant = "synthetic-clinic-b"
    other_checks = tuple(
        sign_verification(
            check_signers[v.result.verification_class],
            assertion_id=v.assertion_id,
            content_digest=v.content_digest,
            tenant_id=other_tenant,
            result=v.result,
            verified_at_us=clock.now_us(),
        )
        for v in verifications
    )
    other_assertion = replace(assertion, tenant_id=other_tenant, verifications=other_checks)
    other_ctx = replace(
        ctx, tenant_id=other_tenant, actor=Actor("workflow-operator-b", other_tenant, frozenset())
    )
    other_target = FilesystemTargetAdapter(
        path=output / "tenant-b-must-not-exist.txt",
        tenant_id=other_tenant,
        authority=engine.targets,
        uses=uses,
        operation_name=SEND, budget=budget,
    )
    other_action = replace(
        action,
        destination=effect_destination(
            {},
            BoundEffect(
                content_hash,
                other_target.target,
                other_target.current_state(),
                mission="synthetic:health-handout",
            ),
        ),
    )
    other_capability = preflight.authorize(
        tenant_id=other_tenant,
        vertical="health",
        action_id=SEND,
        risk_tier=3,
        correlation_id=other_ctx.correlation_id,
        now_us=clock.now_us(),
        ttl_us=ttl,
        nonce="health-capability-b",
    )
    other_request = engine.authorize_for_target(
        **dict(
            parameters,
            assertion=other_assertion,
            ctx=other_ctx,
            action=other_action,
            target=other_target,
            capability=other_capability,
            nonce="health-release-b",
        ),
        approval_cert=certificate,
        approval_evidence=decision,
    )
    if (
        other_request.authorized
        or other_request.permit is not None
        or other_target.path.exists()
        or target.path.exists()
        or other_request.envelope.record.decision.reason_codes != ("APPROVAL_DECISION_CHANGED",)
    ):
        raise RuntimeError("another tenant's approval was not refused before an effect")
    authorized = engine.authorize_for_target(
        **parameters, approval_cert=certificate, approval_evidence=decision
    )
    if not authorized.authorized or authorized.permit is None or target.path.exists():
        raise RuntimeError("dual-approved Health fixture did not reach a clean permit boundary")
    result = engine.commit(authorized, HANDOUT, target)
    if result.outcome is not Outcome.COMMITTED or target.path.read_bytes() != HANDOUT:
        raise RuntimeError("Health fixture output not certified")
    retry = engine.authorize_for_target(
        **parameters, approval_cert=certificate, approval_evidence=decision
    )
    if retry.authorized or retry.envelope.record.decision.reason_codes != ("PERMIT_REPLAY",):
        raise RuntimeError("Health permit replay was not refused")
    restored = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    entries = restored.entries(tenant)
    if (
        not restored.verify_chain(tenant)
        or not restored.verify_chain(other_tenant)
        or not PostgresPermitUseStore(pool=pool).used(tenant, "health-release")
    ):
        raise RuntimeError("Health evidence or nonce did not survive reconstruction")
    limits = [
        "Synthetic fixture attestations and confidence; no clinical or privacy qualification",
        "Synthetic role credentials and local keys; no real human approvals or credential service",
        "Filesystem delivery only; no patient/provider transmission",
        "Ephemeral payload key; encrypted archive recovery is not demonstrated",
        "Test database administrator; no role isolation or deployed custody claim",
        "Physical expiry, crash recovery and external alert delivery remain open",
    ]
    (output / "evidence.json").write_bytes(
        canonical_bytes(
            {
                "assertion": DecisionInputs(assertion, action, ctx, HealthPolicy.ref).body()[
                    "assertion"
                ],
                "approval": certificate,
                "permit": authorized.permit,
                "entries": entries,
                "tenant_boundary_entries": restored.entries(other_tenant),
                "public_keys": {
                    s.key_id: s.public_key_bytes.hex()
                    for s in (*signers.values(), *check_signers.values())
                },
                "limits": limits,
            }
        )
        + b"\n"
    )
    summary = {
        "status": "PASS",
        "schema": schema,
        "schema_retained": True,
        "database": "factory_test",
        "missing_checks_refused": True,
        "low_confidence_refused": True,
        "missing_payload_reference_refused": True,
        "missing_approval_refused": True,
        "single_approver_refused": True,
        "duplicate_person_refused": True,
        "self_approval_refused": True,
        "cross_tenant_approval_refused": True,
        "synthetic_confidence_boundary": "0.95",
        "approved_artifact_exact": True,
        "replay_refused": True,
        "evidence_entries": len(entries),
        "artifact": target.path.name,
        "artifact_sha256": content_hash,
        "limits": limits,
        "independent_acceptance": "PENDING",
    }
    (output / "run.json").write_bytes(canonical_bytes(summary) + b"\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    if not dsn:
        parser.error("FACTORY_TEST_DB_URL is required")
    print(canonical_bytes(run(args.output, dsn)).decode())


if __name__ == "__main__":
    main()
