"""Reconstruct a receiver and refuse a permit revoked before delivery."""

from __future__ import annotations

import argparse
import hashlib
import os
import uuid
from dataclasses import asdict
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, CoursePolicy, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry, PolicyContext,
    PolicyRegistry, PreflightAuthority, TrustDirectory, VerificationTrustStore, canonical_bytes,
)
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import PostgresPermitUseStore, PostgresRevocationLedger, PostgresMissionBudget, migrate
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination

BODY = b"A synthetic reversible lesson draft.\n"
OPERATION = "course:render-lesson"


def run(output: Path, dsn: str) -> dict:
    """Keep the schema, signed permits and outcome records for independent review."""
    if conninfo_to_dict(dsn).get("dbname") != "factory_test":
        raise ValueError("revocation checks require the standing factory_test database")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    schema = "test_reference_" + uuid.uuid4().hex
    (output / "run.json").write_bytes(canonical_bytes({
        "schema": schema, "schema_retained": True, "status": "STARTED",
    }) + b"\n")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    # Explicit single-login synthetic provisioning; no deployed custody claim.
    with pool.connection() as connection:
        connection.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                           "SELECT session_user::text,kind FROM "
                           "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
    provision_alerts(pool)
    provision_floor(pool, DbClock(pool, domain))
    trust = TrustDirectory()
    signers = {role: Ed25519Signer("revocation:" + role) for role in (
        "evidence", "approval", "identity", "emission", "preflight", "alert",
    )}
    for signer in signers.values():
        trust.register_signer(signer)

    def assemble():
        # New Python objects and new connections; keys remain in this process.
        connections = SchemaConnections(dsn, schema)
        clock = DurableClock(DbClock(connections, domain), floor_pool=connections)
        uses = PostgresPermitUseStore(pool=connections)
        recorder = ReferenceDecisionRecorder(
            signers["evidence"], trust, pool=connections, clock=clock,
        )
        registry = PolicyRegistry()
        registry.register(CoursePolicy())
        intended = IntendedUseRegistry()
        intended.declare(IntendedUse("course", OPERATION, 1))
        preflight = PreflightAuthority(signers["preflight"], intended, trust)
        engine = ReferenceEngine(
            # Two fixture attempts per tenant: withdrawn then fresh authority.
            budget=PostgresMissionBudget(pool=connections),
            default_mission_budget={"limit": 2, "units": 1},
            retention=LocalRetentionStore(output / "retention"),
            alerts=AlertJournal(connections, signers["alert"], trust),
            registry=registry, recorder=recorder,
            verification_trust=VerificationTrustStore(trust),
            approvals=ApprovalWorkflow(
                trust, signers["approval"], IdentityVerifier(trust, "revocation:identity"),
            ),
            emission=EmissionAuthority(signers["emission"], trust, uses),
            preflight=preflight, clock=clock,
            revocation=PostgresRevocationLedger(pool=connections),
        )
        return engine, preflight, clock, uses, recorder

    engine, preflight, clock, uses, recorder = assemble()

    def receiver(engine, uses, tenant):
        return FilesystemTargetAdapter(
            path=output / (tenant + ".txt"), tenant_id=tenant,
            authority=engine.targets, uses=uses, operation_name=OPERATION,
            budget=engine._budget,
        )

    def authorize(engine, preflight, clock, target, tenant, nonce):
        digest = hashlib.sha256(BODY).hexdigest()
        ctx = PolicyContext(tenant, Actor("author", tenant, frozenset()),
                            "education:draft", nonce, 0)
        capability = preflight.authorize(
            tenant_id=tenant, vertical="course", action_id=OPERATION, risk_tier=1,
            correlation_id=nonce, now_us=clock.now_us(), ttl_us=120_000_000,
            nonce=nonce + "-capability",
        )
        result = engine.authorize_for_target(
            vertical="course", capability=capability,
            assertion=Assertion(nonce, tenant, "course:lesson", content_digest=digest),
            action=Action(OPERATION, ActionEffect.REVERSIBLE, destination=effect_destination(
                {}, BoundEffect(digest, target.target, target.current_state(),
                                mission="synthetic:revocation-draft"),
            )),
            ctx=ctx, output=BODY, target=target, permit_ttl_us=120_000_000, nonce=nonce,
        )
        if not result.authorized or result.permit is None or target.path.exists():
            raise RuntimeError("ordinary draft authorization did not prepare an uneffected permit")
        return result

    tenant_a, tenant_b = "revocation-fixture-a", "revocation-fixture-b"
    first = authorize(engine, preflight, clock, receiver(engine, uses, tenant_a), tenant_a, "a-old")
    other = authorize(engine, preflight, clock, receiver(engine, uses, tenant_b), tenant_b, "b-old")
    event = engine.revoke(
        tenant_a, actor="fixture-host-operator", reason="Withdraw outstanding draft permits",
        now_us=clock.now_us(),
    )
    # Rebuild before delivering either of the retained authorizations.
    engine, preflight, clock, uses, recorder = assemble()
    target_a, target_b = receiver(engine, uses, tenant_a), receiver(engine, uses, tenant_b)
    refused = engine.commit(first, BODY, target_a)
    absent_after_refusal = not target_a.path.exists()
    if (refused.outcome is not Outcome.FAILED or "permit revoked" not in refused.detail
            or not absent_after_refusal or uses.used(tenant_a, "a-old")):
        raise RuntimeError("the reconstructed receiver did not refuse the revoked permit")
    committed_b = engine.commit(other, BODY, target_b)
    if committed_b.outcome is not Outcome.COMMITTED or target_b.path.read_bytes() != BODY:
        raise RuntimeError("the other tenant's original permit did not commit")
    fresh = authorize(engine, preflight, clock, target_a, tenant_a, "a-new")
    committed_a = engine.commit(fresh, BODY, target_a)
    if committed_a.outcome is not Outcome.COMMITTED or target_a.path.read_bytes() != BODY:
        raise RuntimeError("a fresh authorization at the current epoch did not commit")
    # A second reconstruction reads the retained event and both complete evidence chains.
    _, _, _, rebuilt_uses, rebuilt_recorder = assemble()
    rebuilt_revocations = PostgresRevocationLedger(pool=SchemaConnections(dsn, schema))
    epochs = {tenant: rebuilt_revocations.epoch(tenant) for tenant in (tenant_a, tenant_b)}
    if epochs != {tenant_a: 1, tenant_b: 0}:
        raise RuntimeError("retained tenant epochs changed")
    if not all(rebuilt_recorder.verify_chain(tenant) for tenant in epochs):
        raise RuntimeError("retained decision chain verification failed")
    if not (rebuilt_uses.used(tenant_a, "a-new") and rebuilt_uses.used(tenant_b, "b-old")):
        raise RuntimeError("committed permit consumption was not retained")
    with pool.connection() as connection:
        events = connection.execute(
            "SELECT tenant,epoch,actor,reason,revoked_at_us FROM regulated_revocation_events_v1 "
            "ORDER BY tenant,epoch"
        ).fetchall()
    if events != [(tenant_a, 1, event.actor, event.reason, event.at_us)]:
        raise RuntimeError("the revocation event could not be reread exactly")
    result = {
        "schema": schema, "status": "PASS", "clock_domain": domain,
        "revocation": asdict(event), "retained_events": events, "epochs": epochs,
        "absent_after_refusal": absent_after_refusal,
        "refused_nonce_unspent": not rebuilt_uses.used(tenant_a, "a-old"),
        "steps": [{
            "permit": authorization.permit.permit.signed_body(),
            "signature": asdict(authorization.permit.signature),
            "outcome": outcome.outcome.value, "detail": outcome.detail,
        } for authorization, outcome in ((first, refused), (other, committed_b), (fresh, committed_a))],
        "evidence": {tenant: [asdict(entry) for entry in rebuilt_recorder.entries(tenant)]
                     for tenant in epochs},
        "public_keys": {key.key_id: key.public_key_bytes.hex() for key in signers.values()},
        "body_sha256": hashlib.sha256(BODY).hexdigest(),
        "limits": [
            "Revocation commits before delivery; no concurrent revocation/effect ordering is qualified.",
            "New objects and connections, not a process crash or database outage; keys remain in memory.",
            "The fixture host calls revoke; production revoker identity and authorization are not qualified.",
            "Tenant key separation under one database login, not RLS qualification.",
            "Physical G4 expiry remains OPEN for this filesystem target.",
            "Local synthetic evidence, not deployed custody or operator delivery.",
        ],
    }
    (output / "revocation.json").write_bytes(canonical_bytes(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    if not dsn:
        parser.error("FACTORY_TEST_DB_URL is required")
    result = run(args.output, dsn)
    print("PASS: revoked permit refused after receiver reconstruction")
    print("Retained schema:", result["schema"])


if __name__ == "__main__":
    main()
