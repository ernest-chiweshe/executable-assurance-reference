"""A signed budget policy, retained preparation and one transactional draft."""

from __future__ import annotations

import argparse
import hashlib
import os
import uuid
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.demo import SchemaConnections
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action, ActionEffect, Actor, Assertion, Ed25519Signer, IntendedUse,
    IntendedUseRegistry, PolicyContext, PreflightAuthority, TrustDirectory,
    canonical_bytes, issue_credential,
)
from regulated_core.budget import BudgetError
from regulated_core.canonical import digest_hex
from regulated_core.clock_pg import DbClock
from regulated_core.database_receiver_pg import (
    SCHEMA as RECEIVER_SCHEMA, PostgresTargetReceiver, ReceiverAuthority,
)
from regulated_core.document_policy import DocumentPolicy
from regulated_core.evidence_checkpoints_pg import PinnedHistory, PinnedVerifier
from regulated_core.input_evidence import DecisionInputs, InputAdmission, InputVerifier
from regulated_core.input_evidence_pg import SCHEMA as INPUT_SCHEMA, record_with_inputs
from regulated_core.models import Annotation, Decision
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresMissionBudget, PostgresRevocationLedger, migrate
from regulated_core.policy_document import document_policy, verify_document
from regulated_core.prepared_issuance_pg import PostgresPreparedIssuer
from regulated_core.preflight import GenerationCapability
from regulated_core.signing import Signature
from regulated_core.reservation_subject import request_subject
from regulated_core.retained_authority_pg import SCHEMA as AUTHORITY_SCHEMA
from regulated_core.target import (
    ABSENT, BoundEffect, Outcome, TargetAuthority, TargetRef, effect_destination, effect_of,
)

TENANT = "prepared-budget-fixture"
OPERATION = "course:save-draft"
MISSION = "one-reviewed-draft"
BODY = b"Synthetic database draft: divide a circle into four equal parts.\n"
TTL = 120_000_000


@dataclass(frozen=True)
class DraftEffect:
    """This fixture writes only through the receiver's transaction."""

    tenant_id: str
    target: TargetRef
    operation: str = OPERATION

    def current_state_on(self, conn):
        row = conn.execute(
            "SELECT body FROM reference_prepared_drafts_v1 WHERE tenant=%s AND target=%s FOR UPDATE",
            (self.tenant_id, self.target.digest()),
        ).fetchone()
        return ABSENT if row is None else hashlib.sha256(row[0]).hexdigest()

    def apply_on(self, conn, output):
        conn.execute(
            "INSERT INTO reference_prepared_drafts_v1 VALUES (%s,%s,%s)",
            (self.tenant_id, self.target.digest(), output),
        )
        return hashlib.sha256(output).hexdigest()


class FixtureCurrentness:
    """Synthetic host membership and exact request scope; no production login claim."""

    def __init__(self, policy, trust, preflight):
        self.policy, self.trust = policy, trust
        self.preflight = preflight

    def check(self, conn, inputs, nonce, now_us):
        ctx = inputs.context
        bound = effect_of(inputs.action.destination)
        row = conn.execute(
            "SELECT principal,revision,role,producer,enabled FROM reference_fixture_members_v1 "
            "WHERE tenant=%s FOR SHARE", (ctx.tenant_id,),
        ).fetchone()
        request = conn.execute(
            "SELECT target_digest,mission,body_digest,capability FROM reference_fixture_requests_v1 "
            "WHERE tenant=%s AND nonce=%s FOR SHARE", (ctx.tenant_id, nonce),
        ).fetchone()
        if (row != ("fixture-author", "fixture-revision-1", "author", False, True)
                or ctx.actor.actor_id != row[0] or ctx.actor.producer
                or ctx.actor.roles != frozenset({"author"}) or ctx.actor.tenant_id != ctx.tenant_id
                or ctx.purpose != "education:draft" or ctx.requested_scope != frozenset({OPERATION})
                or inputs.action.action_id != OPERATION or inputs.action.effect is not ActionEffect.REVERSIBLE
                or bound is None or request is None
                or request[:3] != (bound.target.digest(), bound.mission, bound.output_digest)
                or inputs.assertion.content_digest != bound.output_digest
                or inputs.policy != self.policy.ref
                or not verify_document(self.trust, self.policy.document, authority="prepared:policy")
                or not self.policy.document.effective_at(now_us)):
            raise EmissionError("fixture membership, exact request or current signed policy refused")
        raw = dict(request[3])
        cap = GenerationCapability(**{k: v for k, v in raw.items() if k != "signature"},
                                   signature=Signature(**raw["signature"]))
        if cap.risk_tier != 1 or not self.preflight.verify(
            cap, tenant_id=ctx.tenant_id, vertical="course", action_id=OPERATION,
            correlation_id=ctx.correlation_id, now_us=now_us, connection=conn,
        ):
            raise EmissionError("fixture preflight is not current")

    def verify_on(self, conn, admission, inputs, now_us):
        if (admission.identity_revision != "fixture-revision-1"
                or admission.request_id != admission.permit_nonce):
            raise EmissionError("fixture identity revision or request binding refused")
        self.check(conn, inputs, admission.permit_nonce, now_us)


def run(output: Path, dsn: str, *, released_attempt: bool = False) -> dict:
    if conninfo_to_dict(dsn).get("dbname") != "factory_test":
        raise ValueError("prepared budget checks require the standing factory_test database")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    schema = "test_reference_" + uuid.uuid4().hex
    (output / "run.json").write_bytes(canonical_bytes({
        "schema": schema, "schema_retained": True, "status": "STARTED",
    }) + b"\n")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = conn.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    with pool.connection() as conn, conn.transaction():
        conn.execute(AUTHORITY_SCHEMA)
        conn.execute(INPUT_SCHEMA)
        conn.execute(RECEIVER_SCHEMA)
        conn.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                     "SELECT session_user::text, kind FROM "
                     "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
        # Explicit fixture provisioning; the preparation writer guard remains active.
        conn.execute("INSERT INTO regulated_preparation_writers_v1 VALUES (session_user::text)")
        conn.execute("CREATE TABLE reference_prepared_drafts_v1 "
                     "(tenant text,target text,body bytea,PRIMARY KEY(tenant,target))")
        conn.execute("CREATE TABLE reference_fixture_members_v1 "
                     "(tenant text PRIMARY KEY,principal text,revision text,role text,producer boolean,enabled boolean)")
        conn.execute("INSERT INTO reference_fixture_members_v1 VALUES (%s,%s,%s,%s,false,true)",
                     (TENANT, "fixture-author", "fixture-revision-1", "author"))
        conn.execute("CREATE TABLE reference_fixture_requests_v1 "
                     "(tenant text,nonce text,target_digest text,mission text,body_digest text,capability jsonb,PRIMARY KEY(tenant,nonce))")
    provision_alerts(pool)
    primary = DbClock(pool, domain)
    provision_floor(pool, primary)
    clock = DurableClock(primary, floor_pool=pool)
    trust = TrustDirectory()
    signers = {role: Ed25519Signer("prepared:" + role) for role in (
        "evidence", "permit", "identity", "ingress", "approval", "delegation", "policy", "preflight", "alert",
    )}
    for signer in signers.values():
        trust.register_signer(signer)
    document = document_policy(
        signers["policy"], vertical="course", policy_id="one-draft", version="fixture-1",
        content={"schema": "regulated/policy-content/v1", "content_types": ["course:lesson"],
                 "verifiers": {}, "risk_tier": 1, "actions": {
                     OPERATION: {"effect": "reversible", "mission_budget": {"units": 1, "limit": 1}},
                     "course:publish": {"effect": "external", "approval": {
                         "role_groups": [["instructor"]], "minimum_approvers": 1}},
                 }}, jurisdictions=("synthetic",), effective_from_us=clock.now_us(),
        effective_until_us=clock.now_us() + 600_000_000,
    )
    if not verify_document(trust, document, authority="prepared:policy"):
        raise RuntimeError("fixture policy signature failed")
    def assemble():
        connections = SchemaConnections(dsn, schema)
        clock = DurableClock(DbClock(connections, domain), floor_pool=connections)
        policy = DocumentPolicy(document)
        version = f"course/{policy.ref.policy_id}@{policy.ref.version}#{policy.ref.digest}"
        intended = IntendedUseRegistry()
        intended.declare(IntendedUse("course", OPERATION, 1))
        preflight = PreflightAuthority(signers["preflight"], intended, trust, clock=clock)
        currentness = FixtureCurrentness(policy, trust, preflight)
        verifier = InputVerifier(
            trust, "prepared:ingress", "prepared:identity", currentness,
            "prepared:permit", "prepared:approval", "prepared:delegation", TTL, clock,
        )
        recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=connections, clock=clock)
        history = PinnedVerifier(
            PinnedHistory(TENANT, "fixture-reference", (), "0" * 64), trust=trust,
            current_key="prepared:evidence", max_entries=32,
            evidence_key_ids=frozenset({"prepared:evidence"}),
        )
        epochs = PostgresRevocationLedger(pool=connections)
        authority = TargetAuthority(signers["permit"], trust, revocation_epoch=epochs.epoch, clock=clock)
        issuer = PostgresPreparedIssuer(connections, authority, trust, "prepared:evidence", version, TTL, history,
                                        input_verifier=verifier)
        receiving = ReceiverAuthority(trust, "prepared:permit", "prepared:evidence", version, TTL, history,
                                      verifier, clock=clock)
        budget = PostgresMissionBudget(pool=connections)
        journal = AlertJournal(connections, signers["alert"], trust)
        return connections, clock, policy, preflight, currentness, verifier, recorder, issuer, receiving, budget, journal

    pool, clock, policy, preflight, currentness, verifier, recorder, issuer, receiving, budget, journal = assemble()
    stages = []

    def prepare(nonce):
        try:
            return prepare_checked(nonce)
        except Exception:
            # An exception never proves that no authority was retained or signed.
            journal.append_refusal(
                tenant_id=TENANT, request_hash=digest_hex({"tenant": TENANT, "request_nonce": nonce}),
                decision_hash=None, code="AUTHORIZATION_UNCERTAIN",
            )
            raise

    def prepare_checked(nonce):
        effect = DraftEffect(TENANT, TargetRef("postgres", schema + "/" + nonce))
        receiver = PostgresTargetReceiver(pool=pool, effect=effect, authority=receiving)
        state = receiver.current_state()
        digest = hashlib.sha256(BODY).hexdigest()
        credential = issue_credential(signers["identity"], actor_id="fixture-author", tenant_id=TENANT,
                                      kind="role:author", expires_at_us=clock.now_us() + TTL)
        capability = preflight.authorize(
            tenant_id=TENANT, vertical="course", action_id=OPERATION, risk_tier=1,
            correlation_id=nonce, now_us=clock.now_us(), ttl_us=TTL, nonce=nonce + "-cap",
        )
        # Retain host-authorized request scope and its signed preflight capability.
        with pool.connection() as conn, conn.transaction():
            conn.execute("INSERT INTO reference_fixture_requests_v1 VALUES (%s,%s,%s,%s,%s,%s::jsonb)",
                         (TENANT, nonce, effect.target.digest(), MISSION, digest,
                          canonical_bytes(asdict(capability)).decode()))
        ctx = PolicyContext(TENANT, Actor("fixture-author", TENANT, frozenset({"author"}), (credential,)),
                            "education:draft", nonce, clock.now_us(), requested_scope=frozenset({OPERATION}))
        assertion = Assertion(nonce, TENANT, "course:lesson", content_digest=digest)
        action = Action(OPERATION, ActionEffect.REVERSIBLE, destination=effect_destination(
            {}, BoundEffect(digest, effect.target, state, MISSION),
        ))
        inputs = DecisionInputs(assertion, action, ctx, policy.ref)
        try:
            with pool.connection() as conn, conn.transaction():
                currentness.check(conn, inputs, nonce, clock.now_us())
        except EmissionError:
            alert = journal.append_refusal(tenant_id=TENANT, request_hash=inputs.digest(),
                                           decision_hash=None, code="ADMISSION_REFUSED")
            return None, receiver, {"admission_refusal_alert": alert}
        admission = InputAdmission.issue(
            signers["ingress"], inputs, request_id=nonce, permit_nonce=nonce,
            identity_revision="fixture-revision-1", issued_at_us=ctx.now_us,
            expires_at_us=ctx.now_us + TTL, clock=clock,
        )
        decision = policy.evaluate(assertion, action, ctx)
        if not decision.is_allow_class:
            envelope = record_with_inputs(recorder, inputs, decision, admission=admission, verifier=verifier)
            alert = journal.append_refusal(tenant_id=TENANT, request_hash=inputs.digest(),
                                           decision_hash=envelope.record_hash, code="AUTHORIZATION_REFUSED")
            return None, receiver, {"refusal": asdict(envelope), "alert": alert}
        subject = request_subject(assertion, action, ctx, policy.ref, mission=MISSION, nonce=nonce)
        terms = policy.mission_budget(OPERATION)
        if released_attempt and nonce == "draft-first":
            # Synthetic cancellation before any preparation or signing. Preserve
            # the released history and exercise the ordinary retry path.
            prior = budget.reserve(TENANT, MISSION, reservation_id=nonce,
                                   subject_digest=subject, **terms)
            budget.release(TENANT, MISSION, prior.reservation_id)
        try:
            reservation = budget.reserve(TENANT, MISSION, reservation_id=nonce, subject_digest=subject, **terms)
        except BudgetError:
            envelope = record_with_inputs(
                recorder, inputs, Decision.deny("BUDGET_EXCEEDED", "The signed mission limit is exhausted"),
                admission=admission, verifier=verifier,
            )
            alert = journal.append_refusal(tenant_id=TENANT, request_hash=inputs.digest(),
                                           decision_hash=envelope.record_hash, code="AUTHORIZATION_REFUSED")
            return None, receiver, {"refusal": asdict(envelope), "alert": alert}
        stages.append("reserved")
        envelope = record_with_inputs(recorder, inputs, decision, admission=admission, verifier=verifier)
        stages.append("recorded")
        draft = issuer.draft(
            envelope, BODY, target=effect.target, operation=OPERATION, expected_target_state=state,
            principal=ctx.actor.actor_id, approval_ref="", qualification_digests=(), ttl_us=TTL,
            nonce=nonce, not_after_us=min(admission.expires_at_us, credential.expires_at_us,
                                         capability.expires_at_us, document.effective_until_us),
            mission=MISSION, budget_reservation=reservation.reservation_id, budget_units=terms["units"],
            policy_version=issuer.expected_policy_version,
        )
        preparation = recorder.prepare_target(
            draft, issuer_key_id="prepared:permit", policy=policy, evidence_verifier=issuer.evidence_verifier,
            max_decision_age_us=TTL, input_verifier=verifier, clock=clock,
        )
        stages.append("prepared")
        permit = issuer.issue(draft)
        stages.append("issued")
        return permit, receiver, {
            "inputs": inputs.body(), "admission": asdict(admission),
            "preparation": preparation.signed_body(), "preparation_signature": asdict(preparation.signature),
            "permit": permit.permit.signed_body(), "permit_signature": asdict(permit.signature),
            "decision": asdict(envelope),
        }

    # A host-disabled member is refused before reservation, evidence authority or effect.
    with pool.connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_fixture_members_v1 SET enabled=false WHERE tenant=%s", (TENANT,))
    denied, _, denied_proof = prepare("disabled-member")
    if denied is not None or "admission_refusal_alert" not in denied_proof:
        raise RuntimeError("disabled fixture member was admitted")
    with pool.connection() as conn:
        for table in ("regulated_mission_budget_events_v1", "regulated_permit_uses_v1", "reference_prepared_drafts_v1"):
            if conn.execute("SELECT count(*) FROM " + table).fetchone()[0] != 0:
                raise RuntimeError("refused admission consumed authority or wrote a draft")
    with pool.connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_fixture_members_v1 SET enabled=true WHERE tenant=%s", (TENANT,))
    signed, receiver, proof = prepare("draft-first")
    if signed is None:
        raise RuntimeError("first unit was refused")
    with pool.connection() as conn:
        if conn.execute("SELECT count(*) FROM reference_prepared_drafts_v1").fetchone()[0] != 0:
            raise RuntimeError("draft appeared before delivery")
    # Reconstruct all composition objects before delivery; only fixture key custody remains local.
    pool, clock, policy, preflight, currentness, verifier, recorder, issuer, receiving, budget, journal = assemble()
    receiver = PostgresTargetReceiver(pool=pool, effect=DraftEffect(TENANT, TargetRef("postgres", schema + "/draft-first")),
                                      authority=receiving)
    delivered = receiver.commit(signed, BODY)
    request_inputs = DecisionInputs.decode(proof["inputs"])
    if delivered.outcome is Outcome.UNKNOWN:
        journal.append(tenant_id=TENANT, decision_hash=proof["decision"]["record_hash"],
                       permit_hash=digest_hex(signed.permit.signed_body()), code="TARGET_UNKNOWN", outcome="unknown")
    try:
        outcome_envelope = recorder.record(
            request_inputs.assertion, request_inputs.action,
            replace(request_inputs.context, now_us=clock.now_us()), policy.ref,
            Decision(
                kind=Decision.allow("OUTCOME_COMMITTED", "Database receipt retained").kind
                if delivered.outcome is Outcome.COMMITTED else Decision.deny("OUTCOME_FAILED", "No certified draft").kind,
                reason_codes=("OUTCOME_" + delivered.outcome.name,), rationale=delivered.detail,
                annotations=(Annotation("outcome-of-decision", proof["decision"]["record_hash"]),
                             Annotation("outcome-of-permit", digest_hex(signed.permit.signed_body()))),
            ),
        )
    except Exception:
        journal.append(tenant_id=TENANT, decision_hash=proof["decision"]["record_hash"],
                       permit_hash=digest_hex(signed.permit.signed_body()),
                       code="OUTCOME_RECORDING_FAILED", outcome=delivered.outcome.value)
        raise
    if delivered.outcome is not Outcome.COMMITTED or budget.committed(TENANT, MISSION) != 1:
        raise RuntimeError("prepared effect did not settle: " + delivered.detail)
    stages.append("committed")
    refused, _, refusal = prepare("draft-second")
    if refused is not None:
        raise RuntimeError("a second permit exceeded the mission budget")
    pool, clock, policy, preflight, currentness, verifier, recorder, issuer, receiving, budget, journal = assemble()
    rebuilt = PostgresTargetReceiver(pool=pool, effect=DraftEffect(TENANT, TargetRef("postgres", schema + "/draft-first")),
                                     authority=receiving)
    replay = rebuilt.commit(signed, BODY)
    observed = rebuilt.observe(signed)
    if replay.outcome is not Outcome.COMMITTED or observed.outcome is not Outcome.COMMITTED:
        raise RuntimeError("retained exact receiving result did not survive reconstruction")
    with pool.connection() as conn:
        drafts = conn.execute("SELECT tenant,target,body FROM reference_prepared_drafts_v1").fetchall()
        events = conn.execute("SELECT kind,units,limit_units,subject_digest FROM regulated_mission_budget_events_v1 "
                              "ORDER BY CASE kind WHEN 'reserve' THEN 0 ELSE 1 END").fetchall()
        counts = {name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0] for name in (
            "regulated_database_receipts_v1", "regulated_decision_uses_v1", "regulated_permit_uses_v1",
            "regulated_preparations_v1", "regulated_decision_inputs_v1",
        )}
    if released_attempt:
        expected_kinds = ["consume", "release", "reserve", "reserve"]
        if (len(drafts) != 1 or drafts[0][2] != BODY
                or sorted(row[0] for row in events) != expected_kinds
                or any(row[3] != (None if row[0] == "release" else
                                 proof["preparation"]["subject_digest"]) for row in events)):
            raise RuntimeError("unexpected retry effect or budget history")
    elif len(drafts) != 1 or drafts[0][2] != BODY or [row[0] for row in events] != ["reserve", "consume"]:
        raise RuntimeError("unexpected effect or budget history")
    if not recorder.verify_chain(TENANT):
        raise RuntimeError("retained decision chain failed verification")
    result = {
        "status": "PASS", "schema": schema, "stages": stages, "proof": proof, "refusal": refusal,
        "outcome_evidence": asdict(outcome_envelope), "chain": [asdict(entry) for entry in recorder.entries(TENANT)],
        "alerts": [journal.read(denied_proof["admission_refusal_alert"], tenant_id=TENANT),
                   journal.read(refusal["alert"], tenant_id=TENANT)],
        "policy": document.signed_body(), "policy_signature": asdict(document.signature),
        "policy_digest": document.digest(), "events": events, "counts": counts,
        "body_sha256": hashlib.sha256(drafts[0][2]).hexdigest(),
        "replay": replay.outcome.value, "observed": observed.outcome.value,
        "public_keys": {s.key_id: s.public_key_bytes.hex() for s in signers.values()},
        "limits": [
            "Prepared database-draft composition; not ReferenceEngine's filesystem authorization path.",
            "Synthetic host identity/scope rows and local keys; no production session or role isolation claim.",
            "One mission and sequential requests; no delegated authority or concurrency qualification.",
            "Replay returns the exact durable receipt without a second effect; no process crash injected.",
            "Physical G4 expiry, external effects, deployed key custody and completeness remain OPEN.",
        ],
    }
    (output / "prepared-budget.json").write_bytes(canonical_bytes(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    if not dsn:
        parser.error("FACTORY_TEST_DB_URL is required")
    result = run(args.output, dsn)
    print("PASS: one prepared database draft; second permit refused by signed budget")
    print("Retained schema:", result["schema"])


if __name__ == "__main__":
    main()
