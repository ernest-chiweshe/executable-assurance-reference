"""Actual reviewed roots, host-bound children and one shared mission unit."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
import json
from threading import Barrier

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.delegated_creation import ChildRequest, ReviewedChildCreation
from assurance_reference.delegated_draft import AuditedDelegatedReceiver, PreparedDelegatedDraft
from assurance_reference.prepared_budget_demo import DraftEffect, BODY, OPERATION
from regulated_core import (Action, ActionEffect, Actor, Assertion, PolicyContext,
                            IntendedUseRegistry, IntendedUse, PreflightAuthority, issue_credential)
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.database_receiver_pg import SCHEMA as RECEIVER_SCHEMA, ReceiverAuthority
from regulated_core.delegated_effect_pg import DelegatedEffectVerifier
from regulated_core.delegation_chain_pg import resolve_stored_chain_on
from regulated_core.delegation import DelegationAuthority, ReleaseAuthority, RELEASE_AUTHORITY_FIELD
from regulated_core.input_evidence import DecisionInputs, InputAdmission
from regulated_core.models import Annotation, Decision
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGrantStore, PostgresMissionBudget, PostgresRevocationLedger
from regulated_core.preflight import GenerationCapability
from regulated_core.prepared_issuance_pg import PostgresPreparedIssuer
from regulated_core.restrictions import RestrictionRegistry
from regulated_core.signing import Signature
from regulated_core.target import ABSENT, BoundEffect, Outcome, TargetAuthority, TargetRef, effect_destination
from test_delegated_creation import FixtureCreations
from test_root_admission import FixtureCurrentness, TENANTS, TTL, canonical, reviewed_root_fixture


class DraftCurrentness(FixtureCurrentness):
    def __init__(self, policy, trust, clock, signers, pool):
        super().__init__(policy, trust)
        registry = IntendedUseRegistry()
        registry.declare(IntendedUse("course", OPERATION, 1))
        self.preflight = PreflightAuthority(signers["preflight"], registry, trust, clock=clock)

    def check(self, conn, inputs, nonce, now):
        if inputs.action.action_id == "course:admit-mission":
            return super().check(conn, inputs, nonce, now)
        ctx = inputs.context
        member = conn.execute("SELECT role,revision,enabled,expires FROM reference_root_members "
                              "WHERE tenant=%s AND subject=%s FOR SHARE",
                              (ctx.tenant_id, ctx.actor.actor_id)).fetchone()
        request = conn.execute("SELECT input_digest,capability FROM reference_draft_requests "
                               "WHERE tenant=%s AND nonce=%s FOR SHARE", (ctx.tenant_id, nonce)).fetchone()
        if (member is None or member[:3] != ("executor", "fixture-1", True) or now >= member[3]
                or ctx.actor.roles != frozenset({"executor"}) or ctx.actor.producer
                or ctx.actor.tenant_id != ctx.tenant_id or ctx.purpose != "education:draft"
                or ctx.requested_scope != frozenset({OPERATION}) or inputs.action.action_id != OPERATION
                or inputs.action.effect is not ActionEffect.REVERSIBLE
                or request is None or request[0] != inputs.digest()
                or inputs.policy != self.policy.ref or not self.policy.document.effective_at(now)):
            raise EmissionError("current executor, exact draft request or policy refused")
        # Keep the signature check from the root fixture for this same pinned document.
        from regulated_core.policy_document import verify_document
        if not verify_document(self.trust, self.policy.document, authority="root:policy"):
            raise EmissionError("draft policy signature refused")
        raw = request[1]
        cap = GenerationCapability(**{k: v for k, v in raw.items() if k != "signature"},
                                   signature=Signature(**raw["signature"]))
        if cap.risk_tier != 1 or not self.preflight.verify(
                cap, tenant_id=ctx.tenant_id, vertical="course", action_id=OPERATION,
                correlation_id=ctx.correlation_id, now_us=now, connection=conn):
            raise EmissionError("draft preflight refused")


class FixtureExecutors:
    def verify_on(self, conn, tenant, principal):
        row = conn.execute("SELECT revision FROM reference_root_members WHERE tenant=%s AND subject=%s "
                           "AND role='executor' AND enabled FOR SHARE", (tenant, principal)).fetchone()
        if row is None:
            raise EmissionError("current executor membership refused")
        return row[0]


def assemble_delegated_fixture(f, tenant):
    p, clock, recorder, root, admission, _ = f["assemble"](tenant)
    delegated = DelegatedEffectVerifier(root, root.policy, RestrictionRegistry(), FixtureExecutors())
    version = f"course/{root.policy.ref.policy_id}@{root.policy.ref.version}#{root.policy.ref.digest}"
    epoch = PostgresRevocationLedger(pool=p)
    def chain_status(tenant, leaf):
        with p.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            current_epoch = conn.execute("SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 "
                                         "WHERE tenant=%s", (tenant,)).fetchone()[0]
            resolve_stored_chain_on(conn, tenant, leaf, verifier=root, expected_epoch=int(current_epoch))
    authority = TargetAuthority(f["signers"]["permit"], f["trust"], revocation_epoch=epoch.epoch,
                                 clock=clock, chain_status=chain_status)
    issuer = PostgresPreparedIssuer(p, authority, f["trust"], "root:evidence", version, TTL, root.history,
                                    input_verifier=root.inputs, delegated_verifier=delegated)
    receiving = ReceiverAuthority(f["trust"], "root:permit", "root:evidence", version, TTL, root.history,
                                  root.inputs, delegation=delegated, clock=clock)
    budget = PostgresMissionBudget(pool=p)
    service = PreparedDelegatedDraft(pool=p, delegated=delegated, recorder=recorder,
                                     issuer=issuer, budget=budget, alerts=admission.alerts)
    receiver = AuditedDelegatedReceiver(pool=p, effect=DraftEffect(tenant, TargetRef("postgres", f["schema"]+"/"+tenant)),
                                        authority=receiving, alerts=admission.alerts)
    return p, clock, root, recorder, service, receiver, budget, admission.alerts


def delegated_draft_fixture(tmp_path):
    def configure(content):
        content["content_types"].append("course:lesson")
        content["actions"][OPERATION] = {"effect": "reversible", "mission_budget": {"units": 1, "limit": 1}}

    f = reviewed_root_fixture(tmp_path, configure_policy=configure, currentness_factory=DraftCurrentness,
                              extra_members=(("executor:alpha", "executor"), ("executor:beta", "executor")),
                              extra_signer_names=("preflight",))
    pool, clock, _, _, _, _ = f["assemble"](TENANTS[0])
    with pool.connection() as conn, conn.transaction():
        conn.execute(RECEIVER_SCHEMA)
        conn.execute("INSERT INTO regulated_budget_writer_roles_v1 SELECT session_user::text,kind "
                     "FROM (VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
        conn.execute("INSERT INTO regulated_preparation_writers_v1 VALUES (session_user::text)")
        conn.execute("CREATE TABLE reference_prepared_drafts_v1 "
                     "(tenant text,target text,body bytea,PRIMARY KEY(tenant,target))")
        conn.execute("CREATE TABLE reference_draft_requests "
                     "(tenant text,nonce text,input_digest text,capability jsonb,PRIMARY KEY(tenant,nonce))")
        conn.execute("CREATE TABLE reference_child_claims (tenant text,creation_id text,parent text,"
                     "actor text,subject text,PRIMARY KEY(tenant,creation_id),UNIQUE(tenant,subject))")
        for tenant in TENANTS:
            for name in ("alpha", "beta"):
                conn.execute("INSERT INTO reference_child_claims VALUES (%s,%s,%s,'owner',%s)",
                             (tenant, name, f["roots"][tenant].digest, "executor:" + name))
    children = {}
    for tenant in TENANTS:
        for name in ("alpha", "beta"):
            p, _, _, root, admission, _ = f["assemble"](tenant)
            result = ReviewedChildCreation(pool=p, root_verifier=root, signer=f["signers"]["delegation"],
                                           creations=FixtureCreations(), alerts=admission.alerts).create(ChildRequest(
                tenant, f["roots"][tenant].digest, name, "owner", (OPERATION,),
                f["roots"][tenant].grant.targets, f["expires"] - 1_000_000,
            ))
            assert result.status == "created", result
            children[tenant, name] = result.grant

    def assemble(tenant):
        return assemble_delegated_fixture(f, tenant)

    def authorize(tenant, name, barrier=None):
        p, clock, root, recorder, service, receiver, _, _ = assemble(tenant)
        captured = []
        def admit():
            child = children[tenant, name]
            chain = DelegationAuthority(f["signers"]["delegation"], f["trust"], PostgresGrantStore(pool=p)).resolve(
                tenant, child.digest, now_us=clock.now_us())
            nonce = tenant + "-" + name
            preflight = root.inputs.currentness.preflight
            cap = preflight.authorize(tenant_id=tenant, vertical="course", action_id=OPERATION, risk_tier=1,
                                      correlation_id=nonce, now_us=clock.now_us(), ttl_us=TTL, nonce=nonce+"-cap")
            credential = issue_credential(f["signers"]["identity"], actor_id=child.grant.subject, tenant_id=tenant,
                                          kind="role:executor", expires_at_us=f["expires"])
            ctx = PolicyContext(tenant, Actor(child.grant.subject, tenant, frozenset({"executor"}), (credential,)),
                                "education:draft", nonce, clock.now_us(), requested_scope=frozenset({OPERATION}))
            assertion = Assertion(nonce, tenant, "course:lesson", content_digest=hashlib.sha256(BODY).hexdigest())
            claim = ReleaseAuthority(child.digest, chain.digest, chain.root.digest(), chain.root.root_mission)
            action = Action(OPERATION, ActionEffect.REVERSIBLE, effect_destination(
                {RELEASE_AUTHORITY_FIELD: claim.as_fields()},
                BoundEffect(assertion.content_digest, TargetRef("postgres", f["schema"]+"/"+tenant), ABSENT, claim.mission),
            ))
            inputs = DecisionInputs(assertion, action, ctx, root.policy.ref)
            with p.connection() as conn, conn.transaction():
                conn.execute("INSERT INTO reference_draft_requests VALUES (%s,%s,%s,%s::jsonb)",
                             (tenant, nonce, inputs.digest(), canonical_bytes(asdict(cap)).decode()))
            admission = InputAdmission.issue(f["signers"]["ingress"], inputs, request_id=nonce, permit_nonce=nonce,
                                              identity_revision="fixture-1", issued_at_us=ctx.now_us,
                                              expires_at_us=f["expires"], clock=clock)
            captured.append(inputs)
            return inputs, admission, BODY
        if barrier is not None:
            barrier.wait(timeout=20)
        result = service.authorize_current(tenant=tenant, request_id=tenant + "-" + name, admit=admit)
        assert captured, result
        return result, captured[0]

    return f, assemble, authorize


def test_delegated_draft_shared_budget_and_parent_withdrawal(tmp_path):
    f, assemble, authorize = delegated_draft_fixture(tmp_path)
    barrier = Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as workers:
        attempts = list(workers.map(lambda name: authorize(TENANTS[0], name, barrier), ("alpha", "beta")))
    (tmp_path / "attempts.json").write_bytes(canonical_bytes([
        {"result": asdict(result), "inputs": inputs.body()} for result, inputs in attempts
    ]) + b"\n")
    assert sorted(r.status for r, _ in attempts) == ["authorized", "refused"], [(r.status, r.detail) for r, _ in attempts]
    winner, inputs = next((r, i) for r, i in attempts if r.status == "authorized")
    loser, _ = next((r, i) for r, i in attempts if r.status == "refused")
    assert loser.decision.record.decision.reason_codes == ("BUDGET_EXCEEDED",)
    p, clock, root, recorder, _, receiver, budget, alerts = assemble(TENANTS[0])
    with p.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_prepared_drafts_v1").fetchone()[0] == 0
    delivered = receiver.commit(winner.permit, BODY)
    assert delivered.outcome is Outcome.COMMITTED, delivered
    outcome = recorder.record(inputs.assertion, inputs.action, replace(inputs.context, now_us=clock.now_us()),
                               root.policy.ref, replace(Decision.allow("OUTCOME_COMMITTED", "Database draft committed"),
                               annotations=(Annotation("outcome-of-permit", digest_hex(winner.permit.permit.signed_body())),)))
    assert budget.committed(TENANTS[0], "one-draft") == 1

    pending, _ = authorize(TENANTS[1], "alpha")
    assert pending.status == "authorized", pending
    p, clock, _, _, _, receiver_b, budget_b, alerts_b = assemble(TENANTS[1])
    DelegationAuthority(f["signers"]["delegation"], f["trust"], PostgresGrantStore(pool=p)).revoke_authorized(
        TENANTS[1], f["roots"][TENANTS[1]].digest, actor="owner", reason="synthetic parent withdrawal",
        now_us=clock.now_us(),
    )
    refused = receiver_b.commit(pending.permit, BODY)
    assert refused.outcome is Outcome.FAILED, refused
    # A refused child spends neither its nonce nor the reserved unit; the hold stays retained.
    with p.connection() as conn:
        assert conn.execute("SELECT count(*) FROM regulated_permit_uses_v1 WHERE tenant=%s", (TENANTS[1],)).fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM reference_prepared_drafts_v1 WHERE tenant=%s", (TENANTS[1],)).fetchone()[0] == 0
        events_b = conn.execute("SELECT kind FROM regulated_mission_budget_events_v1 WHERE tenant=%s", (TENANTS[1],)).fetchall()
        stored_alerts = [json.loads(bytes(row[0])) for row in conn.execute("SELECT envelope FROM reference_alerts_v1").fetchall()]
    receiving_alert, = [a for a in stored_alerts if a["payload"].get("request_hash") ==
                        digest_hex(pending.permit.permit.signed_body())]
    assert receiving_alert["payload"]["tenant_id"] == TENANTS[1]
    assert receiving_alert["payload"]["decision_hash"] == pending.decision.record_hash
    assert receiving_alert["payload"]["code"] == "AUTHORIZATION_REFUSED"
    assert events_b == [("reserve",)] and budget_b.committed(TENANTS[1], "one-draft") == 0
    _, _, _, _, _, receiver_a, _, _ = assemble(TENANTS[0])
    assert receiver_a.commit(winner.permit, BODY).outcome is Outcome.COMMITTED
    assert receiver_a.observe(winner.permit).outcome is Outcome.COMMITTED
    with p.connection() as conn:
        assert conn.execute("SELECT body FROM reference_prepared_drafts_v1").fetchall() == [(BODY,)]
    saved_alerts = [alerts.read(loser.alert_id, tenant_id=TENANTS[0]), receiving_alert]
    # Verify the newly issued artifacts without project signature-verification helpers.
    for authorization in (winner, pending):
        Ed25519PublicKey.from_public_bytes(f["signers"]["permit"].public_key_bytes).verify(
            bytes.fromhex(authorization.permit.signature.value),
            canonical(authorization.permit.permit.signed_body()))
        Ed25519PublicKey.from_public_bytes(f["signers"]["evidence"].public_key_bytes).verify(
            bytes.fromhex(authorization.preparation.signature.value),
            canonical(authorization.preparation.signed_body()))
        assert authorization.preparation.signed_body()["draft"]["grant_digest"] == authorization.permit.permit.grant_digest
        assert authorization.preparation.signed_body()["budget_limit"] == 1
    for alert in saved_alerts:
        Ed25519PublicKey.from_public_bytes(f["signers"]["alert"].public_key_bytes).verify(
            bytes.fromhex(alert["signature"]["value"]), canonical(alert["payload"]))
    (tmp_path / "delegated-draft.json").write_bytes(canonical_bytes({
        "schema": f["schema"], "winner": asdict(winner), "loser": asdict(loser),
        "pending": asdict(pending), "outcome": asdict(outcome), "alerts": saved_alerts,
        "refused_delivery": asdict(refused), "events_b": events_b,
        "keys": {name: signer.public_key_bytes.hex() for name, signer in f["signers"].items()},
        "limits": ["Synthetic host identity and local signing keys; one database login, no RLS claim.",
                   "Database-owned draft only; no external effect or physical G4 claim.",
                   "Reconstructed objects and connections, not killed-process recovery.",
                   "Refused delivery retains its reservation for reconciliation; no automatic release."],
    }) + b"\n")
