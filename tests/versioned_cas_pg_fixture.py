"""Local synthetic reviewed CAS fixture; all original verification paths stay intact."""
from dataclasses import asdict
from hashlib import sha256

from assurance_reference.versioned_cas import (
    SCHEMA, compose_retained_versioned_receiver, state_digest,
)
from regulated_core import Action, ActionEffect, Actor, Assertion, PolicyContext, issue_credential
from regulated_core.approval_evidence import verified_approvals
from regulated_core.database_receiver_pg import SCHEMA as RECEIVER_SCHEMA, ReceiverAuthority
from regulated_core.identity_provider import CredentialVerifier
from regulated_core.input_evidence import DecisionInputs, InputAdmission
from regulated_core.input_evidence_pg import record_with_inputs
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresMissionBudget, PostgresRevocationLedger
from regulated_core.policy_document import verify_document
from regulated_core.prepared_issuance_pg import PostgresPreparedIssuer
from regulated_core.reservation_subject import request_subject
from regulated_core.review_store import PostgresReviewStore
from regulated_core.target import BoundEffect, TargetAuthority, TargetRef, effect_destination
from isolated_worker_database import verify_isolated_worker_database
from test_root_admission import FixtureCurrentness, TENANTS, TTL, reviewed_root_fixture

OPERATION = "course:cas-state"
BODY = b"Synthetic reviewed replacement state.\n"
OLD = b"Synthetic existing state.\n"


class CasCurrentness(FixtureCurrentness):
    def __init__(self, policy, trust, clock, signers, pool):
        super().__init__(policy, trust)

    def check(self, conn, inputs, nonce, now):
        if inputs.action.action_id != OPERATION:
            return super().check(conn, inputs, nonce, now)
        ctx = inputs.context
        member = conn.execute(
            "SELECT role,revision,enabled,expires FROM reference_root_members "
            "WHERE tenant=%s AND subject=%s FOR SHARE", (ctx.tenant_id, ctx.actor.actor_id),
        ).fetchone()
        request = conn.execute(
            "SELECT input_digest FROM reference_root_requests WHERE tenant=%s AND nonce=%s FOR SHARE",
            (ctx.tenant_id, nonce),
        ).fetchone()
        if (member is None or member[:3] != ("requester", "fixture-1", True)
                or now >= member[3] or request != (inputs.digest(),)
                or ctx.actor.producer or ctx.actor.tenant_id != ctx.tenant_id
                or ctx.actor.roles != frozenset({"requester"})
                or ctx.requested_scope != frozenset({OPERATION}) or ctx.purpose != "education:cas"
                or inputs.action.effect is not ActionEffect.AUTHORITATIVE
                or inputs.policy != self.policy.ref
                or not self.policy.document.effective_at(now)
                or not verify_document(self.trust, self.policy.document, authority="root:policy")):
            raise EmissionError("current CAS requester, exact request or policy refused")


def prepared_cas_fixture(tmp_path, *, expected_revision=3, admission_window_us=None):
    if admission_window_us is not None and (type(admission_window_us) is not int or admission_window_us <= 0):
        raise ValueError("synthetic admission window must be positive")
    verify_isolated_worker_database()  # Before any fixture provisioning.
    def configure(content):
        content["content_types"].append("course:state")
        content["actions"][OPERATION] = {
            "effect": "authoritative", "mission_budget": {"units": 1, "limit": 1},
            "approval": {"role_groups": [["instructor"], ["supervisor"]], "minimum_approvers": 2},
        }

    f = reviewed_root_fixture(tmp_path, configure_policy=configure,
                              currentness_factory=CasCurrentness)
    tenant = TENANTS[0]
    pool, clock, recorder, root, _, directory = f["assemble"](tenant)
    target = TargetRef("postgres", f["schema"] + "/cas-state")
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        conn.execute(RECEIVER_SCHEMA)
        conn.execute(
            "INSERT INTO regulated_budget_writer_roles_v1 SELECT session_user::text,kind "
            "FROM (VALUES ('reserve'),('consume'),('release')) AS kinds(kind) ON CONFLICT DO NOTHING")
        conn.execute("INSERT INTO regulated_preparation_writers_v1 VALUES (session_user::text) "
                     "ON CONFLICT DO NOTHING")
        conn.execute(SCHEMA)
        conn.execute("INSERT INTO reference_versioned_state_v1 VALUES (%s,%s,3,%s)",
                     (tenant, target.digest(), OLD))
    version = f"course/{root.policy.ref.policy_id}@{root.policy.ref.version}#{root.policy.ref.digest}"
    epoch = PostgresRevocationLedger(pool=pool)
    target_authority = TargetAuthority(
        f["signers"]["permit"], f["trust"], revocation_epoch=epoch.epoch, clock=clock)
    issuer = PostgresPreparedIssuer(
        pool, target_authority, f["trust"], "root:evidence", version, TTL, root.history,
        approval_authority=root.approvals, input_verifier=root.inputs)
    authority = ReceiverAuthority(
        f["trust"], "root:permit", "root:evidence", version, TTL, root.history,
        root.inputs, approvals=root.approvals, clock=clock)
    nonce, review_id, mission = tenant + "-cas", tenant + "-cas-review", "one-cas"
    credential = issue_credential(
        f["signers"]["identity"], actor_id="requester", tenant_id=tenant,
        kind="role:requester", expires_at_us=f["expires"])
    ctx = PolicyContext(
        tenant, Actor("requester", tenant, frozenset({"requester"}), (credential,)),
        "education:cas", nonce, clock.now_us(), requested_scope=frozenset({OPERATION}))
    assertion = Assertion(nonce, tenant, "course:state", content_digest=sha256(BODY).hexdigest())
    action = Action(OPERATION, ActionEffect.AUTHORITATIVE, effect_destination(
        {}, BoundEffect(assertion.content_digest, target, state_digest(3, OLD), mission)))
    inputs = DecisionInputs(assertion, action, ctx, root.policy.ref)
    with pool.connection() as conn, conn.transaction():
        conn.execute("INSERT INTO reference_root_requests VALUES (%s,%s,%s)",
                     (tenant, nonce, inputs.digest()))
    ingress = InputAdmission.issue(
        f["signers"]["ingress"], inputs, request_id=nonce, permit_nonce=nonce,
        identity_revision="fixture-1", issued_at_us=ctx.now_us, expires_at_us=f["expires"], clock=clock)
    budget = PostgresMissionBudget(pool=pool)
    terms = root.policy.mission_budget(OPERATION)
    reservation = budget.reserve(
        tenant, mission, reservation_id=nonce,
        subject_digest=request_subject(assertion, action, ctx, root.policy.ref,
                                       mission=mission, nonce=nonce), **terms)
    decision = root.policy.evaluate(assertion, action, ctx)
    assert decision.approval is not None
    envelope = record_with_inputs(
        recorder, inputs, decision, admission=ingress, verifier=root.inputs)
    store = PostgresReviewStore(pool=pool)
    store.transact(tenant, review_id, lambda _: {
        "review_id": review_id, "envelope": asdict(envelope), "grants": [],
        "credential_receipts": [], "certificate": None})
    request = root.approvals.open(
        request_id=review_id, requester_id="requester", tenant_id=tenant,
        assertion_id=assertion.assertion_id, decision_record_id=envelope.record.record_id,
        decision_record_hash=envelope.record_hash, requirement=decision.approval,
        now_us=envelope.record.decided_at_us)
    credentials = CredentialVerifier(f["trust"], f["signers"]["credential"], directory, directory)
    grants = []
    for reviewer in ("instructor", "supervisor"):
        state = store.get(tenant, review_id)
        grants, _ = verified_approvals(
            root.approvals, state, envelope, request, now_us=clock.now_us())
        receipt = credentials.verify(
            reviewer, tenant, reviewer, jurisdiction="synthetic", now_us=clock.now_us())
        grant = root.approvals.grant(
            request, Actor(reviewer, tenant, frozenset()), clock.now_us(), receipt=receipt)
        store.transact(tenant, review_id, lambda old: {
            **old, "grants": [*old["grants"], asdict(grant)],
            "credential_receipts": [*old["credential_receipts"], asdict(receipt)]})
        grants = [*grants, grant]
    certificate = root.approvals.finalize(request, grants, clock.now_us())
    store.transact(tenant, review_id, lambda old: {**old, "certificate": asdict(certificate)})
    draft = issuer.draft(
        envelope, BODY, target=target, operation=OPERATION,
        expected_target_state=state_digest(3, OLD), principal="requester", approval_ref=review_id,
        qualification_digests=(), ttl_us=TTL, nonce=nonce,
        not_after_us=min(f["expires"], request.expires_at_us), mission=mission,
        budget_reservation=reservation.reservation_id, budget_units=terms["units"], policy_version=version)
    recorder.prepare_target(
        draft, issuer_key_id="root:permit", policy=root.policy, evidence_verifier=root.history,
        max_decision_age_us=TTL, approval_authority=root.approvals,
        input_verifier=root.inputs, clock=clock)
    signed = issuer.issue(draft)
    host_observations = []

    def authenticate_and_lock(conn, permit, bound_target):
        if (permit.permit.nonce != nonce or permit.permit.approval_ref != review_id
                or permit.permit.principal != "requester" or bound_target != target):
            raise EmissionError("CAS host request identity differs")
        now = root.inputs.now_on(conn)
        root.inputs.verify_on(conn, inputs, ingress, evidence_key_id="root:evidence", now_us=now)
        # Customer/reviewer membership locks precede the shared review lock.
        expiries = [ingress.expires_at_us]
        for reviewer in ("instructor", "supervisor"):
            row = conn.execute(
                "SELECT role,enabled,expires FROM reference_root_members "
                "WHERE tenant=%s AND subject=%s FOR SHARE", (tenant, reviewer),
            ).fetchone()
            if row is None or row[:2] != (reviewer, True) or now >= row[2]:
                raise EmissionError("current CAS reviewer membership refused")
            expiries.append(row[2])
        host_observations.append((permit.permit.nonce, bound_target.digest()))
        deadline = min(expiries)
        if admission_window_us is not None:
            deadline = min(deadline, root.inputs.now_on(conn) + admission_window_us)
        return deadline

    receiver = compose_retained_versioned_receiver(
        pool=pool, authority=authority, tenant_id=tenant, target=target, operation=OPERATION,
        expected_revision=expected_revision, authenticate_and_lock_on=authenticate_and_lock)
    return dict(pool=pool, tenant=tenant, target=target, signed=signed, receiver=receiver,
                authority=authority, budget=budget, mission=mission, nonce=nonce,
                observations=host_observations, fixture=f)


def snapshot(f):
    with f["pool"].connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
        state = conn.execute(
            "SELECT revision,body FROM reference_versioned_state_v1 WHERE tenant=%s AND target=%s",
            (f["tenant"], f["target"].digest())).fetchone()
        uses = conn.execute(
            "SELECT count(*) FROM regulated_permit_uses_v1 WHERE tenant=%s AND nonce=%s",
            (f["tenant"], f["nonce"])).fetchone()[0]
        outcomes = conn.execute(
            "SELECT outcome FROM regulated_database_receipts_v1 WHERE tenant=%s AND nonce=%s",
            (f["tenant"], f["nonce"])).fetchall()
    return {"state": (state[0], bytes(state[1])), "uses": uses,
            "outcomes": [row[0] for row in outcomes],
            "budget": f["budget"].committed(f["tenant"], f["mission"])}
