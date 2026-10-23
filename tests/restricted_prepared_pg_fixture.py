"""Signed prepared CAS through restricted roles; synthetic identity/business provisioning only.

Root admission is not exercised; no admin pool is returned or used for recording,
preparation, issuance, approval persistence, budget allocation or receiving.
"""
from dataclasses import asdict
from types import SimpleNamespace
from contextlib import contextmanager
import os
from psycopg import sql
from assurance_reference.local_roles import LocalPool
from assurance_reference.local_prepared_roles import provision_local_prepared_roles
from assurance_reference.clock_floor import DurableClock, install_recovery_guard
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.role_contract import collect_access_matrix
from regulated_core.clock_pg import DbClock
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.document_policy import DocumentPolicy
from regulated_core.policy_document import document_policy
from regulated_core.evidence_checkpoints_pg import PinnedHistory, PinnedVerifier
from regulated_core.input_evidence import InputVerifier
from regulated_core.approval import ApprovalWorkflow
from regulated_core.identity import IdentityVerifier
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
from test_root_admission import FixtureCurrentness, FixtureDirectory, TENANTS, TTL

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


def restricted_prepared_cas_fixture(tmp_path, *, tenant=TENANTS[0], environment=None, expected_revision=3, admission_window_us=None):
    if admission_window_us is not None and (type(admission_window_us) is not int or admission_window_us <= 0):
        raise ValueError("synthetic admission window must be positive")
    verify_isolated_worker_database()  # Before any fixture provisioning.
    env = environment or prepared_environment(tmp_path)
    roles, clock, f = env.roles, env.clock, env.f
    pool = roles.receiver
    target = TargetRef("postgres", roles.schema + "/cas-state")
    policy = env.policy
    history = PinnedVerifier(PinnedHistory(tenant, "restricted-prepared-fixture", (), "0" * 64),
        trust=f["trust"], current_key="root:evidence", max_entries=16,
        evidence_key_ids=frozenset({"root:evidence"}))
    inputs_verifier = InputVerifier(f["trust"], "root:ingress", "root:identity",
        CasCurrentness(policy, f["trust"], clock, f["signers"], pool),
        "root:permit", "root:approval", "root:delegation", TTL, clock)
    approvals = ApprovalWorkflow(f["trust"], f["signers"]["approval"], IdentityVerifier(f["trust"], "root:identity"),
        credential_authorities={FixtureDirectory.provider: "root:credential"})
    root = SimpleNamespace(policy=policy, history=history, inputs=inputs_verifier, approvals=approvals)
    recorder = ReferenceDecisionRecorder(f["signers"]["evidence"], f["trust"], pool=roles.recorder, clock=clock)
    directory = FixtureDirectory(TenantReadPool(roles.session_reader, tenant), tenant)
    # Explicit synthetic initial business state, written by the restricted target login.
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        conn.execute("INSERT INTO reference_versioned_state_v1 VALUES (%s,%s,3,%s)",
                     (tenant, target.digest(), OLD))
    version = f"course/{root.policy.ref.policy_id}@{root.policy.ref.version}#{root.policy.ref.digest}"
    epoch = PostgresRevocationLedger(pool=pool)
    target_authority = TargetAuthority(
        f["signers"]["permit"], f["trust"], revocation_epoch=epoch.epoch, clock=clock)
    issuer = PostgresPreparedIssuer(
        roles.issuer, target_authority, f["trust"], "root:evidence", version, TTL, root.history,
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
    with roles.session_issuer.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        conn.execute("INSERT INTO reference_root_requests (tenant,nonce,input_digest) VALUES (%s,%s,%s)",
                     (tenant, nonce, inputs.digest()))
    ingress = InputAdmission.issue(
        f["signers"]["ingress"], inputs, request_id=nonce, permit_nonce=nonce,
        identity_revision="fixture-1", issued_at_us=ctx.now_us, expires_at_us=f["expires"], clock=clock)
    budget = PostgresMissionBudget(pool=roles.allocator)
    terms = root.policy.mission_budget(OPERATION)
    reservation = budget.reserve(
        tenant, mission, reservation_id=nonce,
        subject_digest=request_subject(assertion, action, ctx, root.policy.ref,
                                       mission=mission, nonce=nonce), **terms)
    decision = root.policy.evaluate(assertion, action, ctx)
    assert decision.approval is not None
    envelope = record_with_inputs(
        recorder, inputs, decision, admission=ingress, verifier=root.inputs)
    store = PostgresReviewStore(pool=roles.reviewer)
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
                observations=host_observations, fixture=f, roles=roles, env=env, draft=draft, issuer=issuer, recorder=recorder)



class TenantReadPool:
    """Tenant-bound connection for the synthetic identity directory only."""
    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, tenant

    @contextmanager
    def connection(self):
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            yield conn


def prepared_environment(tmp_path):
    verify_isolated_worker_database()
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_prepared_roles(dsn)
    audit = collect_access_matrix(roles, partitioned_lifecycle=True, prepared_authority=True)
    assert audit["privilege_contract_matches"], audit["errors"]
    import json
    (tmp_path / "prepared-role-audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         recovery_not_used_reason="Synthetic restricted prepared fixture")
    trust = TrustDirectory()
    signers = {n: Ed25519Signer("root:" + n) for n in (
        "evidence", "permit", "identity", "ingress", "approval", "credential", "delegation", "policy")}
    for signer in signers.values():
        trust.register_signer(signer)
    expires = clock.now_us() + TTL
    content = {"schema": "regulated/policy-content/v1", "content_types": ["course:state"], "verifiers": {},
        "risk_tier": 1, "actions": {OPERATION: {"effect": "authoritative",
            "mission_budget": {"units": 1, "limit": 1},
            "approval": {"role_groups": [["instructor"], ["supervisor"]], "minimum_approvers": 2}}}}
    document = document_policy(signers["policy"], vertical="course", policy_id="restricted-cas", version="fixture-1",
        content=content, jurisdictions=("synthetic",), effective_from_us=clock.now_us(), effective_until_us=expires)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    try:
        with owner.connection() as conn, conn.transaction():
            conn.execute(SCHEMA)
            conn.execute("CREATE TABLE reference_root_members (tenant text,subject text,role text,revision text,"
                         "enabled boolean,expires bigint,lock_anchor boolean NOT NULL DEFAULT true,"
                         "PRIMARY KEY(tenant,subject))")
            conn.execute("CREATE TABLE reference_root_requests (tenant text,nonce text,input_digest text,"
                         "lock_anchor boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant,nonce))")
            for table in ("reference_root_members", "reference_root_requests"):
                conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(table)))
                conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(sql.Identifier(table)))
                conn.execute(sql.SQL("CREATE POLICY tenant_v1 ON {} USING(tenant=current_setting('app.tenant',true)) "
                                     "WITH CHECK(tenant=current_setting('app.tenant',true))").format(sql.Identifier(table)))
                conn.execute(sql.SQL("CREATE TRIGGER immutable_v1 BEFORE UPDATE OR DELETE ON {} FOR EACH ROW "
                                     "EXECUTE FUNCTION regulated_authority_no_mutation_v1()").format(sql.Identifier(table)))
                conn.execute(sql.SQL("CREATE TRIGGER no_truncate_v1 BEFORE TRUNCATE ON {} FOR EACH STATEMENT "
                                     "EXECUTE FUNCTION regulated_authority_no_mutation_v1()").format(sql.Identifier(table)))
                for pool in (roles.recorder, roles.issuer, roles.receiver):
                    conn.execute(sql.SQL("GRANT SELECT,UPDATE(lock_anchor) ON {} TO {}").format(
                        sql.Identifier(table),sql.Identifier(pool.role)))
            conn.execute(sql.SQL("GRANT SELECT ON reference_root_members TO {}").format(sql.Identifier(roles.session_reader.role)))
            conn.execute(sql.SQL("GRANT INSERT ON reference_root_requests TO {}").format(sql.Identifier(roles.session_issuer.role)))
            conn.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE(revision,body) ON reference_versioned_state_v1 TO {}").format(
                sql.Identifier(roles.receiver.role)))
            for tenant in TENANTS:
                for subject in ("requester", "instructor", "supervisor"):
                    conn.execute("INSERT INTO reference_root_members (tenant,subject,role,revision,enabled,expires) "
                                 "VALUES (%s,%s,%s,'fixture-1',true,%s)", (tenant,subject,subject,expires))
        install_recovery_guard(owner)  # Includes the newly created business tables.
    finally:
        owner.close()
    f = dict(schema=roles.schema, domain=roles.domain, expires=expires, signers=signers, trust=trust)
    return SimpleNamespace(roles=roles, clock=clock, f=f, policy=DocumentPolicy(document))
