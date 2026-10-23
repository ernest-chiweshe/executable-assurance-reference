"""Retained human review, current membership and reconstructed root admission."""

import hashlib
import json
import os
import uuid
from dataclasses import asdict

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.root_admission import ReviewedRootAdmission
from regulated_core import Action, ActionEffect, Actor, Assertion, PolicyContext, issue_credential
from regulated_core.approval import ApprovalWorkflow
from regulated_core.approval_evidence import verified_approvals
from regulated_core.canonical import canonical_bytes
from regulated_core.clock_pg import DbClock
from regulated_core.delegation import DelegationProposal, PROPOSAL_FIELD
from regulated_core.document_policy import DocumentPolicy
from regulated_core.evidence_checkpoints_pg import PinnedHistory, PinnedVerifier
from regulated_core.identity import IdentityVerifier
from regulated_core.identity_provider import CredentialVerifier, IdentitySubject, LicenceRecord
from regulated_core.input_evidence import DecisionInputs, InputAdmission, InputVerifier
from regulated_core.input_evidence_pg import SCHEMA as INPUT_SCHEMA, record_with_inputs
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import migrate
from regulated_core.policy_document import document_policy, verify_document
from regulated_core.retained_authority_pg import SCHEMA as AUTHORITY_SCHEMA
from regulated_core.review_store import PostgresReviewStore
from regulated_core.root_admission_pg import (
    SCHEMA as ROOT_SCHEMA, RootAdmissionVerifier, load_root_provenance_on,
)
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import TargetRef


TTL = 120_000_000
OPERATION = "course:admit-mission"
TENANTS = ("root-school-a", "root-school-b")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class FixtureDirectory:
    """Synthetic PG membership and licences, not a production identity provider."""

    provider = "reference-pg-fixture"
    provider_backed = False

    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, tenant

    def resolve(self, subject_id, tenant):
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT enabled FROM reference_root_members WHERE tenant=%s AND subject=%s",
                (tenant, subject_id),
            ).fetchone()
        return None if row is None else IdentitySubject(subject_id, tenant, subject_id, row[0])

    def lookup(self, subject_id, role):
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT enabled,expires FROM reference_root_members "
                "WHERE tenant=%s AND subject=%s AND role=%s",
                (self.tenant, subject_id, role),
            ).fetchone()
        return None if row is None else LicenceRecord(
            subject_id, role, "fixture-register", "synthetic", "active" if row[0] else "suspended", row[1],
        )

    def verify_on(self, conn, tenant, subject):
        row = conn.execute(
            "SELECT revision FROM reference_root_members "
            "WHERE tenant=%s AND subject=%s AND role='owner' AND enabled FOR SHARE",
            (tenant, subject),
        ).fetchone()
        if row is None or not row[0]:
            raise EmissionError("current accountable root owner is unavailable")
        return row[0]


class FixtureCurrentness:
    def __init__(self, policy, trust):
        self.policy, self.trust = policy, trust

    def check(self, conn, inputs, nonce, now):
        ctx = inputs.context
        member = conn.execute(
            "SELECT role,revision,enabled FROM reference_root_members "
            "WHERE tenant=%s AND subject=%s FOR SHARE", (ctx.tenant_id, ctx.actor.actor_id),
        ).fetchone()
        request = conn.execute(
            "SELECT input_digest FROM reference_root_requests "
            "WHERE tenant=%s AND nonce=%s FOR SHARE", (ctx.tenant_id, nonce),
        ).fetchone()
        if (member != ("requester", "fixture-1", True)
                or request != (inputs.digest(),) or ctx.actor.producer
                or ctx.actor.tenant_id != ctx.tenant_id
                or ctx.actor.roles != frozenset({"requester"})
                or ctx.requested_scope != frozenset({OPERATION})
                or ctx.purpose != "education:delegation"
                or inputs.policy != self.policy.ref
                or not self.policy.document.effective_at(now)
                or not verify_document(self.trust, self.policy.document, authority="root:policy")):
            raise EmissionError("current fixture membership, request or signed policy refused")

    def verify_on(self, conn, admission, inputs, now_us):
        if admission.identity_revision != "fixture-1" or admission.request_id != admission.permit_nonce:
            raise EmissionError("fixture ingress identity or request revision differs")
        self.check(conn, inputs, admission.permit_nonce, now_us)


def assemble_root_fixture(tenant, *, dsn, schema, domain, document, trust, signers,
                          currentness_factory=None):
    pool = SchemaConnections(dsn, schema)
    clock = DurableClock(DbClock(pool, domain), floor_pool=pool)
    policy = DocumentPolicy(document)
    current = (FixtureCurrentness(policy, trust) if currentness_factory is None
               else currentness_factory(policy, trust, clock, signers, pool))
    inputs = InputVerifier(trust, "root:ingress", "root:identity", current,
                           "root:permit", "root:approval", "root:delegation", TTL, clock)
    approvals = ApprovalWorkflow(trust, signers["approval"], IdentityVerifier(trust, "root:identity"),
                                 credential_authorities={FixtureDirectory.provider: "root:credential"})
    recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
    history = PinnedVerifier(PinnedHistory(tenant, "root-fixture", (), "0" * 64), trust=trust,
                             current_key="root:evidence", max_entries=16,
                             evidence_key_ids=frozenset({"root:evidence"}))
    directory = FixtureDirectory(pool, tenant)
    verifier = RootAdmissionVerifier(trust, "root:evidence", "root:delegation", "root:permit",
                                      approvals, inputs, history, policy, directory)
    alerts = AlertJournal(pool, signers["alert"], trust)
    service = ReviewedRootAdmission(pool=pool, verifier=verifier, evidence_signer=signers["evidence"],
                                     delegation_signer=signers["delegation"], alerts=alerts)
    return pool, clock, recorder, verifier, service, directory


def reviewed_root_fixture(tmp_path, *, configure_policy=None, currentness_factory=None,
                          extra_members=(), extra_signer_names=()):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn and conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    (tmp_path / "run.json").write_bytes(canonical_bytes({"schema": schema, "retained": True}) + b"\n")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = conn.execute("SELECT 'pg:' || system_identifier::text FROM pg_control_system()").fetchone()[0]
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    with pool.connection() as conn, conn.transaction():
        conn.execute(AUTHORITY_SCHEMA)
        conn.execute(INPUT_SCHEMA)
        conn.execute(ROOT_SCHEMA)
        conn.execute("CREATE TABLE reference_root_members "
                     "(tenant text,subject text,role text,revision text,enabled boolean,expires bigint,"
                     "PRIMARY KEY(tenant,subject))")
        conn.execute("CREATE TABLE reference_root_requests "
                     "(tenant text,nonce text,input_digest text,PRIMARY KEY(tenant,nonce))")
    provision_alerts(pool)
    provision_floor(pool, DbClock(pool, domain))
    clock = DurableClock(DbClock(pool, domain), floor_pool=pool)
    trust = TrustDirectory()
    signers = {name: Ed25519Signer("root:" + name) for name in (
        "evidence", "permit", "identity", "ingress", "approval", "credential", "delegation", "policy", "alert",
    ) + extra_signer_names}
    for signer in signers.values():
        trust.register_signer(signer)
    expires = clock.now_us() + TTL
    with pool.connection() as conn, conn.transaction():
        for tenant in TENANTS:
            for subject, role in (("requester", "requester"), ("owner", "owner"),
                                  ("instructor", "instructor"), ("supervisor", "supervisor")) + extra_members:
                conn.execute("INSERT INTO reference_root_members VALUES (%s,%s,%s,'fixture-1',true,%s)",
                             (tenant, subject, role, expires))
    content = {"schema": "regulated/policy-content/v1", "content_types": ["course:mission"],
                 "verifiers": {}, "risk_tier": 1, "actions": {
                     OPERATION: {"effect": "authoritative", "mission_budget": {"units": 1, "limit": 1},
                                 "approval": {"role_groups": [["instructor"], ["supervisor"]],
                                              "minimum_approvers": 2}},
                 }}
    if configure_policy is not None:
        configure_policy(content)
    document = document_policy(
        signers["policy"], vertical="course", policy_id="delegate-one-draft", version="fixture-1",
        content=content, jurisdictions=("synthetic",), effective_from_us=clock.now_us(),
        effective_until_us=expires,
    )

    def assemble(tenant):
        return assemble_root_fixture(tenant, dsn=dsn, schema=schema, domain=domain,
                                     document=document, trust=trust, signers=signers,
                                     currentness_factory=currentness_factory)

    reviews = {}
    for tenant in TENANTS:
        pool, clock, recorder, verifier, service, directory = assemble(tenant)
        nonce = tenant + "-proposal"
        proposal = DelegationProposal("owner", ("course:save-draft",),
                                      (TargetRef("postgres", schema + "/" + tenant).digest(),),
                                      "one-draft", True, expires, expires, 0)
        credential = issue_credential(signers["identity"], actor_id="requester", tenant_id=tenant,
                                      kind="role:requester", expires_at_us=expires)
        ctx = PolicyContext(tenant, Actor("requester", tenant, frozenset({"requester"}), (credential,)),
                            "education:delegation", nonce, clock.now_us(), requested_scope=frozenset({OPERATION}))
        assertion = Assertion(nonce, tenant, "course:mission", content_digest=hashlib.sha256(b"one draft").hexdigest())
        action = Action(OPERATION, ActionEffect.AUTHORITATIVE,
                        canonical_bytes({PROPOSAL_FIELD: proposal.as_fields()}).decode())
        inputs = DecisionInputs(assertion, action, ctx, verifier.policy.ref)
        with pool.connection() as conn, conn.transaction():
            conn.execute("INSERT INTO reference_root_requests VALUES (%s,%s,%s)", (tenant, nonce, inputs.digest()))
            verifier.inputs.currentness.check(conn, inputs, nonce, clock.now_us())
        admission = InputAdmission.issue(signers["ingress"], inputs, request_id=nonce, permit_nonce=nonce,
                                          identity_revision="fixture-1", issued_at_us=ctx.now_us,
                                          expires_at_us=expires, clock=clock)
        decision = verifier.policy.evaluate(assertion, action, ctx)
        envelope = record_with_inputs(recorder, inputs, decision, admission=admission, verifier=verifier.inputs)
        review_id = tenant + "-review"
        state = {"review_id": review_id, "envelope": asdict(envelope),
                 "grants": [], "credential_receipts": [], "certificate": None}
        store = PostgresReviewStore(pool=pool)
        store.transact(tenant, review_id, lambda old: state)
        reviews[tenant] = (review_id, nonce, inputs, envelope)

    # A recorded REQUIRE_APPROVAL decision alone never creates root authority.
    pool, clock, recorder, verifier, service, directory = assemble(TENANTS[0])
    review_id, nonce, _, _ = reviews[TENANTS[0]]
    pending = service.admit(tenant=TENANTS[0], review_id=review_id, nonce=nonce)
    assert pending.status == "refused" and pending.grant is None and pending.alert_id
    with pool.connection() as conn:
        assert conn.execute("SELECT count(*) FROM regulated_root_admissions_v1").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM regulated_delegation_grants_v1").fetchone()[0] == 0

    partial = None
    for tenant in TENANTS:
        pool, clock, recorder, verifier, service, directory = assemble(tenant)
        review_id, nonce, inputs, envelope = reviews[tenant]
        request = verifier.approvals.open(
            request_id=review_id, requester_id="requester", tenant_id=tenant,
            assertion_id=inputs.assertion.assertion_id, decision_record_id=envelope.record.record_id,
            decision_record_hash=envelope.record_hash, requirement=envelope.record.decision.approval,
            now_us=envelope.record.decided_at_us,
        )
        credentials = CredentialVerifier(trust, signers["credential"], directory, directory)
        assert not credentials.provider_backed
        for reviewer in ("instructor", "supervisor"):
            # Recover each earlier review from PG before accepting the next one.
            pool, clock, recorder, verifier, service, directory = assemble(tenant)
            credentials = CredentialVerifier(trust, signers["credential"], directory, directory)
            store = PostgresReviewStore(pool=pool)
            old = store.get(tenant, review_id)
            prior_grants, _ = verified_approvals(verifier.approvals, old, envelope, request, now_us=clock.now_us())
            receipt = credentials.verify(reviewer, tenant, reviewer, jurisdiction="synthetic", now_us=clock.now_us())
            grant = verifier.approvals.grant(request, Actor(reviewer, tenant, frozenset()), clock.now_us(), receipt=receipt)
            store.transact(tenant, review_id, lambda old: {
                **old, "grants": [*old["grants"], asdict(grant)],
                "credential_receipts": [*old["credential_receipts"], asdict(receipt)],
            })
            if reviewer == "instructor" and tenant == TENANTS[0]:
                pool, clock, recorder, verifier, service, directory = assemble(tenant)
                partial = service.admit(tenant=tenant, review_id=review_id, nonce=nonce)
                assert partial.status == "refused" and partial.grant is None
            grants = [*prior_grants, grant]
        certificate = verifier.approvals.finalize(request, grants, clock.now_us())
        PostgresReviewStore(pool=pool).transact(tenant, review_id, lambda old: {
            **old, "certificate": asdict(certificate),
        })

    # The same complete review still refuses when its accountable owner is disabled.
    pool, clock, recorder, verifier, service, directory = assemble(TENANTS[0])
    with pool.connection() as conn, conn.transaction():
        conn.execute("UPDATE reference_root_members SET enabled=false WHERE tenant=%s AND subject='owner'", (TENANTS[0],))
    review_id, nonce, _, _ = reviews[TENANTS[0]]
    disabled = service.admit(tenant=TENANTS[0], review_id=review_id, nonce=nonce)
    assert disabled.status == "refused" and disabled.grant is None
    with pool.connection() as conn:
        for table in ("regulated_delegation_grants_v1", "regulated_root_admissions_v1",
                      "regulated_mission_budget_events_v1", "regulated_permit_uses_v1"):
            assert conn.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0

    admitted = {}
    for tenant in reversed(TENANTS):
        pool, clock, recorder, verifier, service, directory = assemble(tenant)
        if tenant == TENANTS[0]:
            with pool.connection() as conn, conn.transaction():
                conn.execute("UPDATE reference_root_members SET enabled=true "
                             "WHERE tenant=%s AND subject='owner'", (tenant,))
        review_id, nonce, _, _ = reviews[tenant]
        result = service.admit(tenant=tenant, review_id=review_id, nonce=nonce)
        assert result.status == "admitted" and result.alert_id is None and result.grant
        admitted[tenant] = result.grant

    proofs, chains = {}, {}
    for tenant in TENANTS:
        pool, clock, recorder, verifier, service, directory = assemble(tenant)
        review_id, nonce, _, _ = reviews[tenant]
        replay = service.admit(tenant=tenant, review_id=review_id, nonce=nonce)
        assert replay.status == "admitted" and replay.grant == admitted[tenant]
        with pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
            proof = load_root_provenance_on(conn, tenant, admitted[tenant].digest, verifier=verifier)
            assert proof.signed == admitted[tenant]
            proofs[tenant] = conn.execute("SELECT body,signature FROM regulated_root_admissions_v1 WHERE tenant=%s",
                                         (tenant,)).fetchone()
        chains[tenant] = [asdict(entry) for entry in recorder.entries(tenant)]
    with pool.connection() as conn:
        counts = {table: conn.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "regulated_root_admissions_v1", "regulated_delegation_grants_v1", "regulated_reviews_v1",
            "regulated_mission_budget_events_v1", "regulated_permit_uses_v1",
        )}
    assert counts == {"regulated_root_admissions_v1": 2, "regulated_delegation_grants_v1": 2,
                      "regulated_reviews_v1": 8, "regulated_mission_budget_events_v1": 0,
                      "regulated_permit_uses_v1": 0}
    result = {
        "schema": schema, "counts": counts, "roots": {t: asdict(g) for t, g in admitted.items()},
        "proofs": proofs, "chains": chains,
        "policy": document.signed_body(), "policy_signature": asdict(document.signature),
        "alerts": [service.alerts.read(r.alert_id, tenant_id=TENANTS[0]) for r in (pending, partial, disabled)],
        "public_keys": {s.key_id: s.public_key_bytes.hex() for s in signers.values()},
        "limits": ["Synthetic PG identity and credential fixture; one admin login, no RLS claim.",
                   "Root admission only: no child, effect permit, shared budget spending or delivered artifact.",
                   "Reconstructed objects and connections with retained host keys, not process-kill recovery.",
                   "Current reviewer withdrawal, concurrency, preflight composition and physical G4 remain OPEN."],
    }
    path = tmp_path / "root-admission.json"
    path.write_bytes(canonical_bytes(result) + b"\n")
    saved = json.loads(path.read_text(encoding="utf-8"))

    def verify(body, signature, key_id):
        assert signature["key_id"] == key_id and signature["alg"] == "ed25519"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(saved["public_keys"][key_id])).verify(
            bytes.fromhex(signature["value"]), canonical(body),
        )

    verify(saved["policy"], saved["policy_signature"], "root:policy")
    for alert in saved["alerts"]:
        verify(alert["payload"], alert["signature"], "root:alert")
        assert alert["payload"]["code"] == "ADMISSION_REFUSED"
        assert alert["payload"]["request_hash"] == hashlib.sha256(canonical({
            "schema": "executable-assurance/root-admission-request/v1", "tenant": TENANTS[0],
            "review_id": reviews[TENANTS[0]][0], "nonce": reviews[TENANTS[0]][1],
        })).hexdigest()
    for tenant in TENANTS:
        body, signature = saved["proofs"][tenant]
        verify(body, signature, "root:evidence")
        root = saved["roots"][tenant]
        grant_body = {"schema": "regulated/delegation-grant/v1", **root["grant"]}
        verify(grant_body, root["signature"], "root:delegation")
        assert body["root_digest"] == hashlib.sha256(canonical(grant_body)).hexdigest()
        assert grant_body["budget_limit"] == 1 and grant_body["subject"] == "owner"
        assert grant_body["tenant_id"] == tenant and grant_body["issuer_subject"] == "instructor,supervisor"
        assert body["admitted_at_us"] >= grant_body["issued_at_us"]
        review = body["review"]
        receipt_digests = []
        for receipt in review["credential_receipts"]:
            receipt_body = {"schema": "regulated/credential-receipt/v1",
                            **{k: v for k, v in receipt.items() if k != "signature"}}
            verify(receipt_body, receipt["signature"], "root:credential")
            assert receipt_body["tenant"] == tenant and receipt_body["status"] == "active"
            receipt_digests.append(hashlib.sha256(canonical({
                **receipt_body, "sig": receipt["signature"]["value"],
            })).hexdigest())
        for grant in review["grants"]:
            verify({"schema": "regulated/approval-grant/v1",
                    **{k: v for k, v in grant.items() if k != "signature"}}, grant["signature"], "root:approval")
            assert grant["credential_receipt_digest"] in receipt_digests
            assert grant["request_id"] == review["review_id"]
        cert = review["certificate"]
        cert_body = {"schema": "regulated/approval-cert/v1",
                     **{k: v for k, v in cert.items() if k != "signature"}}
        verify(cert_body, cert["signature"], "root:approval")
        assert cert_body["credential_receipt_digests"] == sorted(receipt_digests)
        assert cert_body["approver_ids"] == ["instructor", "supervisor"]
        assert grant_body["approval_digest"] == hashlib.sha256(canonical(cert_body)).hexdigest()
        assert cert_body["decision_record_hash"] == body["decision_hash"]
        entry, = saved["chains"][tenant]
        assert entry["record_hash"] == body["decision_hash"] == hashlib.sha256(canonical(entry["record"])).hexdigest()
        assert entry["seq"] == 0 and entry["prev_hash"] == "0" * 64
        verify({"schema": "regulated/evidence/v2", "seq": 0, "prev_hash": entry["prev_hash"],
                "record_hash": entry["record_hash"], "clock_domain": entry["domain"]}, entry["signature"], "root:evidence")

    return {"assemble": assemble, "roots": admitted, "signers": signers,
            "trust": trust, "schema": schema, "expires": expires, "domain": domain, "document": document}


def test_reviewed_root_survives_reconstruction_and_refuses_pending_or_disabled_owner(tmp_path):
    reviewed_root_fixture(tmp_path)
