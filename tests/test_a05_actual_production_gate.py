"""Actual ProductionGate with explicit local signed fixture authorities.

No remote provider, deployed custody, medical or educational validation is
claimed. Checker-labelled reports describe synthetic predicate observations.
"""
from dataclasses import replace
import os
import time

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.qualified_engine import QualificationSet, RequiredQualification
from regulated_core.approval_evidence import _credential, _grant
from regulated_core.canonical import canonical_bytes
from regulated_core.certificates import issue_certificate
from regulated_core.identity import IdentityVerifier, issue_credential
from regulated_core.identity_provider import IdentitySubject
from regulated_core.kms import KmsSigner, LocalKmsBackend
from regulated_core.models import Actor
from regulated_core.production_gate import AssuranceEvidence, MANDATORY, ProductionGate
from regulated_core.qualification import LabeledCase, QualificationDataset, qualify
from regulated_core.resilience import DrillOutcome, DrillReport
from regulated_core.signing import Ed25519Signer, Signature
from regulated_core.worm import LocalWormStore
from test_education_session_release import reviewed_context


class SignedFixtureIdentity:
    """Local signed identity authority, plus current retained-session lookup.

    This declaration identifies this adapter's explicit verification contract;
    LocalSessions itself remains non-provider-backed.
    """
    provider_backed = True

    def __init__(self, sessions, trust, clock, signer):
        self.sessions, self.clock = sessions, clock
        self.verifier = IdentityVerifier(trust, signer.key_id)
        self.attestations = {
            principal: issue_credential(signer, actor_id=principal, tenant_id="school-a",
                kind="synthetic-identity", expires_at_us=clock.now_us() + 120_000_000)
            for principal in ("requester", "teacher", "head")
        }

    def resolve(self, subject_id, tenant):
        credential = self.attestations.get(subject_id)
        actor = Actor(actor_id=subject_id, tenant_id=tenant, roles=frozenset())
        if credential is None or not self.verifier.credential_valid(actor, credential, self.clock.now_us()):
            return None
        current = self.sessions.resolve(subject_id, tenant)
        if current is None or not current.active:
            return None
        return IdentitySubject(subject_id, tenant, current.display_name, active=True)


class FixtureProductionAssurance:
    def __init__(self):
        self.keys, self.reports, self.bindings = {}, {}, []
        self.checked = []
        self.missing_checker = None

    def signer(self, key_id):
        if key_id.endswith(":evidence"):
            backend = LocalKmsBackend(key_id)
            signer = KmsSigner(key_id, backend, backend.custody)
        else:
            signer = Ed25519Signer(key_id)
        self.keys[key_id.rsplit(":", 1)[1]] = signer
        return signer

    def identity(self, sessions, trust, clock):
        self.trust, self.clock = trust, clock
        return SignedFixtureIdentity(sessions, trust, clock, self.keys["identity"])

    def qualifications(self, trust, clock, signer, checks):
        dataset = QualificationDataset("a05-synthetic", "1", "Synthetic strings only; no domain validation.",
            (LabeledCase("yes", True), LabeledCase("no", False)))
        reports = tuple(qualify(signer, verification_class=name, verifier_version="1",
            dataset=dataset, predicate=lambda value: value == "yes",
            qualified_at_us=clock.now_us(), valid_for_us=120_000_000,
            jurisdictions=("synthetic",), languages=("en",), document_types=("synthetic",),
            limitations=("Synthetic predicate observations, not validation of production checker behavior.",))
            for name in checks)
        self.reports = {r.verification_class: r for r in reports}
        requirements = tuple(RequiredQualification(name, "1", dataset.digest(),
            "synthetic", "en", "synthetic", "1", "1") for name in checks)
        return QualificationSet(trust=trust, authority=signer.key_id, clock_domain=clock.domain,
            required=requirements, reports=reports), reports[0]

    def bind(self, pack_id, verification_classes, credential_verifier):
        self.bindings.append((pack_id, verification_classes, credential_verifier))
        def check():
            self.checked.append((pack_id, verification_classes))
            gate = ProductionGate(self.trust, self.assurance.key_id, clock=self.clock, scope=pack_id,
                required_verifiers=verification_classes, required_drills=("synthetic:drill",),
                qualification_authority=self.keys["qualification"].key_id,
                drill_authority=self.drill_key.key_id, max_attestation_age_us=120_000_000,
                min_worm_days=1)
            evidence, drill, receipt = self.proofs[pack_id]
            return gate.check(evidence, evidence_signer=self.keys["evidence"],
                credential_verifier=credential_verifier, qualifications=self,
                drill_report=drill, worm_store=self.worm, worm_receipt=receipt)
        return check

    def current(self, name, now_us):
        return None if name == self.missing_checker else self.reports.get(name)

    def prepare(self):
        self.assurance = Ed25519Signer("synthetic:a05-assurance")
        self.drill_key = Ed25519Signer("synthetic:a05-drill")
        self.trust.register_signer(self.assurance)
        self.trust.register_signer(self.drill_key)
        self.worm, self.proofs = LocalWormStore(), {}
        for pack_id, _, _ in self.bindings:
            now = self.clock.now_us()
            evidence = AssuranceEvidence(pack_id, now, dict.fromkeys(MANDATORY, True), 1,
                "synthetic-owner", "synthetic-validator", "0.01", Signature("", ""))
            evidence = replace(evidence, signature=self.assurance.sign(evidence.signed_body()))
            drill = DrillReport(pack_id, now, now + 120_000_000,
                (DrillOutcome("synthetic:drill", True, "Synthetic observation; no real drill claimed."),),
                self.drill_key.key_id, Signature("", ""))
            drill = replace(drill, signature=self.drill_key.sign(drill.signed_body()))
            receipt = self.worm.anchor(pack_id, canonical_bytes(evidence.signed_body()),
                retain_us=86_400_000_000, now_us=now)
            self.proofs[pack_id] = evidence, drill, receipt


def compose(tmp_path):
    authority = FixtureProductionAssurance()
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path, signer_factory=authority.signer,
        production_assurance=authority, credential_identity_factory=authority.identity,
        qualification_factory=authority.qualifications)
    authority.prepare()
    assert not app.sessions.provider_backed
    assert len(authority.bindings) == 3
    assert all(credentials.provider_backed for _, _, credentials in authority.bindings)
    return app, authority


@pytest.mark.parametrize("missing_checker", [False, True])
def test_actual_production_gate_controls_certificate_backed_release(tmp_path, missing_checker):
    app, authority = compose(tmp_path)
    context = reviewed_context(app)
    gate = app.gates["requester"]
    before_checks = len(authority.checked)
    if missing_checker:
        authority.missing_checker = sorted(authority.reports)[0]
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert len(authority.checked) > before_checks
    if missing_checker:
        assert not decision.allowed and decision.permit is None
        assert "not currently qualified" in decision.reason
        assert not app.path.exists()
        assert not app.stores.permits.used("school-a", context.nonce)
        return
    assert decision.allowed and decision.permit is not None, decision.reason
    retained = app.stores.reviews.get("school-a", context.approval)
    receipts = tuple(_credential(raw) for raw in retained["credential_receipts"])
    grants = tuple(_grant(raw) for raw in retained["grants"])
    assert len(receipts) == len(grants) == 2
    assert {g.credential_receipt_digest for g in grants} == {r.digest() for r in receipts}
    assert all(gate._credverify.verify_receipt(r, now_us=app.clock.now_us()) for r in receipts)
    permit = decision.permit.permit.permit
    assert permit.qualification_digests == tuple(sorted(r.digest() for r in authority.reports.values()))
    before_commit_checks = len(authority.checked)
    result = gate.commit_release(spec=app.spec, contract=app.contract, decision=decision,
        artifact=app.body, out_path=str(app.path), context=context)
    assert len(authority.checked) > before_commit_checks
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
    (tmp_path / "production-gate-observation.json").write_bytes(canonical_bytes({
        "scope": "Actual ProductionGate and actual local signed identity/certificate verification",
        "custody": authority.keys["evidence"].custody,
        "qualification_digests": permit.qualification_digests,
        "receipts": receipts, "grants": grants, "signed_permit": decision.permit.permit,
        "decision_record_hash": permit.decision_record_hash, "outcome": result,
        "limits": ["All identity, custody, assurance, drill and checker data are explicitly synthetic.",
                   "No deployed compliance, external provider, or domain-validity claim."]}))


class MissingReceiptObservation:
    """Read-only incomplete storage observation; retained signed records stay intact."""
    durable = True

    def __init__(self, store):
        self.store = store

    def get(self, tenant, review_id):
        state = self.store.get(tenant, review_id)
        assert state is not None and len(state["credential_receipts"]) == 2
        assert len(state["grants"]) == 2 and state["certificate"] is not None
        return dict(state, credential_receipts=state["credential_receipts"][1:])

    def transact(self, *args, **kwargs):
        raise AssertionError("release validation must not rewrite stored review")


def test_missing_receipt_in_otherwise_complete_review_refuses_release(tmp_path):
    app, authority = compose(tmp_path)
    context = reviewed_context(app)
    gate = app.gates["requester"]
    original = gate._gate._review_store
    retained = original.get("school-a", context.approval)
    gate._gate._review_store = MissingReceiptObservation(original)
    try:
        decision = gate.authorize_release(spec=app.spec, contract=app.contract,
            out_path=str(app.path), context=context, artifact=app.body)
    finally:
        gate._gate._review_store = original
    assert not decision.allowed and decision.permit is None
    assert "receipt" in decision.reason.lower()
    assert original.get("school-a", context.approval) == retained
    assert not app.path.exists()
    assert not app.stores.permits.used("school-a", context.nonce)
    assert authority.checked == []  # review integrity fails before readiness/effect


def test_request_report_digest_mismatch_refuses_before_permit(tmp_path):
    app, authority = compose(tmp_path)
    gate = app.gates["requester"]
    context = reviewed_context(app)
    resolved = gate.resolve_review_context(spec=app.spec, contract=app.contract, context=gate._trusted(context))
    trusted = gate._trusted(resolved)
    assertion, action, capability, policy_context = gate._build(app.contract, trusted)
    gate._release_readiness()  # actual ProductionGate accepts this host's current proofs
    mismatch = "0" * 64
    assert mismatch not in {r.digest() for r in authority.reports.values()}
    denied = gate._engine.authorize_for_target(
        vertical=gate.VERTICAL, capability=capability, assertion=assertion, action=action,
        ctx=policy_context, output=app.body, target=gate.target_for(str(app.path), "school-a"),
        nonce=context.nonce, permit_ttl_us=60_000_000,
        approval_cert=resolved.approval.certificate, approval_evidence=resolved.approval.envelope,
        qualification_digests=(mismatch,),
    )
    assert not denied.authorized and denied.permit is None
    assert denied.envelope.record.decision.reason_codes == ("QUALIFICATION_REFUSED",)
    assert "requests cannot supply qualification references" in denied.reason
    assert not app.path.exists()
    assert not app.stores.permits.used("school-a", context.nonce)
    # Scope: the public reference entry refuses all caller-selected references.
    # This is not a claim that an alternate signed permit was injected or executed.


@pytest.mark.parametrize("expired_authority", ["report", "credential-receipt"])
def test_expired_authority_refuses_in_actual_production_composition(tmp_path, expired_authority):
    app, authority = compose(tmp_path)
    gate = app.gates["requester"]
    if expired_authority == "credential-receipt":
        expires = app.clock.now_us() + 5_000_000
        gate._credverify._registry.present(issue_certificate(authority.keys["issuer"],
            subject_id="teacher", role="teacher", jurisdiction="ZA", expires_at_us=expires))
    context = reviewed_context(app)
    retained = app.stores.reviews.get("school-a", context.approval)
    assert len(retained["grants"]) == len(retained["credential_receipts"]) == 2
    if expired_authority == "report":
        name = sorted(authority.reports)[0]
        now = app.clock.now_us()
        # The lookup returns a signed historical fixture report; no guard or
        # signed permit/grant is replaced. Other configured proofs stay current.
        report = replace(authority.reports[name], qualified_at_us=now - 20, expires_at_us=now - 10)
        authority.reports[name] = replace(report,
            signature=authority.keys["qualification"].sign(report.signed_body()))
        before_checks = len(authority.checked)
    else:
        teacher, = [r for r in retained["credential_receipts"] if r["subject_id"] == "teacher"]
        assert teacher["expires_at_us"] == expires
        timeout = time.monotonic() + 8
        while app.clock.now_us() < expires and time.monotonic() < timeout:
            time.sleep(0.02)
        now = app.clock.now_us()
        assert expires <= now < min(r.expires_at_us for r in authority.reports.values())
        assert now < app.identities["requester"].expires_at_us
        gate._release_readiness()  # actual readiness proofs remain current
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert not decision.allowed and decision.permit is None
    if expired_authority == "report":
        assert len(authority.checked) > before_checks
        assert "not currently qualified" in decision.reason
    else:
        assert "expired" in decision.reason.lower()
    assert not app.path.exists()
    assert not app.stores.permits.used("school-a", context.nonce)
    assert app.stores.reviews.get("school-a", context.approval) == retained
    assert app.stores.recorder.verify_chain("school-a")
