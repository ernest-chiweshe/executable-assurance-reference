"""Guarded local contract tests; no database, provider or human witness claims."""

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.education_review_sessions import SessionEnrollmentReviewer
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from factory.education_workbench.appointments import POLICY, ROLE, ReviewerAppointments
from factory.education_workbench.reviewer_credentials import AssessmentScope
from factory.packs.collections import InMemoryPackCollectionStore
from factory.packs.examples import build_education_pack
from factory.packs.registry import PackRegistry
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import digest_hex
from regulated_core.identity_provider import CredentialError
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, TrustDirectory


class Sessions:
    """Injected session authority with observable lock lifetime and expiry."""

    def __init__(self):
        self.now, self.revoked, self.depth, self.entries = 21, False, 0, 0
        self.clock = SimpleNamespace(now_us=lambda: self.now)

    @contextmanager
    def admit(self, identity):
        def check():
            if self.revoked or self.now >= identity.expires_at_us or self.depth != 1:
                raise SessionRefused("fixture session refused")
        self.entries += 1
        self.depth += 1
        try:
            check()
            yield check
        finally:
            self.depth -= 1


@pytest.fixture
def scene(tmp_path):
    trust = TrustDirectory()
    keys = {name: Ed25519Signer("fictional-education-review:" + name)
            for name in ("publisher", "school", "appointment-owner", "credential")}
    for signer in keys.values():
        trust.register_signer(signer)
    root = tmp_path / "pack"
    manifest = build_education_pack(root, publisher=keys["publisher"], rulebook_authority=keys["school"])
    store = InMemoryPackCollectionStore()
    registry = PackRegistry(trust=trust, collections=store)
    registry.install(root, publisher_key_id=keys["publisher"].key_id, today="2026-09-10")
    registry.activate(manifest.reference, at="2026-09-10T00:00:00Z")
    appointments = ReviewerAppointments(registry, store, trust=trust,
        owner_authority=keys["appointment-owner"].key_id, schools={"workspace-a": "school-a"})
    def appointment(*, version="1", status="active", start=10, supersedes=""):
        return document_policy(keys["appointment-owner"], vertical="education", policy_id=POLICY,
            version=version, content={"tenant_id": "workspace-a", "school_id": "school-a",
                "principal": "head", "class_id": "class-a", "role": ROLE, "status": status,
                "given_name": "Fictional", "family_name": "Reviewer",
                "owner_approval_ref": "fictional-local-fixture-only"},
            jurisdictions=(), effective_from_us=start, effective_until_us=100, supersedes=supersedes)
    grant = appointment()
    appointments.provision(grant, now_us=20)
    contract = {"body": "retained fictional feedback"}
    scope = AssessmentScope("workspace-a", "school-a", "class-a", "assessment-a", "project-a",
                            digest_hex(contract), 90)
    scopes = {(scope.tenant, scope.project_id): scope}
    sessions = Sessions()
    signed = []
    def sign(body):
        assert sessions.depth == 1
        signed.append(body)
        return keys["credential"].sign(body)
    signer = SimpleNamespace(key_id=keys["credential"].key_id, sign=sign)
    def reviewer(principal="head"):
        return SessionEnrollmentReviewer(appointments, signer=signer,
            school_authorities={"workspace-a": keys["school"].key_id},
            assessment_scope=lambda tenant, project: scopes.get((tenant, project)),
            member_active=lambda tenant, actor: tenant == "workspace-a" and actor == "head",
            sessions=sessions, authenticated=AuthenticatedSession(
                "workspace-a", principal, principal + ".local", "synthetic-session:" + principal, 80))
    context = EmissionContext("workspace-a", "head", project_id="project-a", now_us=1)
    return SimpleNamespace(verifier=reviewer(), reviewer=reviewer, sessions=sessions, signed=signed,
        appointments=appointments, appointment=appointment, grant=grant, contract=contract,
        context=context, scopes=scopes, scope=scope)


def issue(s, **changes):
    return s.verifier.verify_review("head", "workspace-a", ROLE, contract=s.contract,
                                    context=replace(s.context, **changes))


def test_signed_appointment_receipt_uses_current_session_clock_and_revalidation_never_signs(scene):
    s = scene
    receipt = issue(s)
    assert receipt.verified_at_us == 21 and receipt.expires_at_us == 90
    assert receipt.provider.startswith("owner-enrollment:")
    s.sessions.now = 22
    s.verifier.validate_review(receipt, contract=s.contract, context=s.context)
    assert len(s.signed) == 1 and s.sessions.depth == 0
    # The requester can read a retained review, but cannot issue it for its author.
    requester = s.reviewer("requester")
    requester.validate_review(receipt, contract=s.contract, context=replace(s.context, actor_id="requester"))
    with pytest.raises(CredentialError, match="another person's"):
        requester.verify_review("head", "workspace-a", ROLE, contract=s.contract,
                                context=replace(s.context, actor_id="requester"))
    assert len(s.signed) == 1


@pytest.mark.parametrize("change", [dict(actor_id="another"), dict(tenant="other-school"),
    dict(actor_roles=(ROLE,)), dict(is_producer=True), dict(project_id="other-project")])
def test_wrong_session_or_assessment_refuses_before_signing(scene, change):
    with pytest.raises(CredentialError):
        issue(scene, **change)
    assert scene.signed == [] and scene.sessions.depth == 0


@pytest.mark.parametrize("failure", ["revoked-session", "expired-session", "expired-assessment"])
def test_stale_caller_time_cannot_keep_authority_current(scene, failure):
    if failure == "revoked-session":
        scene.sessions.revoked = True
    elif failure == "expired-session":
        scene.sessions.now = 80
    else:
        scene.scopes[("workspace-a", "project-a")] = replace(scene.scope, expires_at_us=21)
    with pytest.raises(CredentialError):
        issue(scene, now_us=1)
    assert scene.signed == [] and scene.sessions.depth == 0


def test_owner_revocation_invalidates_retained_receipt_without_resigning(scene):
    s = scene
    receipt = issue(s)
    revoke = s.appointment(version="2", status="revoked", start=25, supersedes=s.grant.digest())
    s.appointments.provision(revoke, now_us=30, expected_revision=1)
    s.sessions.now = 30
    with pytest.raises(CredentialError, match="revoked"):
        s.verifier.validate_review(receipt, contract=s.contract, context=s.context)
    assert len(s.signed) == 1 and s.sessions.depth == 0


def test_nested_review_holds_one_session_admission_and_restores_it_after_error(scene):
    s = scene
    with s.verifier.review_guard(contract=s.contract, context=s.context, actors=("head",)):
        receipt = issue(s)
        s.verifier.validate_review(receipt, contract=s.contract, context=s.context)
        assert s.sessions.entries == 1 and s.sessions.depth == 1
        with pytest.raises(CredentialError):
            issue(s, actor_id="another")
    assert s.sessions.depth == 0
    issue(s)
    assert s.sessions.entries == 2


def test_expiry_during_signing_never_returns_a_current_receipt(scene):
    s = scene
    original = s.verifier.signer.sign
    def slow_sign(body):
        signature = original(body)
        s.sessions.now = 90
        return signature
    s.verifier.signer.sign = slow_sign
    with pytest.raises(CredentialError):
        issue(s)
    assert len(s.signed) == 1 and s.sessions.depth == 0
