"""Offline issuance and exact retained decoding; no effect-boundary claim."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from assurance_reference.clinical_review_admission import ClinicalReviewCredentials, QUALIFIED_CLINICIAN
from assurance_reference.session_credentials import AuthenticatedSession, SessionBoundCredentials
from factory.health_ui.clinician_credentials import MEMBERSHIP_LICENCE
from factory.projectos.regulated import EmissionContext
from regulated_core.approval_evidence import _credential, _data
from regulated_core.identity_provider import CredentialReceipt, IdentitySubject, LicenceRecord
from regulated_core.reviewer_sessions import SessionCredentialReceipt
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_education_review_sessions import scene  # noqa: F401


@pytest.fixture
def authority():
    source = Ed25519Signer("fictional:session-issuance")
    trust = TrustDirectory()
    trust.register_signer(source)
    calls = []
    def sign(body):
        calls.append(body)
        return source.sign(body)
    signer = SimpleNamespace(key_id=source.key_id, sign=sign)
    authenticated = AuthenticatedSession("school", "teacher", "teacher.local", "session-one", 700)
    identity = SimpleNamespace(resolve=lambda subject, tenant: IdentitySubject(subject, tenant, subject))
    registry = SimpleNamespace(provider="health-identity-store", lookup=lambda subject, role:
        LicenceRecord(subject, role, MEMBERSHIP_LICENCE, "ZA", "active", 900))
    return SimpleNamespace(trust=trust, signer=signer, calls=calls, authenticated=authenticated,
                           identity=identity, registry=registry)


def test_generic_review_issues_one_session_bound_receipt(authority):
    a = authority
    @contextmanager
    def admit(identity):
        assert identity == a.authenticated
        yield lambda: None
    sessions = SimpleNamespace(admit=admit, clock=SimpleNamespace(now_us=lambda: 100))
    verifier = SessionBoundCredentials(a.trust, a.signer, a.identity, a.registry,
                                      sessions=sessions, authenticated=a.authenticated)
    context = EmissionContext("school", "teacher", now_us=100)
    receipt = verifier.verify_review("teacher", "school", "teacher", contract={}, context=context)
    assert isinstance(receipt, SessionCredentialReceipt)
    assert receipt.reviewer_session.reference == a.authenticated.reference
    assert len(a.calls) == 1 and _credential(_data(receipt)) == receipt
    verifier.validate_review(receipt, contract={}, context=context)
    assert len(a.calls) == 1


def test_scoped_education_receipt_survives_stored_approval_codec(scene):  # noqa: F811
    s = scene
    receipt = s.verifier.verify_review("head", "workspace-a", "head-of-department",
                                       contract=s.contract, context=s.context)
    assert isinstance(receipt, SessionCredentialReceipt)
    assert receipt.reviewer_session.reference == s.verifier.authenticated.reference
    assert _credential(_data(receipt)) == receipt
    s.verifier.validate_review(receipt, contract=s.contract, context=s.context)
    assert len(s.signed) == 1


def test_clinical_review_binds_separately_admitted_reviewer(authority):
    a = authority
    credentials = ClinicalReviewCredentials(a.trust, a.signer, a.identity, a.registry,
        sessions=SimpleNamespace(admit_session=lambda: None), clock_us=lambda: 100,
        reviewer_session_authority=SimpleNamespace(admit_many=lambda: None))
    context = EmissionContext("school", "teacher", now_us=100)
    checks = []
    with credentials._admitted_review(a.authenticated, context, {}, lambda: checks.append(True)):
        receipt = credentials.verify_review("teacher", "school", QUALIFIED_CLINICIAN,
                                             contract={}, context=context, jurisdiction="ZA")
    assert isinstance(receipt, SessionCredentialReceipt)
    assert receipt.reviewer_session.reference == "session-one"
    assert _credential(_data(receipt)) == receipt and len(a.calls) == 1 and checks
    credentials.validate_review(receipt, contract={}, context=context)
    assert len(a.calls) == 1


def test_existing_v1_stored_receipt_decoding_stays_exact(authority):
    a = authority
    body = dict(schema="regulated/credential-receipt/v1", subject_id="teacher", tenant="school",
                role="teacher", licence_type="fixture", jurisdiction="ZA", status="active",
                expires_at_us=900, verified_at_us=100, provider="fixture")
    fields = {k: v for k, v in body.items() if k != "schema"}
    receipt = CredentialReceipt(signature=a.signer.sign(body), **fields)
    assert type(_credential(_data(receipt))) is CredentialReceipt
    assert _data(_credential(_data(receipt))) == _data(receipt)

