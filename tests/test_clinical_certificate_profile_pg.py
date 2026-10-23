"""X-6/X-14 on the retained local Health final-record path: certificate-backed clinician credentials.

A signed synthetic Health derivative requires ``clinician@institutional-attestation``. The fixture composes an
explicit local certificate authority through the signed-profile selection; membership is never relabelled as a
certificate. Fictional issuer, clinician and data; isolated PostgreSQL. Not a real professional register.
"""
from hashlib import sha256
import time

import pytest

from assurance_reference.local_clinical_fixture import build_clinical_fixture
from factory.health_ui.clinician_certificates import certificate_document
from factory.health_ui.clinician_credentials import CLINICIAN_ROLE
from factory.health_ui.documents import (CLINICIAN, FINALISATION_COMMITTED, OBSERVATION, Paragraph, Session,
                                         build_document)
from factory.health_ui.templates import CONSULTATION
from regulated_core.certificates import issue_certificate
from regulated_core.signing import Ed25519Signer
from synthetic_profile_health import SYNTHETIC_PUBLISHER, build_profile_health_fixture
from test_clinical_finalisation import roles  # noqa: F401

INSTITUTION = "institutional-attestation"
HOUR = 3_600_000_000


def _profile_pack(tmp_path):
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "certificate-profile"
    build_profile_health_fixture(bundle, publisher=publisher, role_groups=[["clinician@" + INSTITUTION]])
    return bundle, publisher


@pytest.fixture
def certified(roles, tmp_path):  # noqa: F811
    bundle, publisher = _profile_pack(tmp_path)
    issuer = Ed25519Signer("fictional-local-ca:institution")
    app = build_clinical_fixture(roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
                                 certificate_issuers={issuer.key_id: INSTITUTION})
    app.trust.register_signer(issuer)
    document = build_document(CONSULTATION, "Fictional record title", "case-fixture", "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented local qualification text; no patient or clinical advice.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
                      "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
                      workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    app.session, app.document, app.issuer = session, document, issuer

    def certify(*, expires_in_us=HOUR):
        certificate = issue_certificate(issuer, subject_id=app.clinician.user_id, role=CLINICIAN_ROLE,
                                        jurisdiction="ZA", expires_at_us=app.clock.now_us() + expires_in_us)
        return app.certificates.import_certificate(app.trust, certificate_document(certificate, app.workspace),
                                                   workspace_id=app.workspace)

    app.certify_clinician = certify
    return app


def test_signed_certificate_profile_selects_the_local_ca_store(certified):
    c = certified
    assert c.profile.kind == INSTITUTION
    assert c.profile.provider.provider == "health-certificate-store"


def test_certificate_backed_clinician_finalises(certified):
    c = certified
    assert c.certify_clinician() == INSTITUTION
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    content = c.finaliser.committed_bytes(c.store.get(c.session.session_id, c.clinician.owner_id)
                                          .document(c.document.doc_id))
    assert sha256(content).hexdigest() == outcome.artifact_sha256


@pytest.mark.parametrize("case", ["no-certificate", "revoked", "expired"])
def test_clinician_without_a_current_certificate_cannot_finalise(certified, case):
    # Membership withdrawal is covered by the offline store matrix (test_x6_credential_matrix.py).
    c = certified
    if case == "revoked":
        c.certify_clinician()
        assert c.certificates.revoke(c.workspace, c.clinician.user_id)
    elif case == "expired":
        c.certify_clinician(expires_in_us=1_500_000)
        time.sleep(2)
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state != FINALISATION_COMMITTED
    assert not list(c.records.rglob("*.docx"))


def test_certificate_profile_without_a_local_ca_refuses_startup(roles, tmp_path):  # noqa: F811
    bundle, publisher = _profile_pack(tmp_path)
    with pytest.raises(ValueError, match="requires institutional-attestation credentials"):
        build_clinical_fixture(roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher)
