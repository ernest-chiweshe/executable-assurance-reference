"""Actual local Health final-record path; fictional data and isolated PostgreSQL."""

from hashlib import sha256
from io import BytesIO
import os
from zipfile import ZipFile

import pytest

from assurance_reference.local_clinical_fixture import build_clinical_fixture
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_COMMITTED,
    FINALISATION_FAILED, SIGNED, Paragraph, Session, build_document)
from factory.health_ui.store import StoreDegraded
from factory.health_ui.templates import CONSULTATION
from assurance_reference.local_roles import provision_local_roles

@pytest.fixture
def roles():
    # Pack activation is shared within a schema, so each fictional workspace
    # gets a fresh authority schema instead of trying a second first bootstrap.
    return provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])


@pytest.fixture
def clinical(roles, tmp_path):
    app = build_clinical_fixture(roles, tmp_path)
    document = build_document(CONSULTATION, "Fictional record title", "case-fixture", "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented local qualification text; no patient or clinical advice.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
        workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    app.session, app.document = session, document
    return app


def test_health_finalisation_commits_exact_retained_bytes_and_export_manifest(clinical):
    c = clinical
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    stored = c.store.get(c.session.session_id, c.clinician.owner_id).document(c.document.doc_id)
    assert stored.status == SIGNED
    assert stored.signed_by == c.clinician.display_name
    assert stored.frozen_export_digest_version == 3
    assert stored.frozen_export_digest == stored.export_digest(3)
    content = c.finaliser.committed_bytes(stored)
    assert sha256(content).hexdigest() == outcome.artifact_sha256
    assert content == c.artifacts.get(c.finaliser._tenant, outcome.artifact_address)
    assert len(list(c.records.rglob("*.docx"))) == 1
    with ZipFile(BytesIO(content)) as archive:
        rendered = archive.read("word/document.xml").decode()
    assert "Fictional record title" in rendered and "Fictional clinician" in rendered
    assert c.stores.recorder.verify_chain(c.clinician.workspace_id)
    receipt = c.gate.reconcile_release(spec=c.spec, artifact_sha256=outcome.artifact_sha256,
        out_path=str(next(c.records.rglob("*.docx"))), nonce=outcome.nonce,
        context=c.finaliser._context(c.session, c.document, c.clinician, outcome))
    assert receipt.state == "committed" and receipt.evidence["target_holds"] is True
    with pytest.raises(PermissionError, match="frozen document"):
        c.store.delete(c.session.session_id, c.clinician.owner_id)
    assert c.store.get(c.session.session_id, c.clinician.owner_id) is not None


def test_empty_health_document_is_refused_without_final_record(clinical):
    c = clinical
    for section in c.document.sections:
        section.paragraphs.clear()
    c.store.save(c.session)
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state == FINALISATION_FAILED
    assert not list(c.records.rglob("*.docx"))
    assert c.stores.recorder.verify_chain(c.clinician.workspace_id)


def test_revoked_retained_session_cannot_start_clinical_finalisation(clinical):
    c = clinical
    c.sessions.revoke(c.authenticated)
    with pytest.raises(StoreDegraded, match="session refused"):
        c.finaliser.finalise(c.session, c.document, c.clinician)
    assert not list(c.records.rglob("*.docx"))


def test_session_revoked_after_approval_is_refused_at_receiving_boundary(clinical):
    c = clinical
    original = c.gate.commit_release
    observed = []

    def revoke_then_commit(**kwargs):
        assert kwargs["decision"].allowed
        c.sessions.revoke(c.authenticated)
        outcome = original(**kwargs)
        observed.append(outcome)
        return outcome

    c.gate.commit_release = revoke_then_commit
    # The effect is refused; the revoked user also cannot update consultation
    # state afterward. Recovery requires an admitted session and the receipt.
    with pytest.raises(StoreDegraded, match="session refused"):
        c.finaliser.finalise(c.session, c.document, c.clinician)
    assert len(observed) == 1 and observed[0].state == "failed"
    assert not list(c.records.rglob("*.docx"))
    assert c.stores.recorder.verify_chain(c.clinician.workspace_id)
