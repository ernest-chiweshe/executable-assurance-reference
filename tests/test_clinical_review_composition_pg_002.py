"""Actual retained preparation and signed reviewer grants; no tier4 release claim."""
from dataclasses import fields, replace
import os

import pytest

from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_roles import provision_local_roles, LocalPool
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.clinical_review_attempts import RetainedClinicalReviewAttempts
from assurance_reference.session_admission_scope import SessionAdmissionScope
from factory.health_ui.documents import (
    CLINICIAN, OBSERVATION, FINALISATION_PENDING, FINALISATION_COMMITTED,
    Paragraph, Session, build_document,
)
from factory.health_ui.templates import CONSULTATION
from regulated_core.approval_exchange import ReviewError
from regulated_core.signing import Ed25519Signer
from synthetic_tier4_health import build_tier4_health_fixture


def populate(app):
    document = build_document(CONSULTATION, "Fictional staged review", "case-fixture",
                              "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented observation for local software qualification.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
        workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    return session, document


@pytest.mark.parametrize("partitioned", [True], ids=["partitioned"])  # legacy profile refused since candidate 060
@pytest.mark.parametrize("reviewed", [False, True], ids=["historical-default", "stored-two-person-review"])
def test_clinical_composition_and_retained_review(partitioned, reviewed, tmp_path):
    provision = provision_partitioned_local_roles if partitioned else provision_local_roles
    roles = provision(os.environ["FACTORY_TEST_DB_URL"])
    try:
        kwargs = {}
        if reviewed:
            publisher = Ed25519Signer("fixture:health-tier4-publisher")
            directory = tmp_path / "signed-synthetic-health"
            build_tier4_health_fixture(directory, publisher=publisher)
            kwargs.update(synthetic_pack_directory=directory, synthetic_publisher=publisher)
        app = build_clinical_fixture(roles, tmp_path, partitioned_lifecycle=partitioned, **kwargs)
        session, document = populate(app)
        if not reviewed:
            assert app.review_attempts is None and app.review_identities == {}
            outcome = app.finaliser.finalise(session, document, app.clinician)
            assert outcome.state == FINALISATION_COMMITTED, outcome.detail
            assert len(list(app.records.rglob("*.docx"))) == 1
        else:
            opened = app.finaliser.begin_review(session, document, app.clinician)
            assert opened["status"] == "awaiting-review"
            record = document.finalisation
            assert record.state == FINALISATION_PENDING
            contract, context = app.finaliser.review_request(session, document, app.clinician)
            packet = app.review_attempts.get(record.nonce)
            assert packet["contract"] == contract
            assert packet["context"]["nonce"] == record.nonce
            app.review_attempts.retain(packet)
            assert app.review_attempts.get(record.nonce) == packet
            peer = app.review_identities["peer"]
            peer_attempts = RetainedClinicalReviewAttempts(pool=roles.project_state,
                sessions=SessionAdmissionScope(app.sessions, peer), authenticated=peer)
            assert peer_attempts.get(record.nonce) is None
            first = app.review_grant("owner", session, document).grant()
            assert first["status"] == "awaiting-review"
            with pytest.raises(ReviewError, match="required quorum"):
                app.finaliser.complete_review(session, document, app.clinician)
            assert document.finalisation.state == FINALISATION_PENDING
            second = app.review_grant("peer", session, document).grant()
            assert second["status"] == "approved"
            contract, context = app.finaliser.review_request(session, document, app.clinician)
            resolved = app.gate.resolve_review_context(spec=app.spec, contract=contract,
                context=replace(context, approval=opened["review_id"]))
            principals = {identity.principal for identity in app.review_identities.values()}
            assert len(principals) == 2
            assert set(resolved.approval.certificate.approver_ids) == principals
            assert {receipt.subject_id for receipt in resolved.approval.credential_receipts} == principals
            assert app.review_attempts.get(record.nonce) == packet
            assert document.finalisation.state == FINALISATION_PENDING
            assert not list(app.records.rglob("*.docx"))
        assert app.stores.recorder.verify_chain(app.clinician.workspace_id)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
