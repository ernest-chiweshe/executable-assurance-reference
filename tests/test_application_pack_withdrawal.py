"""Signed pack withdrawal between lawful approval and actual E/H delivery.

The intervention is an approved governance operation, not a guard replacement.
All records and actors are synthetic; the restricted partitioned runtime and
unchanged signed application bundles are used throughout.
"""
import os

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_education_fixture import build_education_fixture
from factory.health_ui.documents import (
    CLINICIAN, OBSERVATION, FINALISATION_COMMITTED, FINALISATION_FAILED,
    Paragraph, Session, build_document,
)
from factory.health_ui.templates import CONSULTATION
from pack_withdrawal_fixture import PackWithdrawalFixture
from test_education_session_release import approved_request


@pytest.fixture
def roles():
    return provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])


@pytest.mark.parametrize("withdraw", [False, True], ids=["retained", "withdrawn"])
def test_education_pack_withdrawal_refuses_approved_release_before_effect(roles, tmp_path, withdraw):
    app = build_education_fixture(roles, tmp_path, partitioned_lifecycle=True)
    governor = PackWithdrawalFixture(roles, "education-0.1.2")
    context, decision = approved_request(app)
    assert app.stores.activation.resolve_record("school-a", governor.pack.manifest.id) is not None
    if withdraw:
        governor.withdraw()
    outcome = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    if withdraw:
        assert outcome.state == "failed" and "pack authority changed before commit" in outcome.detail
        assert not app.path.exists()
        assert not app.stores.permits.used("school-a", decision.permit.permit.permit.nonce)
        assert app.stores.activation.resolve_record("school-a", governor.pack.manifest.id) is None
    else:
        assert outcome.state == "committed", outcome
        assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")


@pytest.mark.parametrize("withdraw", [False, True], ids=["retained", "withdrawn"])
def test_health_pack_withdrawal_refuses_final_record_at_receiving_boundary(roles, tmp_path, withdraw):
    app = build_clinical_fixture(roles, tmp_path, partitioned_lifecycle=True)
    governor = PackWithdrawalFixture(roles, "health-workspace-membership")
    document = build_document(CONSULTATION, "Fictional withdrawal record", "case-fixture",
                               "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented local test text; no clinical advice.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
        workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    original_commit = app.gate.commit_release
    observed = []

    def commit_after_governance(**request):
        assert request["decision"].allowed
        if withdraw:
            governor.withdraw()
        result = original_commit(**request)
        observed.append((request["decision"], result))
        return result

    # Calls the unchanged receiving method after a lawful governance change.
    app.gate.commit_release = commit_after_governance
    outcome = app.finaliser.finalise(session, document, app.clinician)
    assert len(observed) == 1
    decision, receiving = observed[0]
    if withdraw:
        assert outcome.state == FINALISATION_FAILED
        assert receiving.state == "failed" and "pack authority changed before commit" in receiving.detail
        assert not list(app.records.rglob("*.docx"))
        assert not app.stores.permits.used(app.clinician.workspace_id, decision.permit.permit.permit.nonce)
        assert app.stores.activation.resolve_record(app.clinician.workspace_id, app.pack.manifest.id) is None
    else:
        assert outcome.state == FINALISATION_COMMITTED, outcome.detail
        assert receiving.state == "committed"
        assert len(list(app.records.rglob("*.docx"))) == 1
    assert app.stores.recorder.verify_chain(app.clinician.workspace_id)
