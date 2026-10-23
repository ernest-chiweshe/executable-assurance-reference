"""Real Health retention and refusal path; requires the owned serial DB window."""

from assurance_reference.clinical_lineage import RetainedClinicalLineage
from assurance_reference.lineage_gate import LineageUnavailable
from assurance_reference.session_credentials import SessionRefused
from factory.health_ui.documents import FINALISATION_COMMITTED, FINALISATION_FAILED
from test_clinical_finalisation import clinical, roles  # noqa: F401

import pytest

# ruff: noqa: F811


def test_health_lineage_survives_adapter_reconstruction_and_has_no_effect_verdict(clinical, roles):
    c = clinical
    captured = []
    original = c.gate.authorize_release

    def observe(**request):
        answer = original(**request)
        captured.append(answer)
        return answer

    c.gate.authorize_release = observe
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    restarted = RetainedClinicalLineage(pool=roles.project_state, sessions=c.sessions,
        authenticated=c.authenticated, qualifications=c.gate._engine._qualifications,
        recorder=c.stores.recorder, permit_authority=c.gate._engine.targets._signer.key_id)
    found = restarted.get(outcome.nonce)
    assert found["evidence"] == captured[0].evidence
    assert found["evidence"]["qualification_lineage"]["reports"][0]["report_digest"] == c.report.digest()
    assert "committed" not in found
    # Exact retry is read-back comparison, not a state update or second effect.
    restarted.retain(captured[0])
    assert restarted.get(outcome.nonce) == found
    assert c.stores.recorder.verify_chain(c.authenticated.tenant)
    assert len(list(c.records.rglob("*.docx"))) == 1

    for tenant, principal in ((c.authenticated.tenant, "other-clinician"), ("other-workspace", "other")):
        c.sessions.provision_identity(tenant, principal, principal, "fictional-password-002")
        other = c.sessions.authenticate(tenant, c.sessions.login(tenant, principal, "fictional-password-002"))
        foreign = RetainedClinicalLineage(pool=roles.project_state, sessions=c.sessions, authenticated=other,
            qualifications=c.gate._engine._qualifications, recorder=c.stores.recorder,
            permit_authority=c.gate._engine.targets._signer.key_id)
        assert foreign.get(outcome.nonce) is None
        with pytest.raises(LineageUnavailable):
            foreign.retain(captured[0])
    c.sessions.revoke(c.authenticated)
    with pytest.raises(SessionRefused):
        restarted.get(outcome.nonce)


def test_failed_lineage_retention_prevents_release_and_cleans_reservation(clinical):
    c = clinical
    cleaned = []
    cleanup = c.gate._gate._return_unreleased_reservation

    def observe_cleanup(authorization):
        cleaned.append(authorization)
        return cleanup(authorization)

    class UnavailableRetention:
        def retain(self, decision):
            # Failure injection at the new storage boundary; all authorization
            # guards execute normally and no receiving guard is modified.
            raise LineageUnavailable("synthetic retention unavailable")

    c.gate._gate._return_unreleased_reservation = observe_cleanup
    c.gate._retention = UnavailableRetention()
    outcome = c.finaliser.finalise(c.session, c.document, c.clinician)
    assert outcome.state == FINALISATION_FAILED
    assert "retention unavailable" in outcome.detail
    assert len(cleaned) == 1
    assert not list(c.records.rglob("*.docx"))
    assert c.lineage.get(outcome.nonce) is None
    assert c.stores.recorder.verify_chain(c.authenticated.tenant)
