"""Offline recovered-application contracts; no release or D2 completion claim."""

import json
from types import SimpleNamespace

import pytest

from factory.health_ui.clinical_checks import AUTHORSHIP, NO_PENDING_SUGGESTIONS, clinical_checks
from factory.health_ui.documents import CLINICIAN, OBSERVATION, Paragraph, Session, build_document
from factory.health_ui.store import Store
from factory.health_ui.templates import MEDICO_LEGAL
from factory.projectos.spec import KIND_ASSEMBLE, StageRun, StageSpec
from factory.verticals.product_spec.spec import build_product_spec_contract, make_product_spec_runner, product_spec_spec
from factory.verticals.product_spec.view import product_spec_view
from regulated_core.models import Outcome


@pytest.fixture
def clinical(tmp_path):
    path = tmp_path / "fictional-clinical-state.json"
    store = Store(path)
    document = build_document(MEDICO_LEGAL, "Fictional contract fixture", "case-fixture", "subject-fixture", [])
    session = Session("session-fixture", "Fictional clinician", "Fixture", "subject-fixture",
                      "2026-10-14T00:00:00+00:00", owner_id="workspace-a:clinician-a",
                      workspace_id="workspace-a", documents=[document])
    store.save(session)
    # Reopen rather than inspect the object supplied to save.
    reopened = Store(path)
    checks = clinical_checks(reopened, lambda context: context.owner)
    contract = {"session_id": session.session_id, "doc_id": document.doc_id,
                "document_digest": document.digest()}
    return SimpleNamespace(path=path, store=reopened, checks=checks, contract=contract,
                           context=SimpleNamespace(owner=session.owner_id))


def test_clinical_checks_require_context_and_ignore_contract_owner(clinical):
    check = clinical.checks[NO_PENDING_SUGGESTIONS]
    assert check("", clinical.contract) == (Outcome.FAIL, ("CLINICAL_CHECK_CONTEXT_REQUIRED",))
    assert check.verify_context("", clinical.contract, clinical.context) == (Outcome.PASS, ())
    forged_owner = {**clinical.contract, "owner_id": clinical.context.owner}
    assert check.verify_context("", forged_owner, SimpleNamespace(owner="workspace-b:clinician-a")) == (
        Outcome.FAIL, ("DOCUMENT_NOT_FOUND",))


def test_clinical_checks_bind_current_persisted_document(clinical):
    stored = clinical.store.get(clinical.contract["session_id"], clinical.context.owner)
    stored.documents[0].sections[0].paragraphs.append(
        Paragraph("Fictional changed paragraph", OBSERVATION, origin=CLINICIAN))
    clinical.store.save(stored)
    assert clinical.checks[NO_PENDING_SUGGESTIONS].verify_context("", clinical.contract, clinical.context) == (
        Outcome.FAIL, ("DOCUMENT_VERSION_CHANGED",))


def test_blank_clinician_sections_are_not_authored_by_the_fixture(clinical):
    assert clinical.checks[AUTHORSHIP].verify_context("", clinical.contract, clinical.context) == (
        Outcome.FAIL, ("CLINICIAN_SECTIONS_UNWRITTEN",))


def test_clinical_export_manifest_binds_metadata_separately(clinical):
    document = clinical.store.get(clinical.contract["session_id"], clinical.context.owner).documents[0]
    content_digest, export_digest = document.digest(), document.export_digest()
    document.title = "A different title"
    assert document.digest() == content_digest
    assert document.export_digest() != export_digest


def test_unreadable_clinical_state_is_indeterminate(clinical):
    clinical.path.write_bytes(b"synthetic unreadable store fixture")
    checks = clinical_checks(Store(clinical.path), lambda context: context.owner)
    for check in checks.values():
        assert check.verify_context("", clinical.contract, clinical.context) == (
            Outcome.INDETERMINATE, ("STORE_DEGRADED",))


@pytest.mark.parametrize("accepted", [False, True])
def test_product_spec_copies_the_supplied_gate_verdict(accepted):
    class ScriptedFactory:
        def run(self, prompt, profile, tenant, *, context):
            assert profile.gate_checks == frozenset({"input-guardrail", "grounded-critic"})
            return SimpleNamespace(output="Fictional problem statement", accepted=accepted,
                gate_reason="scripted contract verdict", run_id="scripted-offline-001",
                cost_usd=0, harness_name="scripted-no-provider")

    spec = product_spec_spec()
    outcome = make_product_spec_runner(ScriptedFactory())(StageRun(
        spec.stage("problem"), {"title": "Fixture", "idea": "Offline fixture"}, None, None))
    assert outcome.accepted is accepted
    assert outcome.reason == "scripted contract verdict"
    assert outcome.run_id == "scripted-offline-001"
    assert outcome.extra["cost_usd"] == 0


def test_product_contract_excludes_rejected_stages_and_readiness_refuses_stub():
    state = {"spec_id": "fixture", "stages": {
        "problem": {"output": "Accepted problem", "accepted": True},
        "spec": {"output": "Rejected PRD", "accepted": False}}}
    contract = build_product_spec_contract(state, False)
    assert contract["problem"] == "Accepted problem"
    assert contract["spec"] == "" and contract["approved"] is False
    runner = make_product_spec_runner(None)
    result = runner(StageRun(StageSpec("assemble", "Assemble", kind=KIND_ASSEMBLE),
                            {"contract": json.dumps(contract)}, None, None))
    assert result.accepted is False and "too thin" in result.reason
    view = product_spec_view(SimpleNamespace(get=lambda project_id: state), "fixture")
    assert view["pipeline"][-1]["accepted"] is False
    assert view["approved"] is False
