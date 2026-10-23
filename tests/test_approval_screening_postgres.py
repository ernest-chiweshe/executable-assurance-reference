"""Guarded integration of signed screening contracts, not a qualified detector.

The operational-labelled case below is explicitly a hypothetical protocol fixture.
It must never be cited as operational persuasion qualification or used by a host.
"""

from dataclasses import replace
import hashlib
import os

import pytest

from assurance_reference.approval_screening import (
    ApprovalScreening, SCREENING_FIELD, ScreenedMaterialReview, VERIFICATION_CLASS,
    screening_attestation,
)
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.qualified_engine import RequiredQualification
from assurance_reference.review_material import material_contract
from regulated_core.approval_evidence import ReviewError
from regulated_core.qualification import LabeledCase, QualificationDataset, qualify
from regulated_core.signing import Ed25519Signer, TrustDirectory


def screening_fixture(app, evidence_kind):
    authority = Ed25519Signer("fixture:screening-qualification")
    checker = Ed25519Signer("fixture:screening-checker")
    trust = TrustDirectory()
    trust.register_signer(authority)
    trust.register_signer(checker)
    dataset = QualificationDataset("fixture:protocol-only", "1", "No persuasion validation",
        (LabeledCase("yes", True), LabeledCase("no", False)))
    now = app.clock.read()
    report = qualify(authority, verification_class=VERIFICATION_CLASS, verifier_version="fixture:1",
        dataset=dataset, predicate=lambda text: text == "yes", qualified_at_us=now.now_us,
        valid_for_us=60_000_000, jurisdictions=("fixture",), languages=("en",),
        document_types=("fixture",), limitations=("Protocol fixture, no scientific qualification",))
    requirement = RequiredQualification(VERIFICATION_CLASS, "fixture:1", dataset.digest(),
                                       "fixture", "en", "fixture", "1", "1")
    policy = ApprovalScreening(trust=trust, checker_key_id=checker.key_id,
        qualification_authority=authority.key_id, clock=app.clock, requirement=requirement,
        report=report, escalation_route="fixture:independent-review", operational_admission=True)
    contract = material_contract(app.contract, prior_artifact=None,
        reversibility="Fictional first file; disclosure cannot be recalled",
        exposure="Fictional local feedback only", checker_findings=["Protocol fixture only"],
        uncertainty="No scientific persuasion qualification or human independence claim")
    contract[SCREENING_FIELD] = screening_attestation(signer=checker, contract=contract,
        tenant=app.context.tenant, verifier_version="fixture:1", qualification_digest=report.digest(),
        clock_domain=now.domain, observed_us=now.now_us, expires_us=now.now_us + 50_000_000,
        result="clear", evidence_kind=evidence_kind)
    return policy, contract


@pytest.mark.parametrize("evidence_kind", ["synthetic", "operational"],
                         ids=["synthetic-always-escalates", "hypothetical-eligible-contract"])
def test_screening_preserves_original_session_roles_quorum_and_receiving_guard(tmp_path, evidence_kind):
    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]), tmp_path)
    policy, contract = screening_fixture(app, evidence_kind)
    requester = app.gates["requester"]
    opened = requester.open_review(spec=app.spec, contract=contract, context=app.context)
    common = dict(spec=app.spec, contract=contract, review_id=opened["review_id"], artifact=app.body)
    # Even a hypothetical eligible screening result cannot turn the requester
    # into an entitled independent approver through the unchanged original gate.
    requester_adapter = ScreenedMaterialReview(requester, screening=policy)
    requester_context = replace(app.context, now_us=app.clock.now_us())
    requester_view = requester_adapter.view(**common, context=requester_context)
    with pytest.raises(ReviewError):
        requester_adapter.grant(**common, context=requester_context, role="teacher",
                                displayed_sha256=requester_view["display_sha256"])

    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        adapter = ScreenedMaterialReview(app.gates[principal], screening=policy)
        context = replace(app.context, actor_id=principal, now_us=app.clock.now_us())
        view = adapter.view(**common, context=context)
        disposition = view["bound"]["screening_disposition"]
        assert not disposition["scientific_qualification_established_by_this_check"]
        if evidence_kind == "synthetic":
            assert disposition["reason"] == "synthetic-evidence-only"
            with pytest.raises(ReviewError, match="requires escalation"):
                adapter.grant(**common, context=context, role=role,
                              displayed_sha256=view["display_sha256"])
            assert requester.get_review(spec=app.spec, contract=contract,
                context=replace(app.context, now_us=app.clock.now_us()),
                review_id=opened["review_id"])["approver_ids"] == []
        else:
            assert disposition["status"] == "CLEAR_BY_HOST_POLICY"
            adapter.grant(**common, context=context, role=role,
                          displayed_sha256=view["display_sha256"])
        release_context = replace(app.context, approval=opened["review_id"])
        decision = requester.authorize_release(spec=app.spec, contract=contract,
            context=release_context, artifact=app.body, out_path=str(app.path))
        if evidence_kind == "synthetic" or principal == "teacher":
            assert not decision.allowed
            assert not app.path.exists()
        else:
            assert decision.allowed, decision.reason
            result = requester.commit_release(spec=app.spec, contract=contract,
                context=release_context, decision=decision, artifact=app.body, out_path=str(app.path))
            assert result.state == "committed"
            assert app.path.read_bytes() == app.body
            assert requester.release_receipt(spec=app.spec, out_path=str(app.path),
                tenant=app.context.tenant, nonce=app.context.nonce,
                artifact_sha256=hashlib.sha256(app.body).hexdigest(),
                decision_record_hash=decision.permit.envelope.record_hash) is not None
    assert app.stores.recorder.verify_chain(app.context.tenant)
