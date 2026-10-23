"""Offline signed contract fixtures only; no qualified persuasion detector exists here."""

from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from assurance_reference.approval_screening import (
    ApprovalScreening, SCREENING_FIELD, ScreenedMaterialReview, VERIFICATION_CLASS,
    screening_attestation,
)
from assurance_reference.qualified_engine import RequiredQualification
from assurance_reference.review_material import commentary_contract, render_review
from regulated_core.approval_evidence import ReviewError
from regulated_core.clock import ClockReading
from regulated_core.qualification import LabeledCase, QualificationDataset, qualify
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_review_material import ViewFixture, inputs


class Clock:
    domain = "fixture:screening-clock"
    now = 150

    def read(self):
        return ClockReading(self.domain, self.now)


def fixture_case(*, admit=False, kind="synthetic", result="clear"):
    authority, checker = Ed25519Signer("fixture:qualification"), Ed25519Signer("fixture:checker")
    trust = TrustDirectory()
    trust.register_signer(authority)
    trust.register_signer(checker)
    data = QualificationDataset("synthetic-protocol-only", "1", "Not persuasion validation",
        (LabeledCase("fixture-positive", True), LabeledCase("fixture-negative", False)))
    report = qualify(authority, verification_class=VERIFICATION_CLASS, verifier_version="fixture:1",
        dataset=data, predicate=lambda text: text == "fixture-positive", qualified_at_us=100,
        valid_for_us=100, jurisdictions=("fixture",), languages=("en",),
        document_types=("synthetic-protocol",), limitations=("Not scientific qualification",))
    requirement = RequiredQualification(VERIFICATION_CLASS, "fixture:1", data.digest(),
        "fixture", "en", "synthetic-protocol", "1", "1")
    clock = Clock()
    policy = ApprovalScreening(trust=trust, checker_key_id=checker.key_id,
        qualification_authority=authority.key_id, clock=clock, requirement=requirement, report=report,
        escalation_route="fixture:independent-review", operational_admission=admit)
    request = inputs()
    evidence = screening_attestation(signer=checker, contract=request["contract"], tenant="one",
        verifier_version="fixture:1", qualification_digest=report.digest(), clock_domain=clock.domain,
        observed_us=120, expires_us=190, result=result, evidence_kind=kind)
    request["contract"][SCREENING_FIELD] = evidence
    return SimpleNamespace(policy=policy, clock=clock, checker=checker, trust=trust,
                           report=report, request=request)


@pytest.mark.parametrize("admit", [False, True])
def test_synthetic_clear_always_escalates_even_when_host_enabled(admit):
    case = fixture_case(admit=admit)
    gate = ViewFixture()
    adapter = ScreenedMaterialReview(gate, screening=case.policy)
    view = adapter.view(**case.request)
    disposition = view["bound"]["screening_disposition"]
    assert disposition["reason"] == "synthetic-evidence-only"
    assert not disposition["eligible_for_grant"]
    assert "ESCALATE" in render_review(view)
    assert "fixture:independent-review" in render_review(view)
    with pytest.raises(ReviewError, match="requires escalation"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert gate.grants == []


def test_operational_label_is_insufficient_without_host_admission():
    # A synthetic fixture encodes a hypothetical operational attestation. This
    # tests protocol disposition, not a claim of real-world qualification.
    case = fixture_case(kind="operational")
    assert case.policy.assess(case.request["contract"], tenant="one")["reason"] == (
        "operational-qualification-not-admitted")


def test_commentary_added_after_screening_requires_new_screening_evidence():
    case = fixture_case(admit=True, kind="operational")
    changed = commentary_contract(case.request["contract"], text="New shared explanation")
    result = case.policy.assess(changed, tenant="one")
    assert not result["eligible_for_grant"]
    assert result["reason"] == "missing-invalid-or-unqualified-evidence"


@pytest.mark.parametrize("result", ["flagged", "unknown"])
def test_flagged_or_unknown_never_enables_grant(result):
    case = fixture_case(admit=True, kind="operational", result=result)
    verdict = case.policy.assess(case.request["contract"], tenant="one")
    assert verdict["reason"] == "screening-" + result
    assert not verdict["eligible_for_grant"]


def test_hypothetical_eligible_contract_still_requires_display_ack_and_original_grant():
    case = fixture_case(admit=True, kind="operational")
    gate = ViewFixture()
    adapter = ScreenedMaterialReview(gate, screening=case.policy)
    view = adapter.view(**case.request)
    verdict = view["bound"]["screening_disposition"]
    assert verdict["status"] == "CLEAR_BY_HOST_POLICY"
    assert not verdict["scientific_qualification_established_by_this_check"]
    with pytest.raises(ReviewError, match="renewed review"):
        adapter.grant(**case.request, role="teacher", displayed_sha256="f" * 64)
    assert not gate.grants
    assert adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert len(gate.grants) == 1


@pytest.mark.parametrize("field,value", [
    ("tenant", "other"), ("contract_scope_sha256", "0" * 64),
    ("artifact_sha256", "0" * 64), ("verifier_version", "other"),
    ("qualification_digest", "0" * 64), ("clock_domain", "other"),
    ("observed_us", 151), ("observed_us", 99), ("expires_us", 150), ("expires_us", 201),
])
def test_signed_but_inapplicable_observation_stays_incomplete(field, value):
    case = fixture_case(admit=True, kind="operational")
    signed = case.request["contract"][SCREENING_FIELD]
    signed["body"][field] = value
    signed["signature"] = asdict(case.checker.sign(signed["body"]))
    verdict = case.policy.assess(case.request["contract"], tenant="one")
    assert verdict["reason"] == "missing-invalid-or-unqualified-evidence"
    assert not verdict["eligible_for_grant"]


@pytest.mark.parametrize("change", ["missing", "content", "signer", "report", "target", "commentary"])
def test_unverified_or_changed_evidence_cannot_enable_grant(change):
    case = fixture_case(admit=True, kind="operational")
    contract = case.request["contract"]
    if change == "missing":
        del contract[SCREENING_FIELD]
    elif change == "content":
        contract[SCREENING_FIELD]["body"]["result"] = "unknown"
    elif change == "signer":
        signed = contract[SCREENING_FIELD]
        signed["signature"] = asdict(Ed25519Signer(case.checker.key_id).sign(signed["body"]))
    elif change == "report":
        case.policy._qualification._reports = (replace(case.report, dataset_version="changed"),)
    elif change == "target":
        contract["release_target"]["identity"] = "different"
    else:
        contract["model_commentary"] = "New content is covered by screening scope too"
    assert not case.policy.assess(contract, tenant="one")["eligible_for_grant"]


def test_stale_view_rechecks_clock_before_any_grant():
    case = fixture_case(admit=True, kind="operational")
    gate = ViewFixture()
    adapter = ScreenedMaterialReview(gate, screening=case.policy)
    before = deepcopy(case.request)
    view = adapter.view(**case.request)
    case.clock.now = 190
    with pytest.raises(ReviewError, match="requires escalation"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants
    assert case.request["contract"] == before["contract"]
