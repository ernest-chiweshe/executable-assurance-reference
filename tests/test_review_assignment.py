"""Detached host-roster contracts; no real institutional independence claim."""

import pytest

from assurance_reference.review_assignment import AssignedScreenedMaterialReview, ReviewAssignmentPolicy
from regulated_core.approval_evidence import ReviewError
from test_approval_screening import fixture_case
from test_review_material import ViewFixture


class Directory:
    def __init__(self):
        self.lines = {"reviewer": "teaching", "teacher-two": "second-teaching", "head": "leadership",
                      "author": "requester", "producer": "generation"}

    def reporting_line(self, tenant_id, subject_id):
        assert tenant_id == "one"
        return self.lines.get(subject_id)


def setup(*, rotation=0, synthetic=False):
    case = fixture_case(admit=True, kind="synthetic" if synthetic else "operational")
    directory = Directory()
    roster = {"teacher": ["reviewer", "teacher-two"], "head": ["head"]}
    policy = ReviewAssignmentPolicy(tenant="one", review_id="review:fixture", decision_record_hash="a" * 64,
        roster=roster, directory=directory, rotation_index=rotation, excluded_principals=("producer",),
        escalation_route="fixture:independent-review")
    gate = ViewFixture()
    return case, directory, roster, policy, gate, AssignedScreenedMaterialReview(
        gate, screening=case.policy, assignment=policy)


def test_assigned_reviewer_still_uses_screening_display_and_original_grant():
    case, _, _, _, gate, adapter = setup()
    view = adapter.view(**case.request)
    assignment = view["bound"]["assignment"]
    assert assignment["status"] == "ASSIGNED_BY_HOST_POLICY"
    assert not assignment["institutional_independence_established"]
    adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert len(gate.grants) == 1


def test_rotation_selects_alternative_without_performance_or_refusal_inputs():
    case, _, _, _, gate, adapter = setup(rotation=1)
    view = adapter.view(**case.request)
    assert view["bound"]["assignment"]["selected"][0]["principal"] == "teacher-two"
    with pytest.raises(ReviewError, match="assignment"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants


@pytest.mark.parametrize("change", ["missing", "same", "unavailable"])
def test_unknown_same_or_unavailable_reporting_lines_escalate(change):
    case, directory, _, _, gate, adapter = setup()
    if change == "missing":
        directory.lines.pop("head")
    elif change == "same":
        directory.lines["head"] = "teaching"
    else:
        def unavailable(*args):
            raise RuntimeError("synthetic directory outage")
        directory.reporting_line = unavailable
    view = adapter.view(**case.request)
    assert view["bound"]["assignment"]["status"] == "ESCALATE"
    assert view["bound"]["assignment"]["selected"] == []
    with pytest.raises(ReviewError):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants


def test_changed_directory_invalidates_display_acknowledgement():
    case, directory, _, _, gate, adapter = setup()
    view = adapter.view(**case.request)
    directory.lines["reviewer"] = "changed-line"
    with pytest.raises(ReviewError, match="display changed"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants


def test_assignment_does_not_override_synthetic_screening_escalation():
    case, _, _, _, gate, adapter = setup(synthetic=True)
    view = adapter.view(**case.request)
    assert view["bound"]["assignment"]["status"] == "ASSIGNED_BY_HOST_POLICY"
    with pytest.raises(ReviewError, match="screening requires escalation"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants


def test_roster_is_detached_from_later_mutation_and_wrong_role_refuses():
    case, _, roster, _, gate, adapter = setup()
    roster["teacher"][:] = ["author"]
    view = adapter.view(**case.request)
    assert view["bound"]["assignment"]["selected"][0]["principal"] == "reviewer"
    with pytest.raises(ReviewError, match="assignment"):
        adapter.grant(**case.request, role="head", displayed_sha256=view["display_sha256"])
    assert not gate.grants


@pytest.mark.parametrize("field,value", [("tenant", "two"), ("review_id", "other"),
                                       ("decision_record_hash", "b" * 64)])
def test_assignment_cannot_be_reused_for_another_verified_review(field, value):
    case, _, _, policy, _, adapter = setup()
    bound = adapter.view(**case.request)["bound"]
    assert policy.assess({**bound, field: value})["reason"] == "review-binding-differs"


def test_requester_and_explicit_producer_excluded_even_if_on_roster():
    directory = Directory()
    policy = ReviewAssignmentPolicy(tenant="one", review_id="review:fixture", decision_record_hash="a" * 64,
        roster={"teacher": ["author", "producer", "reviewer"], "head": ["head"]},
        directory=directory, rotation_index=0, excluded_principals=("producer",), escalation_route="route")
    case, _, _, _, _, adapter = setup()
    selected = policy.assess(adapter.view(**case.request)["bound"])["selected"]
    assert [row["principal"] for row in selected] == ["reviewer", "head"]


@pytest.mark.parametrize("rotation", [-1, True, 2**63])
def test_invalid_rotation_refuses_at_configuration(rotation):
    with pytest.raises(ValueError):
        setup(rotation=rotation)


def test_assignment_never_overrides_original_grant_refusal():
    case, _, _, policy, _, _ = setup()

    class RefusingGate(ViewFixture):
        def grant_review(self, **request):
            raise ReviewError("original credential or quorum refusal")

    adapter = AssignedScreenedMaterialReview(RefusingGate(), screening=case.policy, assignment=policy)
    view = adapter.view(**case.request)
    with pytest.raises(ReviewError, match="original credential or quorum refusal"):
        adapter.grant(**case.request, role="teacher", displayed_sha256=view["display_sha256"])


def test_unsupported_quorum_never_reduces_original_minimum():
    case, _, _, policy, _, adapter = setup()
    bound = adapter.view(**case.request)["bound"]
    result = policy.assess({**bound, "minimum_approvers": 3})
    assert result["status"] == "ESCALATE"
    assert result["selected"] == []
