"""Guarded assignment integration with fictional directory and screening inputs.

These protocol fixtures establish neither a qualified persuasion detector nor
real-world reporting-line independence. Original grant/effect guards stay intact.
"""

from dataclasses import replace
import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.review_assignment import AssignedScreenedMaterialReview, ReviewAssignmentPolicy
from regulated_core.approval_evidence import ReviewError
from test_approval_screening_postgres import screening_fixture


class FictionalDirectory:
    def __init__(self, tenant, complete):
        self.tenant, self.complete = tenant, complete

    def reporting_line(self, tenant_id, subject_id):
        assert tenant_id == self.tenant
        if not self.complete:
            return None
        return {"teacher": "fixture:teaching", "head": "fixture:leadership",
                "requester": "fixture:requester"}.get(subject_id)


@pytest.mark.parametrize("directory_complete", [False, True], ids=["unknown-lines-escalate", "assigned-two-role-release"])
def test_assigned_screened_route_preserves_original_quorum_and_receiving_guard(tmp_path, directory_complete):
    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]), tmp_path)
    screening, contract = screening_fixture(app, "operational")  # Hypothetical signed fixture only.
    requester = app.gates["requester"]
    opened = requester.open_review(spec=app.spec, contract=contract, context=app.context)
    common = dict(spec=app.spec, contract=contract, review_id=opened["review_id"], artifact=app.body)
    verified = requester.get_review(spec=app.spec, contract=contract, review_id=opened["review_id"],
                                    context=replace(app.context, now_us=app.clock.now_us()))
    assignment = ReviewAssignmentPolicy(tenant=app.context.tenant, review_id=opened["review_id"],
        decision_record_hash=verified["decision_record_hash"],
        roster={"teacher": ["requester", "teacher"], "head-of-department": ["head"]},
        directory=FictionalDirectory(app.context.tenant, directory_complete), rotation_index=0,
        excluded_principals=("fixture:producer",), escalation_route="fixture:independent-review")
    route = AssignedScreenedMaterialReview(requester, screening=screening, assignment=assignment)
    context = replace(app.context, now_us=app.clock.now_us())
    view = route.view(**common, context=context)
    with pytest.raises(ReviewError, match="assignment"):
        route.grant(**common, context=context, role="teacher", displayed_sha256=view["display_sha256"])

    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        route = AssignedScreenedMaterialReview(app.gates[principal], screening=screening, assignment=assignment)
        context = replace(app.context, actor_id=principal, now_us=app.clock.now_us())
        view = route.view(**common, context=context)
        if directory_complete:
            assert view["bound"]["assignment"]["status"] == "ASSIGNED_BY_HOST_POLICY"
            route.grant(**common, context=context, role=role, displayed_sha256=view["display_sha256"])
        else:
            assert view["bound"]["assignment"]["status"] == "ESCALATE"
            with pytest.raises(ReviewError, match="assignment"):
                route.grant(**common, context=context, role=role, displayed_sha256=view["display_sha256"])
            retained = requester.get_review(spec=app.spec, contract=contract, review_id=opened["review_id"],
                                            context=replace(app.context, now_us=app.clock.now_us()))
            assert retained["approver_ids"] == []
        release_context = replace(app.context, approval=opened["review_id"])
        decision = requester.authorize_release(spec=app.spec, contract=contract, context=release_context,
                                               artifact=app.body, out_path=str(app.path))
        if not directory_complete or principal == "teacher":
            assert not decision.allowed
            assert not app.path.exists()
        else:
            assert decision.allowed, decision.reason
            outcome = requester.commit_release(spec=app.spec, contract=contract, context=release_context,
                decision=decision, artifact=app.body, out_path=str(app.path))
            assert outcome.state == "committed"
            assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(app.context.tenant)
