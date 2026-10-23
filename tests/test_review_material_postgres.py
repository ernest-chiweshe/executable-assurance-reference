"""A22 artifact-binding increment through the unchanged two-role Education gate."""

from dataclasses import replace
import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.review_material import MATERIAL_FIELD, MaterialReview, material_contract
from regulated_core.approval_evidence import ReviewError


def test_signed_material_two_reviewers_and_exact_guarded_release(tmp_path):
    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]), tmp_path)
    contract = material_contract(app.contract, prior_artifact=None,
        reversibility="Fictional first local file; no claimed recall after disclosure",
        exposure="Fictional local feedback file", checker_findings=["Synthetic marker fixture only"],
        uncertainty="No qualified persuasion screening or human-comprehension claim")
    requester = app.gates["requester"]
    opened = requester.open_review(spec=app.spec, contract=contract, context=app.context)
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        context = replace(app.context, actor_id=principal, now_us=app.clock.now_us())
        adapter = MaterialReview(app.gates[principal])
        request = dict(spec=app.spec, contract=contract, context=context,
                       review_id=opened["review_id"], artifact=app.body)
        view = adapter.view(**request)
        # Detached changed declaration is checked against the original signed
        # contract by get_review, not merely against our local display checksum.
        changed = {**contract, MATERIAL_FIELD: {**contract[MATERIAL_FIELD], "exposure": "changed"}}
        with pytest.raises(ReviewError, match="does not bind"):
            adapter.view(**{**request, "contract": changed})
        with pytest.raises(ReviewError, match="renewed review"):
            adapter.grant(**request, role=role, displayed_sha256="0" * 64)
        assert requester.get_review(spec=app.spec, contract=contract,
                                    context=replace(app.context, now_us=app.clock.now_us()),
                                    review_id=opened["review_id"])["approver_ids"] == (
                                        [] if principal == "teacher" else ["teacher"])
        result = adapter.grant(**request, role=role, displayed_sha256=view["display_sha256"])
        approved_context = replace(app.context, approval=opened["review_id"])
        decision = requester.authorize_release(spec=app.spec, contract=contract,
            context=approved_context, artifact=app.body, out_path=str(app.path))
        if principal == "teacher":
            assert result["status"] == "awaiting-review"
            assert not decision.allowed
            assert not app.path.exists()
        else:
            assert result["status"] == "approved"
            assert decision.allowed, decision.reason
            committed = requester.commit_release(spec=app.spec, contract=contract,
                context=approved_context, decision=decision, artifact=app.body, out_path=str(app.path))
            assert committed.state == "committed"
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
