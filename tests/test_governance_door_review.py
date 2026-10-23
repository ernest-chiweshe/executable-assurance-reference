"""Ordinary incomplete-review refusals with the same request later approved.

Synthetic actors and local clearance/retention only. Every certificate is made
by the unchanged approval workflow; no incomplete certificate is manufactured.
"""
import hashlib
import time

import pytest

from assurance_reference.governance_targets import pack_activation_target
from assurance_reference.packs import verify_bundles
from regulated_core import Action, ActionEffect, Actor, Assertion, PolicyContext, issue_credential
from regulated_core.approval import ApprovalError
from regulated_core.governance_targets import GOVERNANCE_CONTENT_TYPE, change_bytes
from regulated_core.models import DecisionKind
from regulated_core.target import BoundEffect, Outcome, effect_destination
from regulated_core.tier4 import issue_clearance
from test_governance_root_postgres import app as governance_app  # noqa: F401


@pytest.mark.parametrize("review_count", [0, 1], ids=["no-review", "one-approver"])
def test_incomplete_governance_review_refuses_then_two_approvers_commit(request, review_count):
    app = request.getfixturevalue("governance_app")
    tenant = "synthetic-office"
    reference = verify_bundles()["bundles"][0]["reference"]
    pack_id = reference.partition("#")[0]
    target = pack_activation_target(app.packs, reference, tenant_id=tenant,
        authority=app.engine.targets, uses=app.uses, log=app.log, budget=app.budget)
    output = change_bytes("pack-activation", pack_id,
                          {"activate": reference, "at": "synthetic incomplete review"})
    digest = hashlib.sha256(output).hexdigest()
    ctx = PolicyContext(tenant, Actor("requester", tenant, frozenset()),
                        "fixture:governance-door", "review-door", app.clock.now_us())
    assertion = Assertion("change-review-door", tenant, GOVERNANCE_CONTENT_TYPE, digest)
    mission = "fixture:governance-door:" + pack_id
    action = Action(target.operation, ActionEffect.EXTERNAL, destination=effect_destination(
        {}, BoundEffect(digest, target.target, target.current_state(), mission=mission)))
    capability = app.preflight.authorize(tenant_id=tenant, vertical="governance",
        action_id=target.operation, risk_tier=4, correlation_id=ctx.correlation_id,
        now_us=app.clock.now_us(), ttl_us=120_000_000, nonce="cap-review-door")
    parameters = dict(vertical="governance", capability=capability, assertion=assertion,
        action=action, ctx=ctx, output=output, target=target, permit_ttl_us=60_000_000)

    def unchanged():
        assert app.packs.active(pack_id) is None
        assert not app.log.events(tenant)
        assert app.budget.committed(tenant, mission) == 0
        assert not app.uses.used(tenant, "effect-review-door")

    unchanged()
    refused = app.packs.authorize(app.engine, **parameters, nonce="review-door-attempt")
    assert not refused.authorized and refused.permit is None
    unchanged()
    decision = next(entry for entry in reversed(app.recorder.entries(tenant))
                    if entry.record.decision.kind is DecisionKind.REQUIRE_APPROVAL)
    requirement = decision.record.decision.approval
    assert requirement.minimum_approvers == 2 and not requirement.requester_may_approve
    review = app.approvals.open(request_id="review-door", requester_id="requester",
        tenant_id=tenant, assertion_id=assertion.assertion_id,
        decision_record_id=decision.record.record_id, decision_record_hash=decision.record_hash,
        requirement=requirement, now_us=app.clock.now_us())

    def grant(principal):
        credential = issue_credential(app.keys["identity"], actor_id=principal, tenant_id=tenant,
            kind="role:governance-approver", expires_at_us=app.clock.now_us() + 120_000_000)
        return app.approvals.grant(review, Actor(principal, tenant, frozenset(), (credential,)),
                                   app.clock.now_us())

    grants = [grant("reviewer-a")] if review_count else []
    with pytest.raises(ApprovalError):
        app.approvals.finalize(review, grants, app.clock.now_us())
    unchanged()
    # Without a completed review the real policy door still issues no permit.
    refused_again = app.packs.authorize(app.engine, **parameters, nonce="incomplete-review-attempt")
    assert not refused_again.authorized and refused_again.permit is None
    unchanged()

    if not grants:
        grants.append(grant("reviewer-a"))
    grants.append(grant("reviewer-b"))
    certificate = app.approvals.finalize(review, grants, app.clock.now_us())
    remaining = decision.record.decided_at_us + app.cooling - app.clock.now_us()
    if remaining > 0:
        time.sleep(remaining / 1_000_000)
    app.clearances.put(issue_clearance(app.keys["monitor"], decision,
                                      cleared_at_us=app.clock.now_us()))
    authorized = app.packs.authorize(app.engine, **parameters, nonce="effect-review-door",
        approval_cert=certificate, approval_evidence=decision)
    assert authorized.authorized and authorized.permit is not None, authorized.reason
    result = app.engine.commit(authorized, output, target)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.packs.active(pack_id).reference == reference
    assert app.budget.committed(tenant, mission) == 1
    assert [event.phase for event in app.log.events(tenant)] == ["prepared", "committed"]
    assert app.recorder.verify_chain(tenant)
