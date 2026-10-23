"""Ordinary missing-class and missing-approval requests at the installed pack engine."""

from dataclasses import replace

import pytest

from factory.packs.rulebook import RulebookPolicy
from test_education_session_release import education  # noqa: F401

# ruff: noqa: F811


def fresh_review(app):
    context = replace(app.context, nonce="reviewed-positive-control", now_us=app.clock.now_us())
    opened = app.gates["requester"].open_review(spec=app.spec, contract=app.contract, context=context)
    assert opened["status"] == "awaiting-review"
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        state = app.gates[principal].grant_review(spec=app.spec, contract=app.contract,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
    assert state["status"] == "approved"
    return replace(context, approval=opened["review_id"], now_us=app.clock.now_us())


@pytest.mark.parametrize("case", ["unclassified", "unapproved"])
def test_installed_education_rulebook_refuses_incomplete_request(education, case):
    app = education
    gate = app.gates["requester"]
    context = replace(app.context, now_us=app.clock.now_us())
    assertion, action, capability, policy_context = gate._build(app.contract, context)
    policy = gate._engine._registry.resolve(assertion.content_type)
    assert isinstance(policy, RulebookPolicy)
    assert assertion.data_classes
    assert policy.effective_content["data_classes"]
    assert policy.effective_content["rules"][action.action_id]["approval"]
    # These are ordinary incomplete input values; the policy and all engine guards stay intact.
    if case == "unclassified":
        assertion = replace(assertion, data_classes=frozenset())
    nonce = "pack-rulebook-" + case
    prior_count = len(app.stores.recorder.entries(context.tenant))
    refused = gate._engine.authorize_for_target(
        vertical=gate.VERTICAL, capability=capability, assertion=assertion, action=action,
        ctx=policy_context, output=app.body, target=gate.target_for(str(app.path), context.tenant),
        permit_ttl_us=60_000_000, nonce=nonce, not_after_us=context.not_after_us,
    )
    expected = "DATA_UNCLASSIFIED" if case == "unclassified" else "APPROVAL_MISSING"
    assert not refused.authorized and refused.permit is None
    assert refused.envelope.record.decision.reason_codes == (expected,)
    assert refused.envelope.record.decision.kind.value == "deny"
    if case == "unapproved":
        # This actual fixture has no confidence evidence: its signed rulebook
        # requires SECOND_REVIEW before reaching the ordinary approval clause.
        assert assertion.confidence is None
        assert policy.effective_content["rules"][action.action_id]["second_review"]
        new_entries = app.stores.recorder.entries(context.tenant)[prior_count:]
        assert any(entry.record.policy == policy.ref
                   and entry.record.decision.kind.value == "require-approval"
                   and entry.record.decision.reason_codes == ("SECOND_REVIEW",)
                   for entry in new_entries)
    assert app.stores.recorder.verify_entry(refused.envelope)
    assert app.stores.recorder.verify_chain(context.tenant)
    assert not app.path.exists() and not app.stores.permits.used(context.tenant, nonce)
    # The same installed pack still accepts an ordinary, fully reviewed application release.
    approved_context = fresh_review(app)
    allowed = gate.authorize_release(spec=app.spec, contract=app.contract, out_path=str(app.path),
        context=approved_context, artifact=app.body)
    assert allowed.allowed, allowed.reason
    result = gate.commit_release(spec=app.spec, contract=app.contract, context=approved_context,
        decision=allowed, artifact=app.body, out_path=str(app.path))
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(context.tenant)
