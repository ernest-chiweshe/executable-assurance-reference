"""X-7: the authenticated actor is bound to the governance and delegation review (transport excluded).

Governance review: an approver acts only through an identity-signed credential bound to that exact actor and tenant.
Delegation review: each review gate is bound to one authenticated retained session; it cannot act for another
principal. Synthetic actors; isolated PostgreSQL. A revoked delegation reviewer session is covered by
test_delegation_reviewer_session.py.
"""
from dataclasses import replace
import os

import pytest

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core import Action, ActionEffect, Actor, Assertion, PolicyContext, issue_credential
from regulated_core.approval import ApprovalError
from regulated_core.approval_exchange import ReviewError
from regulated_core.governance_targets import GOVERNANCE_CONTENT_TYPE, change_bytes
from regulated_core.models import DecisionKind
from regulated_core.signing import Ed25519Signer
from regulated_core.target import BoundEffect, effect_destination
from assurance_reference.governance_targets import pack_activation_target
from assurance_reference.packs import verify_bundles
from synthetic_bounded_education import SYNTHETIC_PUBLISHER, build_bounded_education_fixture
from test_governance_root_postgres import app as governance_app  # noqa: F401

TENANT = "synthetic-office"


@pytest.fixture
def governance_review(governance_app):  # noqa: F811
    app = governance_app
    reference = verify_bundles()["bundles"][0]["reference"]
    pack_id = reference.partition("#")[0]
    target = pack_activation_target(app.packs, reference, tenant_id=TENANT, authority=app.engine.targets,
                                    uses=app.uses, log=app.log, budget=app.budget)
    output = change_bytes("pack-activation", pack_id, {"activate": reference, "at": "synthetic actor binding"})
    import hashlib
    digest = hashlib.sha256(output).hexdigest()
    ctx = PolicyContext(TENANT, Actor("requester", TENANT, frozenset()), "fixture:governance-door", "x7-door",
                        app.clock.now_us())
    assertion = Assertion("change-x7", TENANT, GOVERNANCE_CONTENT_TYPE, digest)
    action = Action(target.operation, ActionEffect.EXTERNAL, destination=effect_destination(
        {}, BoundEffect(digest, target.target, target.current_state(), mission="fixture:x7:" + pack_id)))
    capability = app.preflight.authorize(tenant_id=TENANT, vertical="governance", action_id=target.operation,
        risk_tier=4, correlation_id=ctx.correlation_id, now_us=app.clock.now_us(), ttl_us=120_000_000,
        nonce="cap-x7")
    refused = app.packs.authorize(app.engine, vertical="governance", capability=capability, assertion=assertion,
        action=action, ctx=ctx, output=output, target=target, permit_ttl_us=60_000_000, nonce="x7-attempt")
    assert not refused.authorized
    decision = next(entry for entry in reversed(app.recorder.entries(TENANT))
                    if entry.record.decision.kind is DecisionKind.REQUIRE_APPROVAL)
    review = app.approvals.open(request_id="x7-review", requester_id="requester", tenant_id=TENANT,
        assertion_id=assertion.assertion_id, decision_record_id=decision.record.record_id,
        decision_record_hash=decision.record_hash, requirement=decision.record.decision.approval,
        now_us=app.clock.now_us())

    def credential(principal, *, tenant=TENANT, expires_in_us=120_000_000):
        return issue_credential(app.keys["identity"], actor_id=principal, tenant_id=tenant,
                                kind="role:governance-approver", expires_at_us=app.clock.now_us() + expires_in_us)

    def grant(actor, credentials):
        return app.approvals.grant(review, Actor(actor, TENANT, frozenset(), tuple(credentials)), app.clock.now_us())

    return app, credential, grant


def test_authenticated_governance_approver_is_bound_to_its_review(governance_review):
    app, credential, grant = governance_review
    assert grant("reviewer-a", [credential("reviewer-a")]).reviewer_id == "reviewer-a"


@pytest.mark.parametrize("case", ["no-credential", "another-actors-credential", "expired-credential",
                                  "another-tenants-credential", "forged-identity-signer"])
def test_unauthenticated_or_mismatched_governance_actor_is_refused_at_review(governance_review, case):
    app, credential, grant = governance_review
    presented = {
        "no-credential": [],
        "another-actors-credential": [credential("reviewer-a")],
        "expired-credential": [credential("reviewer-b", expires_in_us=-1)],
        "another-tenants-credential": [credential("reviewer-b", tenant="synthetic-other-office")],
        "forged-identity-signer": [issue_credential(Ed25519Signer(app.keys["identity"].key_id), actor_id="reviewer-b",
                                                    tenant_id=TENANT, kind="role:governance-approver",
                                                    expires_at_us=app.clock.now_us() + 120_000_000)],
    }[case]
    with pytest.raises(ApprovalError):
        grant("reviewer-b", presented)


def test_delegation_review_gate_cannot_act_for_another_principal(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "signed-budget-pack"
    build_bounded_education_fixture(bundle, publisher=publisher)
    app = build_education_fixture(roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
                                  fixture_budget_limit=None, fixture_validity_us=300_000_000,
                                  delegation_signer=Ed25519Signer("fictional:x7-delegation"),
                                  delegation_source_status=lambda tenant, grant: None)
    context = replace(app.context, nonce="x7-delegation-review", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opened = app.gates["requester"].open_delegation_review(**common, context=context, destinations=(str(app.path),),
        expires_in_us=60_000_000, admit_within_us=30_000_000, delegable=True)
    request = dict(**common, delegation_review_id=opened["delegation_review_id"])
    # The teacher's authenticated gate claims to act as the head of department.
    with pytest.raises((ReviewError, ValueError)):
        app.gates["teacher"].grant_delegation_review(**request, role="head-of-department",
            context=replace(context, actor_id="head", now_us=app.clock.now_us()))
    # The requester's own gate cannot be used to grant as the teacher either.
    with pytest.raises((ReviewError, ValueError)):
        app.gates["requester"].grant_delegation_review(**request, role="teacher",
            context=replace(context, actor_id="teacher", now_us=app.clock.now_us()))
    state = app.gates["requester"].get_delegation_review(**request, context=replace(context, now_us=app.clock.now_us()))
    assert state["status"] == "awaiting-review"
