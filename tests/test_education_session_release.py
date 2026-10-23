"""Fictional local Education release with real retained sessions and two reviews.

This exercises the restricted host, not X-6 appointment scopes or X-19 witnesses.
All people, credentials, qualification data and source content are test fixtures.
"""

from dataclasses import replace
import hashlib
import os

import pytest

from assurance_reference.local_roles import provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.local_retention import LocalRetentionStore
from regulated_core.canonical import canonical_bytes
from regulated_core.clock_pg import DbClock
from regulated_core.approval_evidence import ReviewError

from assurance_reference.local_education_fixture import build_education_fixture
from education_fault_fixtures import AcknowledgementSessions, FaultClock, FaultRetention


@pytest.fixture
def education(tmp_path, request):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    faults = bool(getattr(request, "param", False))
    source = FaultClock(DbClock(roles.receiver, roles.domain)) if faults else None
    retention = FaultRetention(LocalRetentionStore(tmp_path / "retention")) if faults else None
    return build_education_fixture(roles, tmp_path, clock_source=source, retention=retention,
        session_type=AcknowledgementSessions if faults else LocalSessions)


def reviewed_context(app):
    gate = app.gates["requester"]
    opened = gate.open_review(spec=app.spec, contract=app.contract, context=app.context)
    assert opened["minimum_approvers"] == 2
    assert opened["status"] == "awaiting-review"
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        state = app.gates[principal].grant_review(spec=app.spec, contract=app.contract,
            context=replace(app.context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
        if principal == "teacher":
            assert state["status"] == "awaiting-review"
            refused = gate.authorize_release(spec=app.spec, contract=app.contract, out_path=str(app.path),
                context=replace(app.context, approval=opened["review_id"]), artifact=app.body)
            assert not refused.allowed
            assert not app.path.exists()
    assert state["status"] == "approved"
    return replace(app.context, approval=opened["review_id"])


def approved_request(app, *, effect_window_us=None):
    context = reviewed_context(app)
    gate = app.gates["requester"]
    if effect_window_us is not None:
        context = replace(context, not_after_us=app.clock.now_us() + effect_window_us)
    decision = gate.authorize_release(spec=app.spec, contract=app.contract, out_path=str(app.path),
                                       context=context, artifact=app.body)
    assert decision.allowed, decision.reason
    assert decision.permit.permit.permit.qualification_digests == (app.report.digest(),)
    return context, decision


def test_two_authenticated_reviewers_release_exact_fictional_artifact(education):
    app = education
    context, decision = approved_request(app)
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
    receipt = app.gates["requester"].release_receipt(spec=app.spec, out_path=str(app.path),
        tenant="school-a", nonce=context.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None
    (app.path.parent / "education-release-evidence.json").write_bytes(canonical_bytes({
        "scope": "Fictional local Education request; full D1 remains OPEN",
        "public_keys": app.public_keys, "contract": app.contract,
        "signed_permit": decision.permit.permit, "receiving_receipt": receipt,
        "outcome": result, "chain": app.stores.recorder.entries("school-a"),
        "limits": ["No deployed IAM, HSM or compliance WORM claim.",
                   "No scoped appointment or human source-witness qualification.",
                   "Synthetic marker qualification is not educational or clinical validation."],
    }))


def test_revoked_requester_session_refuses_previously_approved_release(education):
    app = education
    context, decision = approved_request(app)
    app.sessions.revoke(app.identities["requester"])
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        decision=decision, artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "failed", result
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")
    (app.path.parent / "education-revocation-evidence.json").write_bytes(canonical_bytes({
        "scope": "Authenticated requester revoked after approval and before target admission",
        "public_keys": app.public_keys, "signed_permit": decision.permit.permit,
        "outcome": result, "target_exists": app.path.exists(),
        "chain": app.stores.recorder.entries("school-a"),
    }))


@pytest.mark.parametrize("case", ["same-person-two-roles", "requester-self-review", "wrong-tenant"])
def test_review_separation_stops_at_approval_boundary(education, case):
    app = education
    opened = app.gates["requester"].open_review(spec=app.spec, contract=app.contract, context=app.context)
    review_id = opened["review_id"]
    common = {"spec": app.spec, "contract": app.contract, "review_id": review_id}
    if case == "same-person-two-roles":
        # Two valid fixture credentials do not make one person two approvers.
        app.certify("teacher", "head-of-department")
        for role in ("teacher", "head-of-department"):
            state = app.gates["teacher"].grant_review(**common, role=role,
                context=replace(app.context, actor_id="teacher", now_us=app.clock.now_us()))
        assert state["approver_ids"] == ["teacher"]
    elif case == "requester-self-review":
        app.certify("requester", "teacher")
        with pytest.raises(ReviewError):
            app.gates["requester"].grant_review(**common, role="teacher",
                context=replace(app.context, now_us=app.clock.now_us()))
    else:
        # An actual second-tenant session, not an asserted tenant/role string.
        app.sessions.provision_identity("school-b", "other-teacher", "other.local", "fictional-password-002")
        identity = app.sessions.authenticate("school-b", app.sessions.login(
            "school-b", "other.local", "fictional-password-002"))
        app.certify("other-teacher", "teacher")
        gate = app.make_gate(identity)
        with pytest.raises(ReviewError):
            gate.grant_review(**common, role="teacher", context=replace(app.context,
                tenant="school-b", actor_id="other-teacher", now_us=app.clock.now_us()))
    state = app.gates["requester"].get_review(**common,
        context=replace(app.context, now_us=app.clock.now_us()))
    assert state["status"] == "awaiting-review"
    refused = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), artifact=app.body, context=replace(app.context, approval=review_id))
    assert not refused.allowed
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")
