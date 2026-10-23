"""Synthetic signed approval admission; no database, effects or guard changes."""
from hashlib import sha256
from types import SimpleNamespace

import pytest

from assurance_reference.epoch_withdrawal_admission import (
    KIND, OPERATION, checked_change, withdrawal_bytes, verify_supervisor_approval,
)
from regulated_core.approval import ApprovedDecision, ApprovalWorkflow
from regulated_core.evidence import DecisionRecorder
from regulated_core.governance_roster import GovernanceRoster, RosterCredentials, RosterMember
from regulated_core.governance_targets import GovernanceWithdrawalPolicy, WITHDRAWAL_CONTENT_TYPE, WITHDRAWAL_ROLE
from regulated_core.identity import IdentityVerifier
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Action, ActionEffect, Actor, Assertion, PolicyContext
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import BoundEffect, TargetRef, effect_destination


class SyntheticRosterObservation:
    """Read-only fixture, not persisted roster-authority qualification."""
    def __init__(self):
        self.roster = GovernanceRoster("fixture-installation", 1, (
            RosterMember("supervisor-a", frozenset({WITHDRAWAL_ROLE}), "line-a"),
            RosterMember("supervisor-b", frozenset({WITHDRAWAL_ROLE}), "line-b"),
            RosterMember("ordinary-approver", frozenset({"governance-approver"}), "line-c"),
        ), frozenset({"synthetic-monitor"}), True)

    def current(self, installation):
        assert installation == self.roster.installation
        return self.roster


def composition(approver_count=1):
    trust = TrustDirectory()
    keys = {n: Ed25519Signer("synthetic-withdrawal:" + n)
            for n in ("evidence", "approval", "identity", "roster")}
    for signer in keys.values():
        trust.register_signer(signer)
    workflow = ApprovalWorkflow(trust, keys["approval"],
        IdentityVerifier(trust, keys["identity"].key_id),
        credential_authorities={"governance-roster:simulated": keys["roster"].key_id})
    store = SyntheticRosterObservation()
    credentials = RosterCredentials(store, "fixture-installation", keys["roster"])
    recorder = DecisionRecorder(keys["evidence"], trust)
    change = {"tenant": "synthetic-tenant", "prior_epoch": 0, "reason": "Withdraw pending draft authority"}
    output = withdrawal_bytes("synthetic-tenant", prior_epoch=0, reason=change["reason"])
    digest = sha256(output).hexdigest()
    assertion = Assertion("withdrawal-assertion", "synthetic-tenant", WITHDRAWAL_CONTENT_TYPE, digest)
    action = Action(OPERATION, ActionEffect.EXTERNAL, destination=effect_destination({}, BoundEffect(
        digest, TargetRef("governance", KIND + ":synthetic-tenant"), "0", "fixture:withdrawal")))
    now = 1_000_000
    ctx = PolicyContext("synthetic-tenant", Actor("requester", "synthetic-tenant", frozenset()),
        "fixture:withdrawal", "withdrawal-request", now)
    policy = GovernanceWithdrawalPolicy()
    decision = policy.evaluate(assertion, action, ctx)
    envelope = recorder.record(assertion, action, ctx, policy.ref, decision)
    request = workflow.open(request_id="withdrawal-review", requester_id="requester",
        tenant_id="synthetic-tenant", assertion_id=assertion.assertion_id,
        decision_record_id=envelope.record.record_id, decision_record_hash=envelope.record_hash,
        requirement=decision.approval, now_us=now)
    # Receipts predate this review; their original lifetime is never refreshed.
    receipts = tuple(credentials(name, "synthetic-tenant", WITHDRAWAL_ROLE, 0)
                     for name in ("supervisor-a", "supervisor-b")[:approver_count])
    grants = [workflow.grant(request, Actor(r.subject_id, "synthetic-tenant", frozenset()),
                              now, receipt=r) for r in receipts]
    certificate = workflow.finalize(request, grants, now)
    approved = ApprovedDecision(certificate, envelope, receipts)
    parameters = dict(workflow=workflow, recorder=recorder, roster_store=store,
        installation="fixture-installation", tenant_id="synthetic-tenant", change=change,
        requester_id="requester")
    return SimpleNamespace(approved=approved, parameters=parameters, now=now,
                           credentials=credentials, output=output)


@pytest.mark.parametrize("approver_count", [1, 2])
def test_actual_signed_supervisor_approval_admits_without_refreshing_receipts(approver_count):
    app = composition(approver_count)
    before = app.approved
    assert verify_supervisor_approval(app.approved, **app.parameters, now_us=app.now) == tuple(
        ("supervisor-a", "supervisor-b")[:approver_count])
    assert app.approved == before
    assert app.parameters["recorder"].verify_chain("synthetic-tenant")


def test_elapsed_original_supervisor_receipt_refuses_while_approval_window_is_current():
    app = composition()
    now = app.approved.credential_receipts[0].expires_at_us
    assert now < app.approved.envelope.record.decided_at_us + 3_600_000_000
    with pytest.raises(EmissionError, match="supervisor receipt is stale"):
        verify_supervisor_approval(app.approved, **app.parameters, now_us=now)


def test_ordinary_non_supervisor_cannot_obtain_supervisor_receipt():
    app = composition()
    with pytest.raises(CredentialError, match="holds no"):
        app.credentials("ordinary-approver", "synthetic-tenant", WITHDRAWAL_ROLE, app.now)


def test_missing_retained_approval_refuses():
    app = composition()
    with pytest.raises(EmissionError, match="retained approved decision"):
        verify_supervisor_approval(None, **app.parameters, now_us=app.now)


@pytest.mark.parametrize("prior", [-1, True, 2**63 - 1])
def test_epoch_input_requires_one_representable_increment(prior):
    with pytest.raises(EmissionError, match="bigint increment"):
        checked_change("synthetic-tenant", {"tenant": "synthetic-tenant", "prior_epoch": prior, "reason": "request"})


def test_request_must_name_reason_without_unreviewed_fields():
    with pytest.raises(EmissionError, match="exactly"):
        checked_change("synthetic-tenant", {"tenant": "synthetic-tenant", "prior_epoch": 0,
                                           "reason": "request", "at_us": 123})
    with pytest.raises(EmissionError, match="nonempty exact reason"):
        withdrawal_bytes("synthetic-tenant", prior_epoch=0, reason=" ")
