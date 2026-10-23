"""Exact withdrawal payloads and fresh, signed supervisor approval admission.

This module grants no write access. The caller must repeat admission at the
receiving transaction boundary; epoch, budget and receipt atomicity are separate.
"""
from collections.abc import Mapping
from hashlib import sha256

from regulated_core.approval import ApprovedDecision, ApprovalWorkflow
from regulated_core.governance_targets import (
    GovernanceWithdrawalPolicy, WITHDRAWAL_ROLE, change_bytes,
)
from regulated_core.models import DecisionKind
from regulated_core.permit import EmissionError
from regulated_core.target import TargetRef, effect_of

KIND = "tenant-epoch-withdrawal"
OPERATION = "governance:withdraw-tenant-epoch"


def checked_change(tenant_id, change):
    if not isinstance(tenant_id, str) or not tenant_id.strip() or tenant_id != tenant_id.strip():
        raise EmissionError("withdrawal requires an exact tenant")
    if not isinstance(change, Mapping) or set(change) != {"tenant", "prior_epoch", "reason"}:
        raise EmissionError("withdrawal carries exactly tenant, prior_epoch and reason")
    if change["tenant"] != tenant_id:
        raise EmissionError("withdrawal tenant differs from the receiving tenant")
    prior = change["prior_epoch"]
    reason = change["reason"]
    if type(prior) is not int or prior < 0 or prior >= 2**63 - 1:
        raise EmissionError("withdrawal prior epoch must permit one bigint increment")
    if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
        raise EmissionError("withdrawal requires a nonempty exact reason")
    return {"tenant": tenant_id, "prior_epoch": prior, "reason": reason}


def withdrawal_bytes(tenant_id, *, prior_epoch, reason):
    change = checked_change(tenant_id, {"tenant": tenant_id, "prior_epoch": prior_epoch, "reason": reason})
    return change_bytes(KIND, tenant_id, change)


def verify_withdrawal_decision(envelope, *, recorder, tenant_id, change, requester_id, now_us):
    """Authenticate exact original policy and effect before review or receipt use."""
    payload = withdrawal_bytes(tenant_id, **{
        k: v for k, v in checked_change(tenant_id, change).items() if k != "tenant"})
    digest = sha256(payload).hexdigest()
    change = checked_change(tenant_id, change)
    if type(now_us) is not int or now_us < 0:
        raise EmissionError("withdrawal requires trusted audit time")
    if not recorder.verify_entry(envelope):
        raise EmissionError("withdrawal decision evidence does not authenticate")
    record = envelope.record
    requirement = record.decision.approval
    if (record.tenant_id != tenant_id or record.actor_id != requester_id
            or record.assertion_digest != digest or record.action.action_id != OPERATION
            or record.decision.kind is not DecisionKind.REQUIRE_APPROVAL
            or requirement is None
            or requirement.role_groups != (frozenset({WITHDRAWAL_ROLE}),)
            or requirement.minimum_approvers != 1 or requirement.requester_may_approve
            or requirement.scope != OPERATION
            or requirement.expires_after_us != 3_600_000_000):
        raise EmissionError("withdrawal decision does not bind the supervisor policy and exact effect")
    if record.policy != GovernanceWithdrawalPolicy.ref:
        raise EmissionError("withdrawal decision names another policy")
    bound = effect_of(record.action.destination)
    if (bound is None or bound.target != TargetRef("governance", KIND + ":" + tenant_id)
            or bound.target_state != str(change["prior_epoch"]) or bound.output_digest != digest
            or not bound.mission):
        raise EmissionError("withdrawal decision effect binding differs")
    if not record.decided_at_us <= now_us < record.decided_at_us + requirement.expires_after_us:
        raise EmissionError("withdrawal decision is outside its original approval lifetime")
    return record


def verify_supervisor_approval(approved, *, workflow, recorder, roster_store,
                               installation, tenant_id, change, requester_id, now_us):
    """Reverify retained evidence and current roster without issuing new receipts.

    Signed certificate and receipts are supplied by the host's retained-review
    loader, never accepted as request authority. This helper does not establish
    that the loader or its transaction is correctly composed.
    """
    if not isinstance(workflow, ApprovalWorkflow) or not workflow.requires_credentials:
        raise EmissionError("withdrawal requires a provider-backed approval workflow")
    if not isinstance(approved, ApprovedDecision):
        raise EmissionError("withdrawal requires a retained approved decision")
    envelope, certificate = approved.envelope, approved.certificate
    record = verify_withdrawal_decision(envelope, recorder=recorder, tenant_id=tenant_id,
        change=change, requester_id=requester_id, now_us=now_us)
    requirement = record.decision.approval
    if not workflow.verify_certificate(certificate):
        raise EmissionError("withdrawal approval evidence does not authenticate")
    if (certificate.tenant_id != tenant_id or certificate.assertion_id != record.assertion_id
            or certificate.decision_record_id != record.record_id
            or certificate.decision_record_hash != envelope.record_hash
            or certificate.requirement_digest != requirement.digest()
            or not certificate.request_id
            or not record.decided_at_us <= certificate.finalized_at_us <= now_us
            or now_us >= record.decided_at_us + requirement.expires_after_us):
        raise EmissionError("withdrawal approval binding or lifetime differs")
    approvers = certificate.approver_ids
    receipts = approved.credential_receipts
    if (not approvers or len(set(approvers)) != len(approvers) or requester_id in approvers
            or len(receipts) != len(approvers)
            or tuple(sorted(r.digest() for r in receipts)) != certificate.credential_receipt_digests
            or {r.subject_id for r in receipts} != set(approvers)):
        raise EmissionError("withdrawal requires exact independent supervisor receipts")
    roster = roster_store.current(installation)
    if roster is None or roster.installation != installation:
        raise EmissionError("withdrawal requires the current governance roster")
    expected_provider = "governance-roster" + (":simulated" if roster.simulated else "")
    for receipt in receipts:
        member = roster.member(receipt.subject_id)
        if (not workflow.verify_credential_signature(receipt)
                or receipt.tenant != tenant_id or receipt.role != WITHDRAWAL_ROLE
                or receipt.status != "active" or receipt.provider != expected_provider
                or receipt.licence_type != "governance-roster:" + roster.digest()
                or receipt.jurisdiction != "installation:" + installation
                or not receipt.verified_at_us <= certificate.finalized_at_us <= now_us < receipt.expires_at_us
                or member is None or WITHDRAWAL_ROLE not in member.roles):
            raise EmissionError("withdrawal supervisor receipt is stale or not current roster authority")
    return approvers
