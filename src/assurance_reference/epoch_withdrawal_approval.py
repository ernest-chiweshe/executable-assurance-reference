"""Authenticate a local supervisor before issuing an original withdrawal review.

The service resolves the reviewer from a retained session and reads the decision
from the configured recorder. It accepts no caller-supplied actor, role, receipt
or signed decision. Local sessions establish fixture identity, not deployed IAM.
Retention and governed release remain explicit subsequent operations.
"""
from assurance_reference.epoch_withdrawal_admission import (
    checked_change, verify_supervisor_approval, verify_withdrawal_decision,
)
from assurance_reference.epoch_withdrawal_review import EpochWithdrawalReviewLoader
from assurance_reference.local_sessions import LocalSessions
from regulated_core.approval import ApprovedDecision
from regulated_core.governance_roster import RosterCredentials
from regulated_core.governance_targets import WITHDRAWAL_ROLE
from regulated_core.models import Actor
from regulated_core.permit import EmissionError


class EpochWithdrawalApprovalService:
    """Host-configured local review issuer; constructor performs no I/O."""

    def __init__(self, *, loader, sessions, credentials):
        if (not isinstance(loader, EpochWithdrawalReviewLoader)
                or not isinstance(sessions, LocalSessions)
                or sessions.clock is not loader.clock
                or not isinstance(credentials, RosterCredentials)
                or credentials._store is not loader.roster
                or credentials._installation != loader.installation):
            raise TypeError("withdrawal approval requires exact loader, local sessions, clock and roster credentials")
        self.loader, self.sessions, self.credentials = loader, sessions, credentials
        self.tenant_id = loader.roster._proof_verifier.tenant

    def approve(self, *, token, review_id, decision_record_id, change):
        """Return original evidence of an authenticated supervisor's approval.

        The decision ID is a reference into the host recorder, not submitted
        authority. Session admission holds identity/session locks while roster
        authority and original policy evidence are read and signed. Logout after
        a completed approval does not rewrite that historical approval.
        """
        if any(not isinstance(value, str) or not value.strip() or value != value.strip()
               for value in (review_id, decision_record_id)):
            raise EmissionError("withdrawal approval requires exact review and decision IDs")
        loader, tenant = self.loader, self.tenant_id
        change = checked_change(tenant, change)
        identity = self.sessions.authenticate(tenant, token)
        with self.sessions.admit(identity) as current:
            current()
            matches = [entry for entry in loader.recorder.entries(tenant)
                       if entry.record.record_id == decision_record_id]
            if len(matches) != 1:
                raise EmissionError("withdrawal decision is not uniquely retained")
            envelope = matches[0]
            requester = envelope.record.actor_id
            now = loader.clock.now_us()
            record = verify_withdrawal_decision(envelope, recorder=loader.recorder,
                tenant_id=tenant, change=change, requester_id=requester, now_us=now)
            # A signed roster receipt supplies the role. Authentication alone
            # never grants supervisor status, and the requester cannot self-approve.
            if identity.principal == requester:
                raise EmissionError("withdrawal requester cannot approve their own action")
            receipt = self.credentials(identity.principal, tenant, WITHDRAWAL_ROLE, now)
            current()
            request = loader.workflow.open(request_id=review_id, requester_id=requester,
                tenant_id=tenant, assertion_id=record.assertion_id,
                decision_record_id=record.record_id, decision_record_hash=envelope.record_hash,
                requirement=record.decision.approval, now_us=record.decided_at_us)
            grant = loader.workflow.grant(request,
                Actor(identity.principal, tenant, frozenset()),
                loader.clock.now_us(), receipt=receipt)
            current()
            certificate = loader.workflow.finalize(request, [grant], loader.clock.now_us())
            approved = ApprovedDecision(certificate, envelope, (receipt,))
            verify_supervisor_approval(approved, workflow=loader.workflow,
                recorder=loader.recorder, roster_store=loader.roster,
                installation=loader.installation, tenant_id=tenant, change=change,
                requester_id=requester, now_us=loader.clock.now_us())
            current()
            return approved
