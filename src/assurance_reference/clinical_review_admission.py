"""Authenticated clinical review grants over the existing qualified role.

This host adapter queries the membership provider by its base role. The signed
credential receipt still supplies the licence kind, and the unchanged approval
workflow enforces the qualified role requested by the signed rulebook.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
import json

from assurance_reference.session_admission_scope import SessionAdmissionScope
from assurance_reference.session_credentials import AuthenticatedSession
from factory.health_ui.clinician_credentials import CLINICIAN_ROLE, MEMBERSHIP_LICENCE
from factory.health_ui.session_release import ClinicalSessionCredentials
from regulated_core.identity_provider import CredentialError, CredentialReceipt
from regulated_core.reviewer_sessions import ReviewerSessionBinding, issue_session_credential

QUALIFIED_CLINICIAN = CLINICIAN_ROLE + "@" + MEMBERSHIP_LICENCE


def membership_query_role(requested_role):
    if requested_role != QUALIFIED_CLINICIAN:
        raise CredentialError("clinical stored review requires the signed workspace membership role")
    return CLINICIAN_ROLE


def _binding(contract, context):
    return (context.tenant, context.actor_id, context.project_id, context.action_id, context.nonce,
            json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False))


class ClinicalReviewCredentials(ClinicalSessionCredentials):
    """Receiving owner session plus separately admitted stored-review principals."""

    requires_stored_review = True

    def __init__(self, *args, clock_us, reviewer_session_authority, **kwargs):
        if not callable(clock_us):
            raise ValueError("clinical review requires the host authority clock")
        super().__init__(*args, **kwargs)
        if not callable(getattr(reviewer_session_authority, "admit_many", None)):
            raise ValueError("clinical review requires explicit retained reviewer session authority")
        self._reviewer_session_authority = reviewer_session_authority
        self._clock_us = clock_us
        self._review = ContextVar("clinical_review_admission", default=None)

    @contextmanager
    def _admitted_review(self, authenticated, context, contract, current):
        if (not isinstance(authenticated, AuthenticatedSession)
                or (context.tenant, context.actor_id) != (authenticated.tenant, authenticated.principal)
                or context.approval is not None or context.actor_roles or context.is_producer
                or not callable(current) or self._review.get() is not None):
            raise CredentialError("clinical review requires its separately authenticated human session")
        current()
        token = self._review.set((_binding(contract, context), current, authenticated))
        try:
            yield
            current()
        finally:
            self._review.reset(token)

    def admit_reviewers(self, *, receipts, tenant, not_after_us):
        from assurance_reference.reviewer_session_admission import admit_reviewer_sessions
        return admit_reviewer_sessions(receipts=receipts, tenant=tenant,
            not_after_us=not_after_us, sessions=self._reviewer_session_authority, trust=self._trust,
            signer_id=self._signer.key_id)

    def _issue_credential(self, body):
        held = self._review.get()
        if held is None:
            return super()._issue_credential(body)
        current = held[2]
        binding = ReviewerSessionBinding(current.tenant, current.principal,
            current.username, current.reference, current.expires_at_us)
        fields = {key: value for key, value in body.items() if key != "schema"}
        return issue_session_credential(self._signer, reviewer_session=binding, **fields)

    def verify_review(self, subject_id, tenant, role, *, contract, context, jurisdiction):
        held = self._review.get()
        if (held is None or (subject_id, tenant) != (context.actor_id, context.tenant)
                or held[0] != _binding(contract, context)):
            raise CredentialError("clinical review has no matching admitted reviewer")
        held[1]()
        receipt = super().verify(subject_id, tenant, membership_query_role(role),
                                 jurisdiction=jurisdiction, now_us=context.now_us)
        held[1]()
        return receipt


    def validate_review(self, receipt, *, contract, context):
        """Read current membership while preserving the original signed receipt.

        HealthMembershipRegistry reports a rolling receipt window on lookup,
        not a fixed professional licence expiry. A new lookup never extends or
        replaces the retained receipt's own signed expiration.
        """
        now = self._clock_us()
        if (type(now) is not int or now <= 0 or not isinstance(receipt, CredentialReceipt)
                or receipt.tenant != context.tenant
                or receipt.role != CLINICIAN_ROLE or receipt.licence_type != MEMBERSHIP_LICENCE
                or receipt.provider != self._registry.provider
                or receipt.provider != "health-identity-store"
                or receipt.verified_at_us > now
                or not self.verify_receipt(receipt, tenant=context.tenant, now_us=now)):
            raise CredentialError("retained clinical reviewer receipt is invalid or expired")
        subject = self._identity.resolve(receipt.subject_id, receipt.tenant)
        licence = self._registry.lookup(receipt.subject_id, receipt.role)
        if (subject is None or not subject.active
                or (subject.subject_id, subject.tenant) != (receipt.subject_id, receipt.tenant)
                or licence is None
                or (licence.subject_id, licence.role, licence.licence_type,
                    licence.jurisdiction, licence.status) !=
                   (receipt.subject_id, receipt.role, receipt.licence_type,
                    receipt.jurisdiction, receipt.status)
                or licence.expires_at_us <= now):
            raise CredentialError("clinical reviewer membership changed since its retained receipt")
        after = self._clock_us()
        if (type(after) is not int or after < now
                or not self.verify_receipt(receipt, tenant=context.tenant, now_us=after)):
            raise CredentialError("retained clinical reviewer receipt expired during validation")


class ClinicalReviewGrant:
    """Host-bound review assignment; grant accepts no caller-selected identity.

    request is an owner-admitted, host-bound zero-argument callback returning
    (spec, exact_contract, owner_context, review_id) for one prepared attempt.
    It is not a public callback or a transport-supplied authorization claim.
    """

    def __init__(self, *, gate, credentials, sessions, authenticated, request):
        if (not isinstance(credentials, ClinicalReviewCredentials)
                or getattr(gate, "_credverify", None) is not credentials
                or not isinstance(sessions, SessionAdmissionScope)
                or not isinstance(authenticated, AuthenticatedSession)
                or sessions.authenticated != authenticated or not callable(request)):
            raise ValueError("clinical review requires an exact host-bound session and credential composition")
        self._gate, self._credentials = gate, credentials
        self._sessions, self._authenticated, self._request = sessions, authenticated, request

    def grant(self):
        with self._sessions.admit(self._authenticated) as current:
            spec, contract, owner, review_id = self._request()
            if (owner.tenant != self._authenticated.tenant
                    or not isinstance(review_id, str) or not review_id
                    or owner.approval is not None or owner.is_producer):
                raise CredentialError("review assignment is not an unapproved attempt in this workspace")
            context = replace(owner, actor_id=self._authenticated.principal, actor_roles=(),
                              approval=None, is_producer=False, now_us=self._sessions.clock.now_us())
            with self._credentials._admitted_review(self._authenticated, context, contract, current):
                answer = self._gate.grant_review(spec=spec, contract=contract, context=context,
                                                review_id=review_id, role=QUALIFIED_CLINICIAN)
                current()
                return answer
