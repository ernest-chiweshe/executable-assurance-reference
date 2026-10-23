"""Bind pinned Education reviewer authority to one authenticated local session.

This adapter issues and revalidates scoped review receipts. It deliberately has
no release-admission port: the reference host cannot use it for effects until
the complete retained-review and source-witness admission is composed.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from factory.education_workbench.reviewer_credentials import EnrollmentCredentialVerifier
from regulated_core.identity_provider import CredentialError


class SessionEnrollmentReviewer(EnrollmentCredentialVerifier):
    """Keep the original signed appointment, enrollment and assessment checks."""

    def __init__(self, appointments, *, signer, school_authorities, assessment_scope,
                 member_active, sessions, authenticated, workspace_bindings=None):
        if (not isinstance(authenticated, AuthenticatedSession)
                or not callable(getattr(sessions, "admit", None))
                or not callable(getattr(getattr(sessions, "clock", None), "now_us", None))):
            raise ValueError("authenticated session and current session authority are required")
        super().__init__(appointments, signer=signer, school_authorities=school_authorities,
                         assessment_scope=assessment_scope, member_active=member_active,
                         workspace_bindings=workspace_bindings)
        self.sessions, self.authenticated = sessions, authenticated
        self._session_check = ContextVar("education_reviewer_session", default=None)

    def _current_context(self, context):
        current = self.authenticated
        if ((context.actor_id, context.tenant) != (current.principal, current.tenant)
                or context.actor_roles or context.is_producer):
            raise CredentialError("Education review requires the exact authenticated human")
        return replace(context, now_us=self.sessions.clock.now_us())

    @contextmanager
    def _admitted(self, context):
        self._current_context(context)
        try:
            current = self._session_check.get()
            if current is not None:
                current()
                yield
                current()
                return
            with self.sessions.admit(self.authenticated) as check:
                check()
                token = self._session_check.set(check)
                try:
                    yield
                    check()
                finally:
                    self._session_check.reset(token)
        except SessionRefused as error:
            raise CredentialError(str(error)) from error

    @contextmanager
    def review_guard(self, *, contract, context, actors):
        # Session parents precede the original school/class/principal locks.
        # Nested witness and receipt lookups share this same admission.
        with self._admitted(context):
            with super().review_guard(contract=contract,
                                      context=self._current_context(context), actors=actors):
                yield

    def verify_review(self, actor_id, tenant, role, *, contract, context, jurisdiction=None):
        if (actor_id, tenant) != (self.authenticated.principal, self.authenticated.tenant):
            raise CredentialError("a session cannot issue another person's review receipt")
        with self.review_guard(contract=contract, context=context, actors=(actor_id,)):
            receipt = super().verify_review(actor_id, tenant, role, contract=contract,
                context=self._current_context(context), jurisdiction=jurisdiction)
            # Signing may take time. Validate the original receipt at current
            # authority time; never replace an expired receipt with a new one.
            super().validate_review(receipt, contract=contract,
                                    context=self._current_context(context))
            return receipt

    def validate_review(self, receipt, *, contract, context):
        # The requesting session may revalidate a different person's retained
        # receipt. Issuance above remains bound to the reviewer's own session.
        with self.review_guard(contract=contract, context=context, actors=(receipt.subject_id,)):
            super().validate_review(receipt, contract=contract,
                                    context=self._current_context(context))

    def teacher_binding(self, actor_id, *, contract, context):
        with self.review_guard(contract=contract, context=context, actors=(actor_id,)):
            return super().teacher_binding(actor_id, contract=contract,
                                           context=self._current_context(context))
