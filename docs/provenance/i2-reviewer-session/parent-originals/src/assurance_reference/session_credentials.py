"""Domain-neutral counterpart of the pinned X-5 session-to-effect adapter.

The caller supplies an authenticated session, never a caller-selected role.
The gate binds the session fields into its signed decision before this adapter
admits them. Actual session authority is held by the injected store.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass

from regulated_core.identity_provider import CredentialError, CredentialVerifier
from regulated_core.permit import EmissionError
from regulated_core.target import ReleaseAdmissionUnavailable

SESSION_FIELD = "authority_session"
SESSION_SCHEMA = "reference/session-admission/v1"


class SessionRefused(ValueError):
    """A known invalid, withdrawn, or expired session."""


class SessionUnavailable(RuntimeError):
    """Session authority could not be established; an effect may need reconciliation."""


@dataclass(frozen=True)
class AuthenticatedSession:
    tenant: str
    principal: str
    username: str
    reference: str
    expires_at_us: int

    def binding(self):
        return {"schema": SESSION_SCHEMA, **asdict(self)}


class SessionBoundCredentials(CredentialVerifier):
    """One authenticated request; do not mutate or share it between requesters."""

    requires_stored_review = True

    def __init__(self, trust, signer, identity, registry, *, sessions, authenticated):
        super().__init__(trust, signer, identity, registry)
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("an authenticated session is required")
        if not callable(getattr(sessions, "admit", None)):
            raise ValueError("retained session admission is required")
        if not callable(getattr(getattr(sessions, "clock", None), "now_us", None)):
            raise ValueError("session authority must supply its current clock")
        self.sessions, self.authenticated = sessions, authenticated

    def verify_review(self, subject_id, tenant, role, *, contract, context, jurisdiction=None):
        current = self.authenticated
        if ((subject_id, tenant) != (current.principal, current.tenant)
                or context.actor_id != subject_id or context.tenant != tenant
                or context.actor_roles or context.is_producer):
            raise CredentialError("review requires the authenticated human without self-supplied roles")
        try:
            with self.sessions.admit(current) as check:
                check()
                receipt = super().verify(subject_id, tenant, role, jurisdiction=jurisdiction,
                                         now_us=context.now_us)
                if not self.verify_receipt(receipt, now_us=self.sessions.clock.now_us()):
                    raise CredentialError("review credential expired during verification")
                check()
                return receipt
        except SessionRefused as error:
            raise CredentialError(str(error)) from error

    def validate_review(self, receipt, *, contract, context):
        # Revalidation is read-only: never sign a replacement receipt. The
        # retained receipt and current identity/certificate must still agree.
        if receipt.tenant != context.tenant or not self.verify_receipt(
            receipt, now_us=self.sessions.clock.now_us(),
        ):
            raise CredentialError("retained reviewer receipt is invalid or expired")
        subject = self._identity.resolve(receipt.subject_id, receipt.tenant)
        licence = self._registry.lookup(receipt.subject_id, receipt.role)
        if (subject is None or not subject.active
                or (subject.subject_id, subject.tenant) != (receipt.subject_id, receipt.tenant)
                or licence is None
                or (licence.subject_id, licence.role, licence.licence_type, licence.jurisdiction,
                    licence.status, licence.expires_at_us) !=
                   (receipt.subject_id, receipt.role, receipt.licence_type, receipt.jurisdiction,
                    receipt.status, receipt.expires_at_us)):
            raise CredentialError("reviewer authority changed since the retained receipt")

    @contextmanager
    def admit_release(self, *, contract, context, authorization):
        current = self.authenticated
        if (contract.get(SESSION_FIELD) != current.binding()
                or (context.actor_id, context.tenant) != (current.principal, current.tenant)
                or context.actor_roles or context.is_producer
                or authorization.permit is None
                or authorization.permit.permit.principal != current.principal):
            raise CredentialError("release requires the exact approved authenticated session")
        try:
            with self.sessions.admit(current, not_after_us=authorization.permit.permit.expires_at_us) as check:
                def final_check():
                    try:
                        check()
                    except SessionRefused as error:
                        raise EmissionError(str(error)) from error
                    except SessionUnavailable as error:
                        raise ReleaseAdmissionUnavailable("session unavailable before effect") from error
                yield final_check
        except SessionRefused as error:
            raise CredentialError(str(error)) from error
        except SessionUnavailable as error:
            raise ReleaseAdmissionUnavailable("session admission unavailable; reconcile the target receipt") from error
