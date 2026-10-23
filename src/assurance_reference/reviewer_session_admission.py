"""Read-only reviewer-session admission over already verified signed receipts."""
from contextlib import contextmanager
from dataclasses import asdict

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.reviewer_sessions import SessionCredentialReceipt
from regulated_core.target import ReleaseAdmissionUnavailable


@contextmanager
def admit_reviewer_sessions(*, receipts, tenant, not_after_us, sessions, trust, signer_id):
    """Hold one provider admission for the exact signed reviewer set.

    The caller resolves the signed retained approval. No session lookup by
    principal, new login, receipt replacement or signature creation is allowed.
    """
    if (not receipts or not callable(getattr(sessions, "admit_many", None))
            or type(not_after_us) is not int or not_after_us <= 0):
        raise CredentialError("retained reviewer session admission is required")
    identities = []
    for receipt in receipts:
        if (not isinstance(receipt, SessionCredentialReceipt)
                or receipt.tenant != tenant or receipt.status != "active"
                or receipt.signature.key_id != signer_id
                or not trust.verify(receipt.signed_body(), receipt.signature)):
            raise CredentialError("review requires a signed retained session binding")
        binding = receipt.reviewer_session
        if (binding.tenant, binding.principal) != (tenant, receipt.subject_id):
            raise CredentialError("reviewer session identity differs from its credential")
        identities.append(AuthenticatedSession(**asdict(binding)))
    deadlines = [not_after_us, *(r.expires_at_us for r in receipts)]
    try:
        with sessions.admit_many(tuple(identities), not_after_us=min(deadlines)) as current:
            if not callable(current):
                raise CredentialError("reviewer admission must provide a final check")
            current()
            def before_effect():
                try:
                    current()
                except SessionRefused as error:
                    raise EmissionError(str(error)) from error
                except SessionUnavailable as error:
                    raise ReleaseAdmissionUnavailable("reviewer session unavailable before effect") from error
            yield before_effect
    except SessionRefused as error:
        raise CredentialError(str(error)) from error
    except SessionUnavailable as error:
        raise ReleaseAdmissionUnavailable("reviewer admission unavailable; reconcile any effect") from error

