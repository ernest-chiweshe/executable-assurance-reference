"""Signed reviewer-session observations; admission remains the host's duty.

This additive receipt type leaves CredentialReceipt v1 bytes unchanged. A
signature binds an observation, not current session validity: the receiving
host must admit the exact retained session through the effect.
"""
from dataclasses import asdict, dataclass, replace
import json

from .canonical import canonical_bytes
from .identity_provider import CredentialError, CredentialReceipt
from .signing import Signature

SESSION_RECEIPT_SCHEMA = "regulated/session-credential-receipt/v1"


@dataclass(frozen=True, slots=True)
class ReviewerSessionBinding:
    tenant: str
    principal: str
    username: str
    reference: str
    expires_at_us: int

    def __post_init__(self):
        for value in (self.tenant, self.principal, self.username, self.reference):
            if type(value) is not str or not value.strip():
                raise CredentialError("reviewer session requires explicit identity fields")
        if type(self.expires_at_us) is not int or self.expires_at_us <= 0:
            raise CredentialError("reviewer session requires an integer expiry")


@dataclass(frozen=True, slots=True)
class SessionCredentialReceipt(CredentialReceipt):
    reviewer_session: ReviewerSessionBinding

    def __post_init__(self):
        binding = self.reviewer_session
        if (not isinstance(binding, ReviewerSessionBinding)
                or (binding.tenant, binding.principal) != (self.tenant, self.subject_id)
                or type(self.verified_at_us) is not int or self.verified_at_us <= 0
                or type(self.expires_at_us) is not int
                or self.expires_at_us <= self.verified_at_us
                or binding.expires_at_us <= self.verified_at_us):
            raise CredentialError("reviewer session does not bind the verified credential")

    def signed_body(self):
        body = CredentialReceipt.signed_body(self)
        body["schema"] = SESSION_RECEIPT_SCHEMA
        body["reviewer_session"] = asdict(self.reviewer_session)
        return body


def issue_session_credential(signer, *, reviewer_session, subject_id, tenant,
                             role, licence_type, jurisdiction, status,
                             expires_at_us, verified_at_us, provider):
    """Sign once after the caller has checked identity, licence and admission.

    This helper adds no trust, identity lookup or authority. Invalid binding
    metadata is refused before invoking the signer.
    """
    receipt = SessionCredentialReceipt(
        subject_id=subject_id, tenant=tenant, role=role, licence_type=licence_type,
        jurisdiction=jurisdiction, status=status, expires_at_us=expires_at_us,
        verified_at_us=verified_at_us, provider=provider,
        signature=Signature(signer.key_id, ""), reviewer_session=reviewer_session)
    return replace(receipt, signature=signer.sign(receipt.signed_body()))


def decode_session_credential(raw):
    """Decode exact retained bytes; signature/current authority checked elsewhere."""
    if type(raw) is not dict:
        raise CredentialError("invalid retained session credential")
    try:
        value = dict(raw)
        value["signature"] = Signature(**value["signature"])
        value["reviewer_session"] = ReviewerSessionBinding(**value["reviewer_session"])
        result = SessionCredentialReceipt(**value)
        if json.loads(canonical_bytes(result)) != raw:
            raise CredentialError("noncanonical retained session credential")
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise CredentialError("invalid retained session credential") from error

