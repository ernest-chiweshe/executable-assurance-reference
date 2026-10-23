"""Trusted verifications: signed, bound to one assertion AND tenant, signed by the named verifier.

Fixes carried from the comparison:
  * bound to `tenant_id` (source review omitted this -> cross-tenant replay of a signed verification);
  * signature.key_id must equal the verifier_id it claims (a result naming the PHI verifier must
    be signed by the PHI verifier's key), and is resolved against the trust directory;
  * authenticity is not sufficiency: policies must still enumerate the classes they require and
    check PASS. `authenticate` only proves the attached verifications are genuine.
"""
from __future__ import annotations

from .models import Assertion, Outcome, SignedVerification, VerificationResult
from .signing import Signer, TrustDirectory


def sign_verification(
    signer: Signer, *, assertion_id: str, content_digest: str, tenant_id: str,
    result: VerificationResult, verified_at_us: int,
) -> SignedVerification:
    if signer.key_id != result.verifier_id:
        raise ValueError("a verification must be signed by the verifier identity it names")
    body = {
        "schema": "regulated/verification/v1", "assertion_id": assertion_id,
        "content_digest": content_digest, "tenant_id": tenant_id,
        "result": result, "verified_at_us": verified_at_us,
    }
    return SignedVerification(
        assertion_id, content_digest, tenant_id, result, verified_at_us, signature=signer.sign(body),
    )


class VerificationTrustStore:
    def __init__(self, trust: TrustDirectory) -> None:
        self._trust = trust

    def _authentic(self, assertion: Assertion, v: SignedVerification) -> bool:
        return (
            v.assertion_id == assertion.assertion_id
            and v.content_digest == assertion.content_digest
            and v.tenant_id == assertion.tenant_id
            and v.signature.key_id == v.result.verifier_id     # signed BY the named verifier
            and self._trust.verify(v.signed_body(), v.signature)
        )

    def authenticate(self, assertion: Assertion) -> bool:
        """True iff every attached verification is genuine and bound to this assertion+tenant.
        Empty is authentic (nothing to forge); policies enforce which classes must be PRESENT."""
        return all(self._authentic(assertion, v) for v in assertion.verifications)

    def trusted_outcome(self, assertion: Assertion, verification_class: str) -> Outcome | None:
        for v in assertion.verifications:
            if v.result.verification_class == verification_class and self._authentic(assertion, v):
                return v.result.outcome
        return None
