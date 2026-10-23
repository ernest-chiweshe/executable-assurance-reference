"""Certificate-backed credentials: a `LicenceRegistry` over certificates signed by registered issuers.

This is the adapter a deployment uses where a credential is proven by a signed certificate rather than a live
registry lookup: an institution attesting its clinicians, or, for proving the protocol, a demonstration issuer
(docs/ARCHITECTURE-OF-RECORD/10-credential-assurance-profiles.md).

The credential KIND a certificate yields is fixed by its issuer's registration, never by the certificate itself. A
demonstration issuer registered as `demonstration-certificate` can sign a certificate that claims anything; it still
yields only `demonstration-certificate`, so it can never satisfy a policy role qualified by a stronger kind, such as
`clinician@professional-register`. Registering issuers, and the kind each may attest, is the deployment owner's
act; nothing a certificate or its bearer presents changes it.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .governance_guard import GovernanceGuard
from .identity_provider import STATUS_ACTIVE, LicenceRecord
from .signing import Signature, Signer, TrustDirectory

DEMONSTRATION_CERTIFICATE = "demonstration-certificate"
_SCHEMA = "regulated/credential-certificate/v1"


@dataclass(frozen=True, slots=True)
class Certificate:
    """An issuer's signed statement that a subject holds a role, until an expiry."""

    subject_id: str
    role: str
    jurisdiction: str
    expires_at_us: int
    issuer: str
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": _SCHEMA, "subject_id": self.subject_id, "role": self.role,
                "jurisdiction": self.jurisdiction, "expires_at_us": self.expires_at_us, "issuer": self.issuer}


def issue_certificate(issuer: Signer, *, subject_id: str, role: str, jurisdiction: str,
                      expires_at_us: int) -> Certificate:
    """Sign a certificate as `issuer`. What kind of credential it proves is decided by the issuer's registration."""
    body = {"schema": _SCHEMA, "subject_id": subject_id, "role": role, "jurisdiction": jurisdiction,
            "expires_at_us": expires_at_us, "issuer": issuer.key_id}
    return Certificate(subject_id, role, jurisdiction, expires_at_us, issuer.key_id, issuer.sign(body))


class CertificateRegistry:
    """`LicenceRegistry` over presented certificates from registered issuers, each fixed to one credential kind."""

    provider = "certificate-registry"
    # Every lookup verifies a signed certificate against registered issuers.
    # Credential kind remains governed by the signed pack; this marker does
    # not turn a demonstration certificate into a professional registration.
    provider_backed = True

    def __init__(self, trust: TrustDirectory, issuers: Mapping[str, str], *,
                 guard: GovernanceGuard | None = None) -> None:
        if not issuers or any(not key or not kind for key, kind in issuers.items()):
            raise ValueError("a certificate registry needs registered issuers, each with its credential kind")
        if any(not trust.is_known(key) for key in issuers):
            raise ValueError("every registered certificate issuer needs a trust anchor")
        self._trust = trust
        self._guard = guard
        self._issuers = dict(issuers)
        self._held: dict[tuple[str, str], Certificate] = {}
        self._receipts: dict[tuple[str, str, str], str] = {}
        self._lock = threading.Lock()

    def issuer_kind(self, issuer_key_id: str) -> str | None:
        """The credential kind this registry recognises an issuer for, or None."""
        return self._issuers.get(issuer_key_id)

    def recognise(self, issuer_key_id: str, kind: str) -> None:
        """Recognise an issuer for one credential kind. An approver change: in a governed deployment it is called only
        by the governance target, under a tier-4 permit (regulated_core/governance_targets.py), and a guarded registry
        refuses any other caller."""
        if self._guard is not None:
            self._guard.require("approver-issuer", issuer_key_id)
        if not self._trust.is_known(issuer_key_id) or not kind.strip():
            raise ValueError("an issuer must be a registered key, recognised for an explicit kind")
        self._issuers[issuer_key_id] = kind

    def recognise_governed(self, issuer_key_id: str, kind: str, governed: Any) -> None:
        """The governance target's entry (A09; regulated_core/governance_targets.GovernedChange): under this
        registry's lock, compare the approved prior state, run the permit's final check, then write the change and its
        exact receiving receipt together."""
        with self._lock:
            if (self._issuers.get(issuer_key_id) or "absent") != governed.approved_prior:
                raise ValueError("the issuer's recognition changed since the change was approved")
            governed.final_check()
            self.recognise(issuer_key_id, kind)
            self._receipts[(governed.tenant_id, governed.operation, governed.nonce)] = governed.change_digest

    def governance_receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Any:
        """COMMITTED only for the exact receipt; NOT_COMMITTED otherwise, because the receipt is written under the
        lock in the same step as the change, so once the lock is free an absent receipt cannot still appear."""
        from .target import Outcome
        with self._lock:
            held = self._receipts.get((tenant_id, operation, nonce))
        return Outcome.COMMITTED if held == change_digest else Outcome.NOT_COMMITTED

    def present(self, certificate: Certificate) -> None:
        """Deposit a certificate for later lookup. It is verified at every lookup, not trusted on deposit."""
        with self._lock:
            self._held[(certificate.subject_id, certificate.role)] = certificate

    def lookup(self, subject_id: str, role: str) -> LicenceRecord | None:
        with self._lock:
            certificate = self._held.get((subject_id, role))
        if certificate is None:
            return None
        kind = self._issuers.get(certificate.issuer)
        if (kind is None or certificate.signature.key_id != certificate.issuer
                or not self._trust.verify(certificate.signed_body(), certificate.signature)):
            return None
        return LicenceRecord(certificate.subject_id, certificate.role, kind, certificate.jurisdiction,
                             STATUS_ACTIVE, certificate.expires_at_us)


__all__ = ["DEMONSTRATION_CERTIFICATE", "Certificate", "CertificateRegistry", "issue_certificate"]
