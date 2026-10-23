"""Authoritative identity & licence verification seam.

KMS proves the signature is controlled; WORM proves the evidence is retained. This proves the
APPROVER: that the person approving a consequential action was a real, tenant-bound identity holding
an ACTIVE, in-jurisdiction, role-appropriate licence/credential at the moment of approval — not a
self-declared role. The verifier produces a SIGNED CredentialReceipt that an approval binds to.

Pure core (no factory dependency); `import regulated_core` stays standalone. Local deterministic
adapters are for tests/dev; real IAM (Okta/Entra/Ping), a medical-board / FINRA licence registry, etc.
drop in behind the `IdentityProvider` / `LicenceRegistry` protocols with no core change. Fail-closed
throughout: any unavailability, mismatch, expiry, or suspension denies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .canonical import digest_hex
from .signing import Signature, Signer, TrustDirectory

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_EXPIRED = "expired"


class IdentityProviderUnavailable(Exception):
    """The IAM/identity provider could not be reached — fail closed."""


class LicenceRegistryUnavailable(Exception):
    """The licence/credential registry could not be reached — fail closed."""


class CredentialError(Exception):
    """Verification failed (unknown/inactive identity, wrong tenant/role/jurisdiction, expired, suspended)."""


@dataclass(frozen=True, slots=True)
class IdentitySubject:
    subject_id: str
    tenant: str
    display_name: str
    active: bool = True


@dataclass(frozen=True, slots=True)
class LicenceRecord:
    subject_id: str
    role: str
    licence_type: str
    jurisdiction: str
    status: str            # active | suspended | expired
    expires_at_us: int


@dataclass(frozen=True, slots=True)
class CredentialReceipt:
    """A signed attestation that (subject, role, licence) was verified against a provider at a time."""

    subject_id: str
    tenant: str
    role: str
    licence_type: str
    jurisdiction: str
    status: str
    expires_at_us: int
    verified_at_us: int
    provider: str
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/credential-receipt/v1", "subject_id": self.subject_id, "tenant": self.tenant,
                "role": self.role, "licence_type": self.licence_type, "jurisdiction": self.jurisdiction,
                "status": self.status, "expires_at_us": self.expires_at_us, "verified_at_us": self.verified_at_us,
                "provider": self.provider}

    def digest(self) -> str:
        return digest_hex({**self.signed_body(), "sig": self.signature.value})


class IdentityProvider(Protocol):
    def resolve(self, subject_id: str, tenant: str) -> IdentitySubject | None: ...


class LicenceRegistry(Protocol):
    #: Who verified the licence, carried into every receipt, so a receipt never names a provider it did not use.
    provider: str

    def lookup(self, subject_id: str, role: str) -> LicenceRecord | None: ...


class LocalIdentityProvider:
    """Deterministic IAM mock. `set_available(False)` simulates an outage (fail-closed)."""

    def __init__(self) -> None:
        self._subjects: dict[tuple[str, str], IdentitySubject] = {}
        self._available = True

    def add(self, subject: IdentitySubject) -> None:
        self._subjects[(subject.tenant, subject.subject_id)] = subject

    def set_available(self, available: bool) -> None:
        self._available = available

    def resolve(self, subject_id: str, tenant: str) -> IdentitySubject | None:
        if not self._available:
            raise IdentityProviderUnavailable("identity provider unreachable")
        return self._subjects.get((tenant, subject_id))


class LocalLicenceRegistry:
    """Deterministic licence/credential registry mock, with status/jurisdiction/expiry."""

    provider = "local-mock"

    def __init__(self) -> None:
        self._licences: dict[tuple[str, str], LicenceRecord] = {}
        self._available = True

    def add(self, licence: LicenceRecord) -> None:
        self._licences[(licence.subject_id, licence.role)] = licence

    def set_available(self, available: bool) -> None:
        self._available = available

    def lookup(self, subject_id: str, role: str) -> LicenceRecord | None:
        if not self._available:
            raise LicenceRegistryUnavailable("licence registry unreachable")
        return self._licences.get((subject_id, role))


class CredentialVerifier:
    """Verifies (subject, role, licence) against the identity provider + licence registry and issues a
    SIGNED receipt. Fail-closed on any provider outage, mismatch, expiry, or suspension."""

    def __init__(self, trust: TrustDirectory, signer: Signer, identity: IdentityProvider,
                 registry: LicenceRegistry, *, provider_backed: bool | None = None) -> None:
        self._trust = trust
        self._signer = signer
        self._identity = identity
        self._registry = registry
        # The compatibility option can disable custody, never assert it. Each
        # configured adapter must declare its own production authority contract.
        self._provider_enabled = provider_backed is not False

    @property
    def provider_backed(self) -> bool:
        """Identify explicit authority adapters; local development stores never qualify.

        This describes the composed adapters, not independently verified remote
        custody. Actual approval still performs both current provider lookups.
        """
        return (
            self._provider_enabled
            and not isinstance(self._identity, LocalIdentityProvider)
            and not isinstance(self._registry, LocalLicenceRegistry)
            and getattr(self._identity, "provider_backed", False) is True
            and getattr(self._registry, "provider_backed", False) is True
        )

    def verify(self, subject_id: str, tenant: str, role: str, *, jurisdiction: str | None = None,
               now_us: int) -> CredentialReceipt:
        subject = self._identity.resolve(subject_id, tenant)   # raises IdentityProviderUnavailable if down
        # The provider must answer about THIS subject: a response naming anyone else, however active, is a
        # misbinding, and no receipt may be issued on it (review 3019).
        if (subject is None or not subject.active or subject.tenant != tenant
                or subject.subject_id != subject_id):
            raise CredentialError(f"identity not verified for {subject_id!r} in tenant {tenant!r}")
        lic = self._registry.lookup(subject_id, role)          # raises LicenceRegistryUnavailable if down
        if lic is None or lic.role != role or lic.subject_id != subject_id:
            raise CredentialError(f"no {role!r} licence for {subject_id!r}")
        if lic.status != STATUS_ACTIVE:
            raise CredentialError(f"licence status is {lic.status!r}")
        if now_us >= lic.expires_at_us:
            raise CredentialError("licence expired")
        if jurisdiction is not None and lic.jurisdiction != jurisdiction:
            raise CredentialError(f"licence jurisdiction {lic.jurisdiction!r} != required {jurisdiction!r}")
        body = {"schema": "regulated/credential-receipt/v1", "subject_id": subject_id, "tenant": tenant,
                "role": role, "licence_type": lic.licence_type, "jurisdiction": lic.jurisdiction,
                "status": lic.status, "expires_at_us": lic.expires_at_us, "verified_at_us": now_us,
                "provider": self._registry.provider}
        return self._issue_credential(body)

    def _issue_credential(self, body):
        """Issue the already verified fields once; adapters may bind more context."""
        fields = {key: value for key, value in body.items() if key != "schema"}
        return CredentialReceipt(signature=self._signer.sign(body), **fields)

    def verify_receipt(self, receipt: CredentialReceipt, *, subject_id: str | None = None,
                       tenant: str | None = None, now_us: int | None = None) -> bool:
        if receipt.signature.key_id != self._signer.key_id or not self._trust.verify(receipt.signed_body(), receipt.signature):
            return False
        if receipt.status != STATUS_ACTIVE:
            return False
        if subject_id is not None and receipt.subject_id != subject_id:
            return False
        if tenant is not None and receipt.tenant != tenant:
            return False
        if now_us is not None and now_us >= receipt.expires_at_us:
            return False
        return True
