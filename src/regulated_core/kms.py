"""KMS/HSM signer seam — the first real production-assurance gate.

Signing is central to the whole architecture (every decision, approval, verification, and evidence
entry is signed), so making it HSM/KMS-backed is the highest-leverage production step. This wires the
core's `Signer` through the Factory's sign-by-reference `factory.provenance.ExternalSigner`: the
private key lives OUTSIDE the process (a KMS/HSM), so a compromised process cannot exfiltrate it.

Opt-in (imports `factory`), so `import regulated_core` stays standalone. `LocalKmsBackend` is a
deterministic mock for tests/dev — NO cloud credentials required. Real AWS KMS / GCP KMS / Azure Key
Vault / a Vault-Transit backend drop in behind the same `SigningBackend` protocol with no core change.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from factory.provenance import ExternalSigner as _ExternalSigner

from .canonical import canonical_bytes
# is_kms_backed is defined in signing; re-exported here so `regulated_core.kms.is_kms_backed`
# resolves too (it is about KMS-backed signers, and callers reasonably look for it here).
from .signing import (
    ALG_ED25519,
    KIND_KMS_EXTERNAL,
    Signature,
    TrustDirectory,
    is_kms_backed as is_kms_backed,
)


class KmsUnavailable(Exception):
    """The KMS/HSM backend could not sign (unreachable, permission denied, key disabled). The core
    treats this as FAIL-CLOSED: no signature, so no evidence/decision/emission proceeds."""


class SigningBackend(Protocol):
    """Matches factory.provenance.SigningBackend: sign by reference, expose the public key."""

    alg: str
    @property
    def custody(self) -> KeyCustody: ...
    def sign(self, payload: bytes) -> bytes: ...
    @property
    def public_key(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class KeyCustody:
    """Provenance for the signing key itself — what an auditor asks for about key management."""

    provider: str            # 'aws-kms' | 'gcp-kms' | 'azure-kv' | 'vault-transit' | 'local-mock'
    key_reference: str       # the KMS key id / ARN / resource name
    key_version: str
    created_at_us: int
    rotated_at_us: int | None = None
    algorithm: str = ALG_ED25519

    def as_dict(self) -> dict[str, object]:
        return {"provider": self.provider, "key_reference": self.key_reference,
                "key_version": self.key_version, "created_at_us": self.created_at_us,
                "rotated_at_us": self.rotated_at_us, "algorithm": self.algorithm}


class LocalKmsBackend:
    """A deterministic, credential-free KMS mock: the private key stays behind the backend boundary,
    it exposes key identity + rotation metadata, and it can be made 'unavailable' to prove fail-closed.
    Production swaps this for a real KMS client behind the identical `SigningBackend` protocol."""

    def __init__(self, key_reference: str, *, key_version: str = "1", created_at_us: int = 0,
                 private_key: Ed25519PrivateKey | None = None) -> None:
        self._sk = private_key or Ed25519PrivateKey.generate()
        self.alg = ALG_ED25519
        self._custody = KeyCustody(
            "local-mock", key_reference, key_version, created_at_us, algorithm=self.alg
        )
        self._available = True

    @property
    def custody(self) -> KeyCustody:
        return self._custody

    def set_available(self, available: bool) -> None:
        self._available = available

    def rotate(self, *, new_version: str, at_us: int, private_key: Ed25519PrivateKey | None = None) -> None:
        """Rotate to a new key version. New signatures verify under the new public key; custody records it."""
        self._sk = private_key or Ed25519PrivateKey.generate()
        c = self._custody
        self._custody = KeyCustody(
            c.provider, c.key_reference, new_version, c.created_at_us, at_us, c.algorithm
        )

    def sign(self, payload: bytes) -> bytes:
        if not self._available:
            raise KmsUnavailable(f"KMS key {self._custody.key_reference!r} is unavailable")
        return self._sk.sign(payload)

    @property
    def public_key(self) -> bytes:
        return self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KmsSigner:
    """A KMS/HSM-backed core `Signer` (sign-by-reference through the Factory's ExternalSigner). Marks
    itself `kind = kms-external` so the production-readiness gate can tell it apart from a dev key, and
    carries `custody` for the evidence pack. Raises `KmsUnavailable` (fail-closed) if the backend is down."""

    kind = KIND_KMS_EXTERNAL

    def __init__(self, key_id: str, backend: SigningBackend, custody: KeyCustody) -> None:
        self.key_id = key_id
        backend_custody = backend.custody
        if custody != backend_custody:
            raise ValueError(
                "supplied key-custody receipt does not match the signing backend"
            )
        self._ext = _ExternalSigner(backend)
        self.custody = backend_custody
        self.alg = backend.alg
        if self.custody.algorithm != self.alg:
            raise ValueError(
                "signing backend algorithm does not match its key-custody receipt"
            )

    def sign(self, payload: object) -> Signature:
        return Signature(key_id=self.key_id, value=self._ext.sign(canonical_bytes(payload)).hex(),
                         alg=self.alg)

    def sign_bytes(self, data: bytes) -> Signature:
        """Sign raw bytes (DSSE and other byte-exact envelope formats)."""
        return Signature(key_id=self.key_id, value=self._ext.sign(data).hex(), alg=self.alg)

    @property
    def public_key_bytes(self) -> bytes:
        return self._ext.public_key


def register_kms_identity(trust: TrustDirectory, key_id: str, backend: LocalKmsBackend) -> KmsSigner:
    """Create a KMS-backed identity and register its public key in the trust directory. In production
    pass a real KMS client backend instead of `LocalKmsBackend`."""
    signer = KmsSigner(key_id, backend, backend.custody)
    trust.register(key_id, signer.public_key_bytes, signer.alg)
    return signer
