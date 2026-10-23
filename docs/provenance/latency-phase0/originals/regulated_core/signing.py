"""Real asymmetric signing (Ed25519) with a trust directory of distinct named identities.

Two design decisions, each fixing a weakness the comparison found:

1. ASYMMETRIC (source review's win over integration review's HMAC). Signers hold a private key; everyone else
   holds only public keys. A verifier can check a signature but cannot mint one. Non-repudiation
   is real, not deferred.

2. TRUST ANCHORED BY IDENTITY NAME, not by a key carried inside the object (fixes source review's
   `verify_approval_certificate` footgun, where a certificate was verified against its own
   embedded key). Every signed object names its signer by a stable `key_id`; verification
   ALWAYS resolves that name to a public key held in the `TrustDirectory`. Unknown name → fail
   closed. This also gives separation of duties: the decision, approval, emission, preflight,
   assurance and each verifier are DISTINCT identities with distinct keys, so compromising one
   cannot forge another (fixes source review's single-signer-key collapse).

Production swap: `Ed25519Signer` can be replaced by a KMS/HSM-backed signer (or the Factory's
`factory.provenance.Ed25519Signer`) behind the `Signer` protocol without touching the core.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes

# Signature algorithms the trust fabric can carry. The algorithm travels with each signature
# and each registered public key, so verification dispatches to the right scheme instead of
# assuming one. Both are NIST-approved (FIPS 186-5); which one a deployment ships is an
# operator choice of signing profile (see docs/regulated-architecture/17-*).
ALG_ED25519 = "ed25519"          # EdDSA over Curve25519; raw 32-byte public key, raw 64-byte sig
ALG_ECDSA_P384 = "ecdsa-p384"    # ECDSA over NIST P-384 with SHA-384; X9.62 point, DER signature


@dataclass(frozen=True, slots=True)
class Signature:
    key_id: str          # WHICH trusted identity signed (audit answers "who attested this")
    value: str           # hex signature over the canonical payload
    alg: str = ALG_ED25519  # signature scheme; defaults to Ed25519 for backward compatibility


class Signer(Protocol):
    key_id: str
    alg: str
    def sign(self, payload: object) -> Signature: ...
    def sign_bytes(self, data: bytes) -> Signature: ...
    @property
    def public_key_bytes(self) -> bytes: ...


# Signer custody kinds. A dev/local key lives in-process (fine for tests/dev); a KMS/HSM-backed
# signer holds the private key outside the process. The production-readiness gate refuses to attest
# HSM/KMS custody while a dev key is in use (see production_gate.py + kms.py).
KIND_DEV_LOCAL = "dev-local"
KIND_KMS_EXTERNAL = "kms-external"


def signer_kind(signer: object) -> str:
    """Classify a signer's key custody. Unmarked signers are dev/local by default."""
    return getattr(signer, "kind", KIND_DEV_LOCAL)


def is_kms_backed(signer: object) -> bool:
    return signer_kind(signer) == KIND_KMS_EXTERNAL


class Ed25519Signer:
    """A single named DEV/LOCAL signing identity (private key in-process). Swap for a KMS/HSM-backed
    signer in production (see kms.py); the `Signer` protocol is identical."""

    kind = KIND_DEV_LOCAL
    alg = ALG_ED25519

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.key_id = key_id
        self._sk = private_key or Ed25519PrivateKey.generate()

    def sign(self, payload: object) -> Signature:
        sig = self._sk.sign(canonical_bytes(payload))
        return Signature(key_id=self.key_id, value=sig.hex(), alg=self.alg)

    def sign_bytes(self, data: bytes) -> Signature:
        """Sign raw bytes (needed for standard envelope formats like DSSE, whose pre-authentication
        encoding is byte-exact — external verifiers must be able to check our signatures)."""
        return Signature(key_id=self.key_id, value=self._sk.sign(data).hex(), alg=self.alg)

    @property
    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class EcdsaP384Signer:
    """A single named DEV/LOCAL ECDSA P-384 signing identity (private key in-process). The FIPS-mode
    profile's production counterpart signs the same scheme inside CloudHSM (CKM_ECDSA_SHA384) or AWS
    KMS (ECC_NIST_P384); the `Signer` protocol is identical. Signature is DER-encoded (r,s); the
    public key is the X9.62 uncompressed point."""

    kind = KIND_DEV_LOCAL
    alg = ALG_ECDSA_P384

    def __init__(self, key_id: str, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self.key_id = key_id
        self._sk = private_key or ec.generate_private_key(ec.SECP384R1())

    def sign(self, payload: object) -> Signature:
        sig = self._sk.sign(canonical_bytes(payload), ec.ECDSA(hashes.SHA384()))
        return Signature(key_id=self.key_id, value=sig.hex(), alg=self.alg)

    def sign_bytes(self, data: bytes) -> Signature:
        return Signature(key_id=self.key_id, value=self._sk.sign(data, ec.ECDSA(hashes.SHA384())).hex(),
                         alg=self.alg)

    @property
    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )


PublicKey: TypeAlias = Ed25519PublicKey | ec.EllipticCurvePublicKey


def _load_public_key(alg: str, public_key_bytes: bytes) -> PublicKey:
    """Reconstruct a verifying public-key object from its algorithm and bytes. Done ONCE at
    registration (not on every verify) — `from_encoded_point` for P-384 is ~60us and must not
    sit on the hot path. Raises on unknown algorithm or malformed key: a trust anchor is
    established deliberately, so garbage fails fast rather than silently."""
    if alg == ALG_ED25519:
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)
    if alg == ALG_ECDSA_P384:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), public_key_bytes)
    raise ValueError(f"unknown signature algorithm: {alg}")


def _verify_with_key(
    alg: str, public_key: PublicKey, signature_hex: str, data: bytes
) -> bool:
    """Verify against a pre-reconstructed public-key object. The only per-call work is decoding
    the hex signature and the library verify itself — no key reconstruction. Fail-closed."""
    try:
        raw_sig = bytes.fromhex(signature_hex)
        if alg == ALG_ED25519:
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(raw_sig, data)
            return True
        if alg == ALG_ECDSA_P384:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            public_key.verify(raw_sig, data, ec.ECDSA(hashes.SHA384()))
            return True
        return False  # unknown algorithm -> fail closed
    except (InvalidSignature, TypeError, ValueError):
        return False


class TrustDirectory:
    """Maps identity name -> (algorithm, trusted public key). Verification is anchored here, never in
    the object being verified. The registered identity fixes BOTH the key and its signature scheme, so
    a signature is verified under the algorithm the identity was registered with. Fail-closed on
    unknown identity or algorithm."""

    def __init__(self) -> None:
        # key_id -> (algorithm, reconstructed public-key object). The key object is built once
        # here so verification never reconstructs it on the hot path.
        self._keys: dict[str, tuple[str, PublicKey]] = {}

    def register(self, key_id: str, public_key_bytes: bytes, alg: str = ALG_ED25519) -> None:
        if key_id in self._keys:
            raise ValueError(f"identity already registered: {key_id}")
        self._keys[key_id] = (alg, _load_public_key(alg, public_key_bytes))

    def register_signer(self, signer: Signer) -> None:
        self.register(signer.key_id, signer.public_key_bytes, getattr(signer, "alg", ALG_ED25519))

    def is_known(self, key_id: str) -> bool:
        return key_id in self._keys

    def matches_signer(self, signer: Signer) -> bool:
        """Compare a signer's public anchor without issuing a test signature."""
        from cryptography.hazmat.primitives import serialization

        entry = self._keys.get(signer.key_id)
        if entry is None or entry[0] != signer.alg:
            return False
        try:
            supplied = _load_public_key(signer.alg, signer.public_key_bytes)
        except (ValueError, TypeError):
            return False
        encoding = serialization.Encoding.DER
        form = serialization.PublicFormat.SubjectPublicKeyInfo
        return entry[1].public_bytes(encoding, form) == supplied.public_bytes(encoding, form)

    def distinct_keys(self, key_ids: tuple[str, ...]) -> bool:
        """Require known, distinct public keys, not merely different key names."""
        from cryptography.hazmat.primitives import serialization

        material = []
        for key_id in key_ids:
            entry = self._keys.get(key_id)
            if entry is None:
                return False
            material.append(entry[1].public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        return bool(material) and len(set(material)) == len(material)

    def verify(self, payload: object, signature: Signature) -> bool:
        return self.verify_bytes(canonical_bytes(payload), signature)

    def verify_bytes(self, data: bytes, signature: Signature) -> bool:
        entry = self._keys.get(signature.key_id)
        if entry is None:
            return False  # unknown identity -> fail closed
        alg, public_key = entry
        if signature.alg != alg:
            # Algorithm identity is auditable security metadata, not a hint.
            # Refuse an otherwise-valid signature that lies about its scheme.
            return False
        return _verify_with_key(alg, public_key, signature.value, data)

    def verify_registered_bytes(
        self, data: bytes, key_id: str, signature_hex: str
    ) -> bool:
        """Verify a standard envelope signature by its trusted key identity.

        DSSE deliberately carries only ``keyid`` and signature bytes; algorithm
        selection belongs to the verifier's trusted key registry. Unknown
        identities fail closed.
        """
        entry = self._keys.get(key_id)
        if entry is None:
            return False
        alg, public_key = entry
        return _verify_with_key(alg, public_key, signature_hex, data)
