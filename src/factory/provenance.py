"""Provenance & signing, proving WHO produced an artifact, HOW, and that it
hasn't changed since.

The ledger (Module 18) content-addresses artifacts: an address is the SHA-256 of
the bytes. That buys integrity, tamper-evidence, but not ORIGIN. The address
says "these exact bytes"; it does not say "the factory produced these bytes, for
this tenant, via this run, and the gate accepted them." Provenance adds the origin.

The shape follows the industry standard, so your attestations interoperate with
the wider supply-chain toolchain. An in-toto attestation is a STATEMENT binding a
SUBJECT (the artifact, named by its digest) to a PREDICATE (who built it and how).
We sign the statement. And because the subject's digest IS the content address,
signing the statement signs the artifact: change one byte and the digest no longer
matches the signed subject.

    Signatures prove INTEGRITY. Attestations prove ORIGIN. You need both.

Phase 1 signs with a keyed Ed25519 keypair, real asymmetric crypto, local-first:
we hold the private key; anyone verifies with the public key. Phase 3 swaps the
`Signer` for Sigstore keyless signing, a short-lived Fulcio certificate tied to an
OIDC identity, recorded in the Rekor transparency log (this is what reaches SLSA
Build Level 3). Same seam; the verify-before-ship policy below does not change.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from factory.ledger import RunRecord

_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://agent-factory.dev/provenance/v1"


@dataclass(frozen=True, slots=True)
class Provenance:
    """The facts about how one artifact came to be, an in-toto statement's content."""

    artifact_name: str
    content_address: str  # the SHA-256 hex from the ledger == the subject digest
    run_id: str
    tenant_id: str
    profile_name: str
    harness_name: str
    gate_accepted: bool
    created_at: float = field(default_factory=time.time)

    def statement_bytes(self) -> bytes:
        """The canonical in-toto statement to be signed. Canonical (sorted keys,
        no whitespace) so the same facts always produce the same bytes."""
        statement = {
            "_type": _STATEMENT_TYPE,
            "subject": [
                {"name": self.artifact_name, "digest": {"sha256": self.content_address}}
            ],
            "predicateType": _PREDICATE_TYPE,
            "predicate": {
                "builder": "agent-factory",
                "runId": self.run_id,
                "tenant": self.tenant_id,
                "product": self.profile_name,
                "harness": self.harness_name,
                "gateAccepted": self.gate_accepted,
                "createdAt": self.created_at,
            },
        }
        return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()


@runtime_checkable
class Signer(Protocol):
    """The signing seam. Phase 1 = keyed Ed25519; Phase 3 = Sigstore keyless."""

    alg: str
    def sign(self, payload: bytes) -> bytes: ...
    @property
    def public_key(self) -> bytes: ...


class Ed25519Signer:
    """Phase-1 keyed signer. Holds the private key; publishes the public key.

    Real asymmetric signing: only the private-key holder can sign, anyone with the
    public key can verify. (Phase 3 replaces this with Fulcio-issued short-lived
    certs + Rekor, removing long-lived key management, but the seam is identical.)
    """

    alg = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._key = private_key or Ed25519PrivateKey.generate()

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class EcdsaP384Signer:
    """Keyed ECDSA P-384 signer — the STRICT signing profile's dev/local counterpart
    (the production key lives in a FIPS-mode HSM/KMS behind the same `Signer` seam).
    Signature is DER-encoded (r,s); the public key is the X9.62 uncompressed point."""

    alg = "ecdsa-p384"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._key = private_key or ec.generate_private_key(ec.SECP384R1())

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, ec.ECDSA(hashes.SHA384()))

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )


class SigningBackend(Protocol):
    """A remote signer: produces a signature without revealing the private key. A
    KMS or HSM. The key never enters this process; we send bytes, get a signature."""

    alg: str
    def sign(self, payload: bytes) -> bytes: ...
    @property
    def public_key(self) -> bytes: ...


class ExternalSigner:
    """Phase-3 `Signer` whose private key lives outside the factory (KMS or HSM).

    Sign-by-reference: the factory hands the backend bytes and receives a
    signature; the key is never loaded here, so a compromised factory process
    cannot exfiltrate it. This is the same `Signer` seam as `Ed25519Signer`, so the
    provenance pipeline and the verify-before-ship policy are unchanged. The only
    edit is which signer the composition root constructs.
    """

    def __init__(self, backend: SigningBackend) -> None:
        self._backend = backend
        self.alg = backend.alg

    def sign(self, payload: bytes) -> bytes:
        return self._backend.sign(payload)

    @property
    def public_key(self) -> bytes:
        return self._backend.public_key


@dataclass(frozen=True, slots=True)
class SignedProvenance:
    """A signed in-toto statement: the bytes that were signed, the signature, the public key
    needed to verify it, and the signature algorithm (stated, not inferred). `alg` defaults to
    Ed25519 so existing three-argument construction stays valid."""

    statement: bytes
    signature: bytes
    public_key: bytes
    alg: str = "ed25519"

    def to_json(self) -> str:
        return json.dumps(
            {
                "statement": self.statement.decode(),
                "signature": base64.b64encode(self.signature).decode(),
                "publicKey": base64.b64encode(self.public_key).decode(),
                "algorithm": self.alg,
            },
            indent=2,
        )


def sign_provenance(provenance: Provenance, signer: Signer) -> SignedProvenance:
    """Sign a provenance statement and return the signed bundle. The Signer seam
    keeps the key choice (Ed25519 or ECDSA P-384) out of this function."""
    statement = provenance.statement_bytes()
    return SignedProvenance(
        statement, signer.sign(statement), signer.public_key, signer.alg
    )


def provenance_for_run(record: RunRecord, content_address: str, signer: Signer) -> SignedProvenance:
    """Build and sign provenance for a recorded run + one of its artifacts."""
    provenance = Provenance(
        artifact_name=f"{record.profile_name}/{record.run_id}",
        content_address=content_address,
        run_id=record.run_id,
        tenant_id=record.tenant_id,
        profile_name=record.profile_name,
        harness_name=record.harness_name,
        gate_accepted=record.accepted,
        created_at=record.created_at,
    )
    return sign_provenance(provenance, signer)


def verify_provenance(signed: SignedProvenance, expected_address: str) -> bool:
    """Verify-before-ship. BOTH must hold:
      1. the signature is valid over the statement (integrity + origin), AND
      2. the signed subject's digest equals the artifact you're about to ship.

    A valid signature over the WRONG artifact is not provenance, that's the
    classic confused-deputy hole. Checking the digest match is the policy that
    closes it (the industry rule: subject.digest == sha256 of what you deploy).

    The signature scheme is taken from the bundle's stated `alg` (ed25519 |
    ecdsa-p384) — the two signing profiles the platform ships. Unknown algorithm
    fails closed.
    """
    try:
        if signed.alg == "ed25519":
            Ed25519PublicKey.from_public_bytes(signed.public_key).verify(
                signed.signature, signed.statement
            )
        elif signed.alg == "ecdsa-p384":
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP384R1(), signed.public_key
            ).verify(signed.signature, signed.statement, ec.ECDSA(hashes.SHA384()))
        else:
            return False  # unknown algorithm -> fail closed
    except (InvalidSignature, ValueError):
        return False
    statement = json.loads(signed.statement)
    # Annotate the digest as str so the equality is a typed bool, not Any from
    # indexing the json.loads result.
    signed_digest: str = statement["subject"][0]["digest"]["sha256"]
    return signed_digest == expected_address
