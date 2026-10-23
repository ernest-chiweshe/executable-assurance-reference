"""Real Agent Factory reuse seam — EAGER and FAIL-CLOSED.

This is the production wiring (not the standalone-sample lazy import). The regulated core
depends on the factory ONE way: `regulated_core` -> `factory`, never the reverse. The factory's
core never imports this package, so its own dependency-light guarantee is untouched.

Fail-closed: if the factory package is not importable, this module raises at import time — a
deployment missing its signing/tenant/crypto substrate fails at startup, not mid-decision.

What it wires:
  * `factory.provenance.Signer` (Ed25519 today, `ExternalSigner` -> KMS/HSM in production, same
    seam) into the core's asymmetric `TrustDirectory` as a named authority.
  * `factory.cryptoledger.EncryptingArtifactStore` as the payload vault (sensitive content stays
    encrypted; decisions keep only an address + digest).
  * `factory.ledger.RunRecord` -> a regulated `Assertion`, promoted only when the run succeeded
    and passed the factory's quality gate.
"""
from __future__ import annotations

from hashlib import sha256

try:
    from factory.provenance import Ed25519Signer as _FactoryEd25519Signer
    from factory.cryptoledger import EncryptingArtifactStore as _EncryptingArtifactStore
    from factory.tenant import TenantContext as _TenantContext
except Exception as exc:  # pragma: no cover - exercised only in a broken deployment
    raise RuntimeError(
        "regulated_core.adapters requires the 'factory' package (tenant/crypto/provenance seams). "
        "Install it or wire the composition root before importing this module."
    ) from exc

from .canonical import canonical_bytes
from .models import Assertion, ConfidenceEvidence, DataClass, ProducerLineage, SignedVerification
from .signing import Signature, TrustDirectory


class FactorySignerAdapter:
    """Adopts a `factory.provenance.Signer` (Ed25519 / KMS-backed ExternalSigner) as the core's
    `Signer`. The factory signs raw bytes; we sign the canonical encoding and name the identity."""

    def __init__(self, key_id: str, factory_signer: object) -> None:
        self.key_id = key_id
        self._fs = factory_signer
        try:
            self.alg = str(factory_signer.alg)  # type: ignore[attr-defined]
        except AttributeError as exc:
            raise ValueError(
                "factory signer must explicitly declare its signature algorithm"
            ) from exc
        if self.alg not in ("ed25519", "ecdsa-p384"):
            raise ValueError(f"unsupported factory signer algorithm: {self.alg!r}")

    def sign(self, payload: object) -> Signature:
        return Signature(key_id=self.key_id, value=self._fs.sign(canonical_bytes(payload)).hex(),  # type: ignore[attr-defined]
                         alg=self.alg)

    def sign_bytes(self, data: bytes) -> Signature:
        return Signature(
            key_id=self.key_id,
            value=self._fs.sign(data).hex(),  # type: ignore[attr-defined]
            alg=self.alg,
        )

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self._fs.public_key)  # type: ignore[attr-defined]


def register_factory_identity(trust: TrustDirectory, key_id: str, factory_signer: object | None = None) -> FactorySignerAdapter:
    """Create a factory-backed identity, register its public key in the trust directory, return the
    signer. Pass a `factory.provenance.ExternalSigner` for the production KMS/HSM path."""
    adapter = FactorySignerAdapter(key_id, factory_signer or _FactoryEd25519Signer())
    trust.register(key_id, adapter.public_key_bytes, adapter.alg)
    return adapter


class FactoryPayloadVault:
    """Sensitive content stays encrypted in the factory's per-tenant envelope store; the decision
    record keeps only the address + a digest."""

    def __init__(self, store: _EncryptingArtifactStore) -> None:
        self._store = store

    def put(self, tenant: _TenantContext, payload: bytes) -> tuple[str, str]:
        return self._store.put(tenant, payload), sha256(payload).hexdigest()

    def get(self, tenant: _TenantContext, address: str) -> bytes:
        return self._store.get(tenant, address)


def assertion_from_factory_run(
    run: object, *, assertion_id: str, content_type: str, content_digest: str, payload_ref: str,
    data_classes: frozenset[DataClass], verifications: tuple[SignedVerification, ...],
    confidence: ConfidenceEvidence | None,
) -> Assertion:
    """Promote a Factory `RunRecord` only when it succeeded, passed its gate, and carries lineage."""
    for name in ("succeeded", "accepted", "output_address", "gate_fingerprint", "policy_hash", "harness_model", "run_id", "tenant_id", "task"):
        if not hasattr(run, name):
            raise ValueError(f"not a Factory RunRecord: missing {name}")
    if not (run.succeeded and run.accepted):            # type: ignore[attr-defined]
        raise ValueError("Factory run did not succeed and pass its quality gate")
    if run.output_address != content_digest:            # type: ignore[attr-defined]
        raise ValueError("Factory output address does not match content digest")
    lineage = ProducerLineage(
        producer="agent-factory", run_id=run.run_id, model_id=run.harness_model or "unknown",  # type: ignore[attr-defined]
        prompt_digest=sha256(run.task.encode()).hexdigest(),                                    # type: ignore[attr-defined]
        policy_digest=_as_digest(run.policy_hash), gate_digest=_as_digest(run.gate_fingerprint),  # type: ignore[attr-defined]
    )
    return Assertion(
        assertion_id=assertion_id, tenant_id=run.tenant_id, content_type=content_type,          # type: ignore[attr-defined]
        content_digest=content_digest, data_classes=data_classes, verifications=verifications,
        lineage=lineage, confidence=confidence, payload_ref=payload_ref,
    )


def _as_digest(value: str) -> str:
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return value
    return sha256((value or "none").encode()).hexdigest()
