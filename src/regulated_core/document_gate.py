"""ONE regulated gate configured by a signed PolicyDocument: the per-domain thin subclasses become data.

``build_document_gate`` validates the document, registers its ``DocumentPolicy`` on the engine's
policy registry and its intended use on the preflight registry, resolves every verifier the
document names from a registry the pack and the platform fill by declaration, and returns a
``_RegulatedGateBase`` whose class attributes come from the document. A named verifier or signer
that is missing refuses the build; nothing is skipped silently. The evidence pack pins
``policy_ref``, ``policy_version``, ``policy_digest`` and ``pack_version`` on every decision.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .approval_exchange import ReviewMembershipEvidence
from .review_store import ReviewStore
from .document_policy import DocumentPolicy
from .engine import RegulatedEngine
from .models import Assertion, DataClass, Outcome, SignedVerification, VerificationResult
from .policy_document import PolicyDocument
from .preflight import IntendedUse, IntendedUseRegistry
from .projectos_gate import CredentialVerifier, QualificationRegistry, _RegulatedGateBase
from .signing import Signer
from .verification import sign_verification
from .worm import WormStore

#: A verifier: the draft and the contract in, an outcome (optionally with reason codes) out.
#: Deterministic ones are pure functions; the pack ships them conformance-tested.
VerifierResult = Outcome | tuple[Outcome, tuple[str, ...]]
Verifier = Callable[[str, Mapping[str, Any]], VerifierResult]


class VerifierRegistry:
    """Verifier id -> callable, filled by declaration (the pack's own checks, the platform's shared
    ones). Re-registering the same callable is idempotent; a different one for the same id refuses."""

    def __init__(self) -> None:
        self._by_id: dict[str, Verifier] = {}

    def register(self, verifier_id: str, verifier: Verifier) -> None:
        existing = self._by_id.get(verifier_id)
        if existing is not None and existing is not verifier:
            raise ValueError(f"verifier already registered: {verifier_id}")
        self._by_id[verifier_id] = verifier

    def resolve(self, verifier_id: str) -> Verifier | None:
        return self._by_id.get(verifier_id)

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_id))


class DocumentGate(_RegulatedGateBase):
    """The base recipe with every domain attribute taken from the document at build time."""

    def __init__(self, engine: RegulatedEngine, *, policy: DocumentPolicy, verifiers: VerifierRegistry,
                 verifier_signers: dict[str, Signer], pack_version: str,
                 worm: WormStore, credential_verifier: CredentialVerifier | None = None,
                 required_jurisdiction: str | None = None,
                 qualifications: QualificationRegistry | None = None,
                 review_store: ReviewStore | None = None,
                 membership_evidence: ReviewMembershipEvidence | None = None) -> None:
        super().__init__(engine, verifier_signers=verifier_signers, worm=worm,
                         credential_verifier=credential_verifier, required_jurisdiction=required_jurisdiction,
                         qualifications=qualifications, review_store=review_store,
                         membership_evidence=membership_evidence)
        self._policy = policy
        self._verifiers = verifiers
        self._pack_version = pack_version
        document = policy.document
        self.VERTICAL = document.vertical
        self.CONTENT_TYPE = sorted(policy.content_types)[0]
        self.DRAFT_ACTION = policy.action_ids("reversible")[0] if policy.action_ids("reversible") else ""
        self.EMIT_ACTION = policy.action_ids("external")[0] if policy.action_ids("external") else ""
        self.DATA_CLASSES = frozenset(DataClass[str(n)] for n in document.content.get("data_classes", ()) or ())
        self.PURPOSE = f"{document.vertical}:emit"
        self.RISK_TIER = policy.risk_tier

    @property
    def policy(self) -> DocumentPolicy:
        return self._policy

    @property
    def pinning(self) -> dict[str, str]:
        document = self._policy.document
        return {"policy_ref": f"{document.vertical}/{document.policy_id}", "policy_version": document.version,
                "policy_digest": document.digest(), "pack_version": self._pack_version}

    def _verify(self, draft: str, contract: dict[str, Any], *, assertion_id: str, content_digest: str,
                tenant_id: str, now_us: int) -> tuple[SignedVerification, ...]:
        signed: list[SignedVerification] = []
        for verifier_id in self._policy.verifier_ids():
            verifier = self._verifiers.resolve(verifier_id)
            assert verifier is not None                     # build_document_gate refused otherwise
            produced = verifier(draft, contract)
            outcome, codes = produced if isinstance(produced, tuple) else (produced, ())
            signer = self._vsign[verifier_id]
            result = VerificationResult(verification_class=verifier_id, outcome=outcome, verifier_id=signer.key_id,
                                        verifier_version=self._policy.verifier_version(verifier_id),
                                        reason_codes=tuple(codes))
            signed.append(sign_verification(signer, assertion_id=assertion_id, content_digest=content_digest,
                                            tenant_id=tenant_id, result=result, verified_at_us=now_us))
        return tuple(signed)

    def _audit(self, *, envelope: Any, assertion: Assertion, approval_cert: Any, permit: Any,
               qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
        """The evidence pack. The four pinning fields are what the release receipt must carry."""
        record = envelope.record
        return {
            **self.pinning,
            "content_type": self.CONTENT_TYPE,
            "assertion_id": assertion.assertion_id,
            "content_digest": assertion.content_digest,
            "decision": {"kind": record.decision.kind.value, "reason_codes": list(record.decision.reason_codes)},
            "policy": {"policy_id": record.policy.policy_id, "version": record.policy.version,
                       "document_digest": record.policy.digest},
            "verifications": [
                {"class": v.result.verification_class, "outcome": v.result.outcome.value,
                 "verifier": v.result.verifier_id, "version": v.result.verifier_version}
                for v in assertion.verifications
            ],
            "approval": None if approval_cert is None else {
                "approvers": list(approval_cert.approver_ids),
                "credential_receipts": list(getattr(approval_cert, "credential_receipt_digests", ()))},
            "emission_permit": None if permit is None else {"output_digest": permit.output_digest,
                                                            "nonce": permit.nonce},
            "qualifications": qualifications,
            "evidence_head_hash": envelope.record_hash,
        }


def build_document_gate(
    document: PolicyDocument,
    *,
    engine: RegulatedEngine,
    verifiers: VerifierRegistry,
    verifier_signers: Mapping[str, Signer],
    pack_version: str,
    worm: WormStore,
    intended_uses: IntendedUseRegistry | None = None,
    credential_verifier: CredentialVerifier | None = None,
    required_jurisdiction: str | None = None,
    qualifications: QualificationRegistry | None = None,
    review_store: ReviewStore | None = None,
    membership_evidence: ReviewMembershipEvidence | None = None,
) -> DocumentGate:
    """Validate, register, build. Refuses when a declared verifier has no registration or signer,
    when the document declares no external action, or when the engine already owns a content type."""
    if membership_evidence is not None and not callable(getattr(review_store, "transact_timed", None)):
        raise ValueError("membership reviews require a database-timed review writer")
    policy = DocumentPolicy(document)
    missing = [v for v in policy.verifier_ids() if verifiers.resolve(v) is None]
    unsigned = [v for v in policy.verifier_ids() if v not in verifier_signers]
    if missing or unsigned:
        raise ValueError(f"policy {document.policy_id}@{document.version}: verifiers without a registration"
                         f" {sorted(missing)}; without a signer {sorted(unsigned)}")
    if not policy.action_ids("external"):
        raise ValueError(f"policy {document.policy_id}@{document.version} declares no external (release) action")
    if len(policy.content_types) != 1:
        raise ValueError(
            f"policy {document.policy_id}@{document.version} must govern exactly one content type; "
            f"declared {sorted(policy.content_types)}"
        )
    engine._registry.register(policy)          # the engine resolves content types to this document
    if intended_uses is not None:
        for action_id in policy.action_ids("external"):
            intended_uses.declare(IntendedUse(document.vertical, action_id, policy.risk_tier))
    return DocumentGate(engine, policy=policy, verifiers=verifiers, verifier_signers=dict(verifier_signers),
                        pack_version=pack_version, worm=worm, credential_verifier=credential_verifier,
                        required_jurisdiction=required_jurisdiction, qualifications=qualifications,
                        review_store=review_store, membership_evidence=membership_evidence)


__all__ = ["DocumentGate", "Verifier", "VerifierRegistry", "VerifierResult", "build_document_gate"]
