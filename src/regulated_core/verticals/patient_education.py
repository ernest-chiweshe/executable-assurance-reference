"""Clinician-Approved Patient Education Generator — the first live regulated-health vertical.

The lowest-risk vertical that still proves the regulated architecture: generate patient-facing
education from APPROVED sources, draft-first, deny-by-default, and never diagnose / prescribe /
triage / modify a record / deliver to a patient without a credentialed clinician's approval.

A pure addition on `regulated_core`: registering it touches no core file. The verifiers are REAL
deterministic local adapters behind provider interfaces (swap for validated vendors later — the
policy never changes). Every verifier result is a signed attestation bound to the assertion digest.
"""
from __future__ import annotations

import re

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..models import (
    Action, ActionEffect, Annotation, ApprovalRequirement, Assertion, DataClass, Decision,
    Outcome, PolicyContext, PolicyRef, SignedVerification, VerificationResult,
)
from ..signing import Signer
from ..verification import sign_verification

CONTENT_TYPE = "health:patient-education"
CREATE_DRAFT = "pe:create-draft"
REQUEST_APPROVAL = "pe:request-approval"
EMIT_TO_PATIENT = "pe:emit-to-patient"
_EFFECT = {
    CREATE_DRAFT: ActionEffect.REVERSIBLE,
    REQUEST_APPROVAL: ActionEffect.REVERSIBLE,
    EMIT_TO_PATIENT: ActionEffect.EXTERNAL,
}

PHI_BOUNDARY = "pe:phi-boundary"
SOURCE_FIDELITY = "pe:source-fidelity"
PROHIBITED_ACTION = "pe:prohibited-action"
READABILITY = "pe:readability"
# Order is load-bearing: the policy denies on the FIRST failing control.
_REQUIRED = (PHI_BOUNDARY, PROHIBITED_ACTION, SOURCE_FIDELITY, READABILITY)


# --- the explicit vertical declaration (intended use is a first-class, bounded contract) -------

@dataclass(frozen=True, slots=True)
class VerticalDeclaration:
    name: str
    intended_use: str
    prohibited_uses: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    risk_tiers: dict[str, int]
    required_verifiers: tuple[str, ...]
    required_approver_roles: tuple[str, ...]
    source_policy: str
    phi_policy: str
    emission_policy: str


PATIENT_EDUCATION = VerticalDeclaration(
    name="Clinician-Approved Patient Education Generator",
    intended_use="Generate draft patient-education material from approved clinical sources; clinician approves release.",
    prohibited_uses=("diagnosis", "treatment-selection", "medication-change", "prescription",
                     "triage", "emergency-advice", "autonomous-patient-delivery", "autonomous-ehr-write-back"),
    allowed_actions=(CREATE_DRAFT, REQUEST_APPROVAL, EMIT_TO_PATIENT),
    risk_tiers={CREATE_DRAFT: 1, REQUEST_APPROVAL: 2, EMIT_TO_PATIENT: 3},
    required_verifiers=_REQUIRED,
    required_approver_roles=("clinician",),
    source_policy="every medical claim must trace to an approved source paragraph",
    phi_policy="minimum-necessary; no PHI identifiers leaked into patient-facing output or external calls",
    emission_policy="deny-by-default; draft-only unless a credentialed clinician approves; output-bound single-use permit",
)


# --- provider interfaces + local deterministic adapters (swap for validated vendors later) -----

class PhiDetector(Protocol):
    def leaks(self, draft: str, allowed_identifiers: frozenset[str]) -> bool: ...


class SourceFidelityChecker(Protocol):
    def unsupported(self, draft: str, sources: tuple[str, ...]) -> bool: ...


class ProhibitedActionDetector(Protocol):
    def found(self, draft: str) -> bool: ...


class ReadabilityChecker(Protocol):
    def unsafe(self, draft: str) -> bool: ...


_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_MRN = re.compile(r"\bMRN[:\s#]*\d{4,}\b", re.I)
_PROHIBITED = re.compile(
    r"(\b\d+\s*mg\b|\bprescrib|\bdiagnos|\bincrease your dose|\bdecrease your dose|"
    r"\bstart taking\b|\bstop taking\b|\btriage\b|\bcall 911\b|\byou should take\b)", re.I)
_ALARMING = re.compile(r"(\bfatal\b|\bdeadly\b|\byou will die\b|\bterminal\b)", re.I)
_CLINICIAN_LINE = re.compile(r"contact your (clinician|doctor|care team)", re.I)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower().rstrip(".")


def _sentences(draft: str) -> list[str]:
    return [s for s in (p.strip() for p in draft.split(".")) if s]


class LocalPhiDetector:
    def leaks(self, draft: str, allowed_identifiers: frozenset[str]) -> bool:
        found = set(_SSN.findall(draft)) | set(m.group(0) for m in _MRN.finditer(draft))
        return bool(found - set(allowed_identifiers))


class LocalSourceFidelityChecker:
    """A sentence must be boilerplate or supported by an approved source paragraph."""
    def unsupported(self, draft: str, sources: tuple[str, ...]) -> bool:
        norm_sources = [_norm(s) for s in sources]
        for s in _sentences(draft):
            n = _norm(s)
            if _CLINICIAN_LINE.search(s):
                continue
            if not any(n in src for src in norm_sources):
                return True
        return False


class LocalProhibitedActionDetector:
    def found(self, draft: str) -> bool:
        return bool(_PROHIBITED.search(draft))


class LocalReadabilityChecker:
    def unsafe(self, draft: str) -> bool:
        return bool(_ALARMING.search(draft)) or _CLINICIAN_LINE.search(draft) is None


@dataclass(frozen=True, slots=True)
class Verifiers:
    phi: PhiDetector = field(default_factory=LocalPhiDetector)
    source: SourceFidelityChecker = field(default_factory=LocalSourceFidelityChecker)
    prohibited: ProhibitedActionDetector = field(default_factory=LocalProhibitedActionDetector)
    readability: ReadabilityChecker = field(default_factory=LocalReadabilityChecker)

    def outcomes(self, draft: str, sources: tuple[str, ...], allowed_identifiers: frozenset[str]) -> dict[str, Outcome]:
        p: Callable[[bool], Outcome] = lambda ok: Outcome.PASS if ok else Outcome.FAIL  # noqa: E731
        return {
            PHI_BOUNDARY: p(not self.phi.leaks(draft, allowed_identifiers)),
            PROHIBITED_ACTION: p(not self.prohibited.found(draft)),
            SOURCE_FIDELITY: p(not self.source.unsupported(draft, sources)),
            READABILITY: p(not self.readability.unsafe(draft)),
        }


def run_verifiers(
    draft: str, sources: tuple[str, ...], *, assertion_id: str, content_digest: str, tenant_id: str,
    now_us: int, verifier_signers: dict[str, Signer], allowed_identifiers: frozenset[str] = frozenset(),
    verifiers: Verifiers | None = None,
) -> tuple[SignedVerification, ...]:
    """Run every content verifier and return a SIGNED attestation (pass OR fail) per class, each
    bound to the assertion digest and signed by that verifier's own trusted identity."""
    outcomes = (verifiers or Verifiers()).outcomes(draft, sources, allowed_identifiers)
    return tuple(
        sign_verification(verifier_signers[cls], assertion_id=assertion_id, content_digest=content_digest,
                          tenant_id=tenant_id, verified_at_us=now_us,
                          result=VerificationResult(cls, outcome, verifier_signers[cls].key_id, "1.0"))
        for cls, outcome in outcomes.items()
    )


# --- the deny-by-default policy ----------------------------------------------------------------

class PatientEducationPolicy:
    content_types = frozenset({CONTENT_TYPE})
    ref = PolicyRef(vertical="patient-education", policy_id="clinician-approved-patient-education", version="1.0.0")

    def __init__(self, ref: PolicyRef | None = None) -> None:
        # A composition root may hand in a DOCUMENTED ref (PolicyDocument.ref(), digest-bearing) so every
        # decision record commits to the exact policy content in force. Default: the undocumented class ref.
        if ref is not None:
            self.ref = ref

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if action.action_id not in _EFFECT:
            return Decision.deny("UNKNOWN_ACTION", "action is outside the declared intended use")
        if action.effect is not _EFFECT[action.action_id]:
            return Decision.deny("EFFECT_MISMATCH", "action effect inconsistent with the declaration")
        if not ({DataClass.PHI, DataClass.PII} & a.data_classes):
            return Decision.deny("PHI_POLICY_ABSENT", "patient-education content must classify PHI/PII handling")
        if not a.payload_ref:
            return Decision.deny("PLAINTEXT_IN_RECORD", "sensitive content requires an encrypted payload reference")
        if a.lineage is None:
            return Decision.deny("SOURCE_PROVENANCE_MISSING", "approved-source provenance is required")
        for cls in _REQUIRED:
            outcome = a.outcome_for(cls)
            if outcome is None:
                return Decision.deny("VERIFIER_MISSING", f"required verifier attestation absent: {cls}")
            if outcome is not Outcome.PASS:
                return Decision.deny("VERIFIER_FAILED", f"safety control failed: {cls}")

        if action.effect is ActionEffect.REVERSIBLE:   # create-draft / request-approval
            return Decision.allow_with("GOVERNED_DRAFT", "safety controls passed for a clinician-review draft",
                                       Annotation("flag", "DRAFT — patient-education, clinician review required before release"))

        # emit-to-patient (external): a probabilistic producer can never deliver; a clinician must sign.
        if ctx.actor.producer:
            return Decision.deny("PRODUCER_FORBIDDEN", "autonomous patient delivery is prohibited")
        return Decision.require_approval(
            "CLINICIAN_APPROVAL_REQUIRED", "all machine controls passed; credentialed clinician must approve release",
            ApprovalRequirement((frozenset({"clinician"}),), 1, action.action_id,
                                "a credentialed clinician approves patient-facing release", 4 * 3600 * 1_000_000))


# --- audit export (the regulator-facing evidence pack for one decision) ------------------------

def audit_export(*, envelope: Any, assertion: Assertion, approval_cert: Any = None,
                 permit: Any = None,
                 qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble the defensible bundle: intended use, source provenance, verifier attestations,
    approval, emission permit, model/tool versions, and the decision reason. When a qualification
    registry is wired, each verifier attestation is chained (by digest) to the qualification report
    that establishes its operating characteristics — the engineering-trust graph."""
    rec = envelope.record
    lineage = assertion.lineage
    return {
        "vertical": PATIENT_EDUCATION.name,
        "intended_use": PATIENT_EDUCATION.intended_use,
        "prohibited_uses": list(PATIENT_EDUCATION.prohibited_uses),
        "tenant": rec.tenant_id,
        "action": rec.action.action_id,
        "decision": {"kind": rec.decision.kind.value, "reason_codes": list(rec.decision.reason_codes),
                     "rationale": rec.decision.rationale},
        "policy": {"policy_id": rec.policy.policy_id, "version": rec.policy.version,
                   "document_digest": rec.policy.digest},   # commitment to the exact policy content in force
        "assertion_digest": assertion.content_digest,
        "source_provenance": None if lineage is None else {
            "producer": lineage.producer, "run_id": lineage.run_id, "model_id": lineage.model_id,
            "prompt_digest": lineage.prompt_digest, "policy_digest": lineage.policy_digest, "gate_digest": lineage.gate_digest},
        "verifier_attestations": [
            {"class": v.result.verification_class, "outcome": v.result.outcome.value,
             "verifier_id": v.result.verifier_id, "signature_key_id": v.signature.key_id}
            for v in assertion.verifications],
        "approval": None if approval_cert is None else {
            "request_id": approval_cert.request_id, "approvers": list(approval_cert.approver_ids),
            "requirement_digest": approval_cert.requirement_digest, "signature_key_id": approval_cert.signature.key_id,
            "credential_receipts": list(getattr(approval_cert, "credential_receipt_digests", ()))},
        "emission_permit": None if permit is None else {
            "output_digest": permit.output_digest, "nonce": permit.nonce, "expires_at_us": permit.expires_at_us},
        "qualifications": qualifications,
        "evidence_head_hash": envelope.record_hash,
    }
