"""Investment Research & Compliance Brief Generator — first vertical in the Financial Services domain.

The finance analogue of patient-education, chosen (per the same philosophy: research brief, NOT
investment advice) to prove a DIFFERENT class of controls: financial-communication safety, not just
AML/KYC. Generate a regulated research brief from approved sources (filings, reports, market data);
it may summarize, cite risks and contradictory evidence, but it may NOT recommend Buy/Sell/Hold,
allocate capital, execute trades, personalize advice, or make suitability decisions. Deny-by-default,
draft-first, released only after a compliance review.

A pure addition on `regulated_core` (governance plane) + a knowledge-backed Project OS vertical in the
Financial Services domain. Same recipe as health; different domain; different verifiers.
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

CONTENT_TYPE = "finance:investment-research"
CREATE_DRAFT = "ir:create-draft"
REQUEST_REVIEW = "ir:request-review"
EMIT_BRIEF = "ir:emit-brief"
_EFFECT = {CREATE_DRAFT: ActionEffect.REVERSIBLE, REQUEST_REVIEW: ActionEffect.REVERSIBLE,
           EMIT_BRIEF: ActionEffect.EXTERNAL}

SOURCE_FIDELITY = "ir:source-fidelity"
MATERIAL_MISSTATEMENT = "ir:material-misstatement"
INVESTMENT_ADVICE = "ir:investment-advice"
COMPLIANCE_LANGUAGE = "ir:compliance-language"
CONFLICT_OF_INTEREST = "ir:conflict-of-interest"
# Order is load-bearing: the policy denies on the FIRST failing control.
_REQUIRED = (INVESTMENT_ADVICE, MATERIAL_MISSTATEMENT, SOURCE_FIDELITY, COMPLIANCE_LANGUAGE, CONFLICT_OF_INTEREST)


@dataclass(frozen=True, slots=True)
class VerticalDeclaration:
    name: str
    domain: str
    intended_use: str
    prohibited_uses: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    risk_tiers: dict[str, int]
    required_verifiers: tuple[str, ...]
    required_approver_roles: tuple[str, ...]
    source_policy: str
    emission_policy: str


INVESTMENT_RESEARCH = VerticalDeclaration(
    name="Investment Research & Compliance Brief Generator",
    domain="financial-services",
    intended_use="Generate a research/compliance brief from approved financial sources; compliance approves release.",
    prohibited_uses=("investment-advice", "buy-sell-hold-recommendation", "capital-allocation", "trade-execution",
                     "suitability-decision", "personalized-advice", "guaranteed-return-claim"),
    allowed_actions=(CREATE_DRAFT, REQUEST_REVIEW, EMIT_BRIEF),
    risk_tiers={CREATE_DRAFT: 1, REQUEST_REVIEW: 2, EMIT_BRIEF: 3},
    required_verifiers=_REQUIRED,
    required_approver_roles=("research-principal", "compliance"),
    source_policy="every financial statement must trace to an approved filing/report/market-data paragraph",
    emission_policy="deny-by-default; draft-only unless research-principal AND compliance approve; single-use permit",
)


# --- provider interfaces + local deterministic adapters (swap for validated vendors later) -----

class SourceFidelityChecker(Protocol):
    def unsupported(self, draft: str, sources: tuple[str, ...]) -> bool: ...


class MaterialMisstatementChecker(Protocol):
    def found(self, draft: str, sources: tuple[str, ...]) -> bool: ...


class InvestmentAdviceDetector(Protocol):
    def found(self, draft: str) -> bool: ...


class ComplianceLanguageChecker(Protocol):
    def missing(self, draft: str) -> bool: ...


class ConflictOfInterestChecker(Protocol):
    def missing(self, draft: str) -> bool: ...


_METRIC = re.compile(r"(\$|%|\bpercent\b|\bbillion\b|\bmillion\b|\brevenue\b|\bprofit\b|\beps\b|\bgrowth\b|\bmargin\b|\bearnings\b)", re.I)
_ADVICE = re.compile(r"\b(strong buy|strong sell|buy|sell|overweight|underweight|price target|"
                     r"guaranteed returns?|will outperform|will beat|should invest|should buy|should sell)\b", re.I)
_DISCLAIMER = re.compile(r"(not investment advice|informational purposes|does not constitute (investment )?advice)", re.I)
_DISCLOSURE = re.compile(r"(disclosures?:|no conflicts? of interest|holds no position|the author (holds|has|reports))", re.I)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower().rstrip(".")


def _sentences(draft: str) -> list[str]:
    return [s for s in (p.strip() for p in draft.split(".")) if s]


def _is_boilerplate(s: str) -> bool:
    return bool(_DISCLAIMER.search(s) or _DISCLOSURE.search(s))


class LocalSourceFidelityChecker:
    def unsupported(self, draft: str, sources: tuple[str, ...]) -> bool:
        ns = [_norm(x) for x in sources]
        return any(not _is_boilerplate(s) and not any(_norm(s) in src for src in ns) for s in _sentences(draft))


class LocalMaterialMisstatementChecker:
    """A sentence carrying a financial metric must be traceable to a source."""
    def found(self, draft: str, sources: tuple[str, ...]) -> bool:
        ns = [_norm(x) for x in sources]
        return any(_METRIC.search(s) and not _is_boilerplate(s) and not any(_norm(s) in src for src in ns)
                   for s in _sentences(draft))


class LocalInvestmentAdviceDetector:
    def found(self, draft: str) -> bool:
        return bool(_ADVICE.search(draft))


class LocalComplianceLanguageChecker:
    def missing(self, draft: str) -> bool:
        return _DISCLAIMER.search(draft) is None


class LocalConflictOfInterestChecker:
    def missing(self, draft: str) -> bool:
        return _DISCLOSURE.search(draft) is None


@dataclass(frozen=True, slots=True)
class Verifiers:
    source: SourceFidelityChecker = field(default_factory=LocalSourceFidelityChecker)
    material: MaterialMisstatementChecker = field(default_factory=LocalMaterialMisstatementChecker)
    advice: InvestmentAdviceDetector = field(default_factory=LocalInvestmentAdviceDetector)
    compliance: ComplianceLanguageChecker = field(default_factory=LocalComplianceLanguageChecker)
    conflict: ConflictOfInterestChecker = field(default_factory=LocalConflictOfInterestChecker)

    def outcomes(self, draft: str, sources: tuple[str, ...]) -> dict[str, Outcome]:
        p: Callable[[bool], Outcome] = lambda ok: Outcome.PASS if ok else Outcome.FAIL  # noqa: E731
        return {
            INVESTMENT_ADVICE: p(not self.advice.found(draft)),
            MATERIAL_MISSTATEMENT: p(not self.material.found(draft, sources)),
            SOURCE_FIDELITY: p(not self.source.unsupported(draft, sources)),
            COMPLIANCE_LANGUAGE: p(not self.compliance.missing(draft)),
            CONFLICT_OF_INTEREST: p(not self.conflict.missing(draft)),
        }


def run_verifiers(draft: str, sources: tuple[str, ...], *, assertion_id: str, content_digest: str,
                  tenant_id: str, now_us: int, verifier_signers: dict[str, Signer],
                  verifiers: Verifiers | None = None) -> tuple[SignedVerification, ...]:
    outcomes = (verifiers or Verifiers()).outcomes(draft, sources)
    return tuple(
        sign_verification(verifier_signers[cls], assertion_id=assertion_id, content_digest=content_digest,
                          tenant_id=tenant_id, verified_at_us=now_us,
                          result=VerificationResult(cls, outcome, verifier_signers[cls].key_id, "1.0"))
        for cls, outcome in outcomes.items())


class InvestmentResearchPolicy:
    content_types = frozenset({CONTENT_TYPE})
    ref = PolicyRef(vertical="investment-research", policy_id="compliance-reviewed-research", version="1.0.0")

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
        if DataClass.FINANCIAL not in a.data_classes:
            return Decision.deny("DATA_UNCLASSIFIED", "research content must classify FINANCIAL handling")
        if a.lineage is None:
            return Decision.deny("SOURCE_PROVENANCE_MISSING", "approved-source provenance is required")
        for cls in _REQUIRED:
            outcome = a.outcome_for(cls)
            if outcome is None:
                return Decision.deny("VERIFIER_MISSING", f"required verifier attestation absent: {cls}")
            if outcome is not Outcome.PASS:
                return Decision.deny("VERIFIER_FAILED", f"compliance control failed: {cls}")

        if action.effect is ActionEffect.REVERSIBLE:
            return Decision.allow_with("GOVERNED_DRAFT", "compliance controls passed for a review draft",
                                       Annotation("disclaimer", "DRAFT — research brief, compliance review required; not investment advice"))
        if ctx.actor.producer:
            return Decision.deny("PRODUCER_FORBIDDEN", "autonomous distribution of a financial brief is prohibited")
        return Decision.require_approval(
            "COMPLIANCE_APPROVAL_REQUIRED", "machine controls passed; research-principal and compliance must approve",
            ApprovalRequirement((frozenset({"research-principal"}), frozenset({"compliance"})), 2, action.action_id,
                                "dual sign-off (research-principal + compliance) before release", 4 * 3600 * 1_000_000))


def audit_export(*, envelope: Any, assertion: Assertion, approval_cert: Any = None,
                 permit: Any = None,
                 qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
    rec = envelope.record
    lineage = assertion.lineage
    return {
        "vertical": INVESTMENT_RESEARCH.name, "domain": INVESTMENT_RESEARCH.domain,
        "intended_use": INVESTMENT_RESEARCH.intended_use, "prohibited_uses": list(INVESTMENT_RESEARCH.prohibited_uses),
        "tenant": rec.tenant_id, "action": rec.action.action_id,
        "decision": {"kind": rec.decision.kind.value, "reason_codes": list(rec.decision.reason_codes),
                     "rationale": rec.decision.rationale},
        "policy": {"policy_id": rec.policy.policy_id, "version": rec.policy.version,
                   "document_digest": rec.policy.digest},   # commitment to the exact policy content in force
        "assertion_digest": assertion.content_digest,
        "source_provenance": None if lineage is None else {
            "producer": lineage.producer, "run_id": lineage.run_id, "model_id": lineage.model_id},
        "verifier_attestations": [
            {"class": v.result.verification_class, "outcome": v.result.outcome.value,
             "verifier_id": v.result.verifier_id, "signature_key_id": v.signature.key_id}
            for v in assertion.verifications],
        "approval": None if approval_cert is None else {
            "request_id": approval_cert.request_id, "approvers": list(approval_cert.approver_ids),
            "requirement_digest": approval_cert.requirement_digest,
            "credential_receipts": list(getattr(approval_cert, "credential_receipt_digests", ()))},
        "emission_permit": None if permit is None else {"output_digest": permit.output_digest, "nonce": permit.nonce},
        "qualifications": qualifications,
        "evidence_head_hash": envelope.record_hash,
    }
