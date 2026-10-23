"""Strict health vertical (HIPAA/PHI shaped). Deny-by-default. Pure addition.

Reads only outcomes the engine already authenticated. Enforces: PHI/PII data-classification,
privacy + minimum-necessary + destination + tenant-isolation + phi-safety verifications, a
payload reference (no plaintext in the record), producer lineage, source fidelity and clinical
validity for record/external actions, and calibrated confidence with a real method that is not
stale — then a credentialed clinician (plus a privacy officer for external PHI), dual control.
"""
from __future__ import annotations

from decimal import Decimal

from ..models import (
    Action, ActionEffect, Annotation, ApprovalRequirement, Assertion, DataClass, Decision,
    Outcome, PolicyContext, PolicyRef,
)

DAY_US = 86_400_000_000
PHI_SAFETY = "health:phi-safety"
PURPOSE = "privacy:purpose-authorized"
MIN_NECESSARY = "privacy:minimum-necessary"
DESTINATION = "privacy:destination-authorized"
TENANT_ISO = "security:tenant-isolation"
SOURCE_FIDELITY = "source:fidelity"
CLINICAL_VALIDITY = "health:clinical-validity"

DRAFT, COMMIT, SEND = "health:draft-note", "health:commit-record", "health:send-patient"
_EFFECT = {DRAFT: ActionEffect.REVERSIBLE, COMMIT: ActionEffect.AUTHORITATIVE, SEND: ActionEffect.EXTERNAL}


class HealthPolicy:
    content_types = frozenset({"health:clinical-claim", "health:patient-education"})
    ref = PolicyRef(vertical="health", policy_id="strict-health-authority", version="1.0.0")

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if action.action_id not in _EFFECT:
            return Decision.deny("UNKNOWN_ACTION", "action is not in the intended-use registry")
        if action.effect is not _EFFECT[action.action_id]:
            return Decision.deny("EFFECT_MISMATCH", "action effect inconsistent with intended use")
        if not ({DataClass.PII, DataClass.PHI} & a.data_classes):
            return Decision.deny("DATA_UNCLASSIFIED", "health content must classify PII/PHI")
        if not a.payload_ref:
            return Decision.deny("PLAINTEXT_IN_RECORD", "sensitive content requires an encrypted payload reference")
        if a.lineage is None:
            return Decision.deny("LINEAGE_MISSING", "regulated action requires producer lineage")

        for cls in (PHI_SAFETY, PURPOSE, MIN_NECESSARY, DESTINATION, TENANT_ISO):
            if a.outcome_for(cls) is not Outcome.PASS:
                return Decision.deny("PRIVACY_CONTROL_MISSING", f"required privacy/security control absent or failing: {cls}")

        if action.action_id == DRAFT:
            if action.destination != "clinical-review-queue":
                return Decision.deny("DRAFT_DESTINATION_FORBIDDEN", "drafts go only to the governed review queue")
            if a.outcome_for(SOURCE_FIDELITY) is not Outcome.PASS:
                return Decision.deny("SOURCE_FIDELITY_MISSING", "even a draft requires traceable source fidelity")
            return Decision.allow_with("GOVERNED_DRAFT", "review-only draft passed privacy and source controls",
                                       Annotation("flag", "DRAFT — NOT PART OF THE CLINICAL RECORD"))

        for cls in (SOURCE_FIDELITY, CLINICAL_VALIDITY):
            if a.outcome_for(cls) is not Outcome.PASS:
                return Decision.deny("CLINICAL_EVIDENCE_MISSING", f"required clinical evidence absent or failing: {cls}")

        floor = Decimal("0.95") if action.action_id == SEND else Decimal("0.90")
        problem = _confidence_problem(a, ctx, floor)
        if problem:
            return Decision.deny("CONFIDENCE_NOT_ESTABLISHED", problem)

        if action.action_id == COMMIT:
            req = ApprovalRequirement((frozenset({"clinician"}),), 1, action.action_id,
                                      "a licensed clinician must accept responsibility for the record", 4 * 3600 * 1_000_000)
        else:  # SEND (external PHI)
            req = ApprovalRequirement((frozenset({"clinician"}), frozenset({"privacy-officer"})), 2, action.action_id,
                                      "external PHI transmission requires clinical and privacy approval", 2 * 3600 * 1_000_000)
        return Decision.require_approval("HUMAN_ACCOUNTABILITY_REQUIRED",
                                         "machine controls passed; accountable human approval remains mandatory", req)


def _confidence_problem(a: Assertion, ctx: PolicyContext, floor: Decimal) -> str | None:
    c = a.confidence
    if c is None:
        return "calibrated confidence evidence is missing"
    if c.method_id == "model-self-report":
        return "model self-report is not an accepted calibration method"
    if c.calibrated_at_us > ctx.now_us:
        return "confidence calibration timestamp is in the future"
    if ctx.now_us - c.calibrated_at_us > 180 * DAY_US:
        return "confidence calibration evidence is stale (over 180 days)"
    if Decimal(c.score) < floor:
        return f"confidence {c.score} is below the action threshold {floor}"
    return None
