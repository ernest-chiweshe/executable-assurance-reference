"""Strict finance vertical (SR 11-7 / SEC / DORA shaped). Second regulated load, same machinery.

Differs from health only in its rulebook: suitability + AML/KYC + source fidelity + calibrated
confidence, and dual control (advisor + compliance) on every consequential financial action.
"""
from __future__ import annotations

from decimal import Decimal

from ..models import (
    Action, ActionEffect, Annotation, ApprovalRequirement, Assertion, Decision,
    Outcome, PolicyContext, PolicyRef,
)
from .health import _confidence_problem

SUITABILITY = "finance:suitability"
AML_KYC = "finance:aml-kyc"
SOURCE_FIDELITY = "source:fidelity"

DRAFT, ORDER, FILE = "finance:draft-analysis", "finance:place-order", "finance:submit-filing"
_EFFECT = {DRAFT: ActionEffect.REVERSIBLE, ORDER: ActionEffect.AUTHORITATIVE, FILE: ActionEffect.EXTERNAL}


class FinancePolicy:
    content_types = frozenset({"finance:recommendation"})
    ref = PolicyRef(vertical="finance", policy_id="strict-finance-authority", version="1.0.0")

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if action.action_id not in _EFFECT:
            return Decision.deny("UNKNOWN_ACTION", "action is not in the intended-use registry")
        if action.effect is not _EFFECT[action.action_id]:
            return Decision.deny("EFFECT_MISMATCH", "action effect inconsistent with intended use")

        if action.action_id == DRAFT:
            if a.outcome_for(SUITABILITY) is Outcome.PASS:
                return Decision.allow("DRAFT_OK", "reversible analysis with suitability established")
            return Decision.allow_with("DRAFT_UNSUITABLE", "draft analysis without confirmed suitability",
                                       Annotation("disclaimer", "draft analysis — not investment advice, unreviewed"))

        if a.lineage is None:
            return Decision.deny("LINEAGE_MISSING", "consequential financial action requires producer lineage")
        for cls in (SUITABILITY, AML_KYC, SOURCE_FIDELITY):
            if a.outcome_for(cls) is not Outcome.PASS:
                return Decision.deny("FINANCIAL_CONTROL_MISSING", f"required control absent or failing: {cls}")
        problem = _confidence_problem(a, ctx, Decimal("0.90"))
        if problem:
            return Decision.deny("CONFIDENCE_NOT_ESTABLISHED", problem)

        req = ApprovalRequirement((frozenset({"advisor"}), frozenset({"compliance"})), 2, action.action_id,
                                  "consequential financial action requires advisor and compliance sign-off (recordkeeping applies)",
                                  2 * 3600 * 1_000_000)
        return Decision.require_approval("HUMAN_ACCOUNTABILITY_REQUIRED",
                                         "machine controls passed; dual-control human approval required", req)
