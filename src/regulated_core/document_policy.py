"""A ConsequencePolicy that INTERPRETS a signed PolicyDocument instead of hard-coding a rulebook.

Health, finance and education become three documents over this one class. A domain expert reviews
and signs the document (actions, effects, required controls, approval role groups, a second-review
confidence threshold, data classes, prohibited language); the platform interprets it. A decision
made through this class carries the document digest in its PolicyRef, which the signed decision
record already binds, so "pinned by digest" becomes true of the authority itself.

The three hand-written rulebooks in ``regulated_core/verticals/`` stay as the proof set until each
is re-expressed as a document with a golden-decision equivalence test; nothing here touches them.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from .models import (
    Action,
    ActionEffect,
    Annotation,
    ApprovalRequirement,
    Assertion,
    DataClass,
    Decision,
    Outcome,
    PolicyContext,
    PolicyRef,
)
from .policy_document import PolicyDocument

CONTENT_SCHEMA = "regulated/policy-content/v1"
_EFFECTS = {"reversible": ActionEffect.REVERSIBLE, "authoritative": ActionEffect.AUTHORITATIVE,
            "external": ActionEffect.EXTERNAL}
_VERIFIER_KINDS = {"deterministic", "platform", "model", "human"}
DEFAULT_APPROVAL_HOURS = 24
_HOUR_US = 3_600_000_000


class PolicyContentError(ValueError):
    """The document's content does not satisfy the schema; the document must not be registered."""


def _approval_problems(spec: Any, where: str) -> list[str]:
    if not isinstance(spec, dict):
        return [f"{where}: approval must be an object with role_groups and minimum_approvers"]
    problems: list[str] = []
    groups = spec.get("role_groups")
    if not isinstance(groups, list) or not groups or any(not isinstance(g, list) or not g for g in groups):
        problems.append(f"{where}: role_groups must be a non-empty list of non-empty role lists")
    minimum = spec.get("minimum_approvers")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        problems.append(f"{where}: minimum_approvers must be an integer >= 1")
    elif isinstance(groups, list) and minimum < len(groups):
        problems.append(f"{where}: minimum_approvers cannot be below the number of role groups")
    hours = spec.get("expires_after_hours", DEFAULT_APPROVAL_HOURS)
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24 * 30:
        problems.append(f"{where}: expires_after_hours must be an integer from 1 to 720")
    scope = spec.get("scope")
    if scope is not None and (
        not isinstance(scope, str)
        or not scope
        or scope != scope.strip()
        or scope == "*"
        or len(scope) > 128
    ):
        problems.append(f"{where}: scope must be one explicit capability")
    return problems


def validate_content(content: Any) -> list[str]:
    """Every problem, not the first: a domain expert fixes the document in one pass."""
    if not isinstance(content, dict):
        return ["content must be an object"]
    problems: list[str] = []
    if content.get("schema") != CONTENT_SCHEMA:
        problems.append(f"schema must be {CONTENT_SCHEMA}")
    types = content.get("content_types")
    if not isinstance(types, list) or not types or any(not isinstance(t, str) or ":" not in t for t in types):
        problems.append("content_types must be a non-empty list of 'domain:type' strings")
    for name in content.get("data_classes", ()) or ():
        if not isinstance(name, str) or name not in DataClass.__members__:
            problems.append(f"unknown data class {name!r}; admitted: {sorted(DataClass.__members__)}")
    verifiers = content.get("verifiers")
    if not isinstance(verifiers, dict):
        problems.append("verifiers must be an object keyed by verifier id")
        verifiers = {}
    for verifier_id, spec in verifiers.items():
        if not isinstance(spec, dict) or spec.get("kind") not in _VERIFIER_KINDS or not str(spec.get("version", "")):
            problems.append(f"verifier {verifier_id!r} needs kind in {sorted(_VERIFIER_KINDS)} and a version")
    actions = content.get("actions")
    if not isinstance(actions, dict) or not actions:
        problems.append("actions must declare at least one action")
        actions = {}
    effects: list[str] = []
    for action_id, rule in actions.items():
        if not isinstance(rule, dict):
            problems.append(f"{action_id}: rule must be an object")
            continue
        effect = rule.get("effect")
        if effect not in _EFFECTS:
            problems.append(f"{action_id}: effect must be reversible, authoritative or external")
        else:
            effects.append(str(effect))
        for outcome in rule.get("required_outcomes", ()) or ():
            if outcome not in verifiers:
                problems.append(f"{action_id}: required outcome {outcome!r} has no declared verifier")
        if "mission_budget" in rule:
            budget = rule["mission_budget"]
            if (not isinstance(budget, dict) or set(budget) != {"units", "limit"}
                    or type(budget.get("units")) is not int
                    or type(budget.get("limit")) is not int
                    or not 1 <= budget["units"] <= budget["limit"] <= 2**63 - 1):
                problems.append(f"{action_id}: mission_budget needs bounded positive units and limit")
        approval = rule.get("approval")
        if effect == "external" and approval is None:
            problems.append(f"{action_id}: an external action needs an approval requirement")
        if approval is not None:
            problems.extend(_approval_problems(approval, f"{action_id}.approval"))
        second = rule.get("second_review")
        if second is not None:
            problems.extend(_approval_problems(second, f"{action_id}.second_review"))
            try:
                threshold = Decimal(str(second.get("below_confidence", ""))) if isinstance(second, dict) else None
            except InvalidOperation:
                threshold = None
            if threshold is None or not (Decimal(0) < threshold <= Decimal(1)):
                problems.append(f"{action_id}.second_review: below_confidence must be a decimal in (0, 1]")
        for annotation in rule.get("annotations", ()) or ():
            if not isinstance(annotation, dict) or not str(annotation.get("kind", "")) or not str(annotation.get("text", "")):
                problems.append(f"{action_id}: every annotation needs kind and text")
    if effects and "external" not in effects and "authoritative" not in effects:
        problems.append("a policy with only reversible actions governs nothing consequential; declare the release action")
    tier = content.get("risk_tier", 3)
    if isinstance(tier, bool) or not isinstance(tier, int) or not 1 <= tier <= 4:
        problems.append("risk_tier must be an integer from 1 to 4 (the preflight tiers)")
    return problems


def _requirement(spec: dict[str, Any], scope: str, default_reason: str) -> ApprovalRequirement:
    groups = tuple(frozenset(str(role) for role in group) for group in spec["role_groups"])
    hours = int(spec.get("expires_after_hours", DEFAULT_APPROVAL_HOURS))
    return ApprovalRequirement(role_groups=groups, minimum_approvers=int(spec["minimum_approvers"]),
                               scope=str(spec.get("scope", scope)),
                               reason=str(spec.get("reason") or default_reason), expires_after_us=hours * _HOUR_US,
                               requester_may_approve=bool(spec.get("requester_may_approve", False)))


def _confidence(a: Assertion) -> Decimal | None:
    if a.confidence is None:
        return None
    try:
        return Decimal(str(a.confidence.score))
    except InvalidOperation:
        return None


class DocumentPolicy:
    """ConsequencePolicy over one signed document. Deny by default; every deny names its code."""

    def __init__(self, document: PolicyDocument) -> None:
        problems = validate_content(document.content)
        if problems:
            raise PolicyContentError("; ".join(problems))
        self._document = document
        self.ref: PolicyRef = document.ref()                       # carries the content digest
        self.content_types: frozenset[str] = frozenset(str(t) for t in document.content["content_types"])
        self._actions: dict[str, dict[str, Any]] = {str(k): dict(v) for k, v in document.content["actions"].items()}
        self._data_classes = frozenset(DataClass[str(n)] for n in document.content.get("data_classes", ()) or ())
        self._payload_ref = bool(document.content.get("requires_payload_ref", False))
        self._mission_budgets: dict[str, dict[str, int]] = {
            action: {"units": rule["mission_budget"]["units"], "limit": rule["mission_budget"]["limit"]}
            for action, rule in self._actions.items() if "mission_budget" in rule
        }

    @property
    def document(self) -> PolicyDocument:
        return self._document

    @property
    def risk_tier(self) -> int:
        return int(self._document.content.get("risk_tier", 3))

    def mission_budget(self, action_id: str) -> dict[str, int] | None:
        """Return the action's signed budget terms; omission grants no budget."""
        budget = self._mission_budgets.get(action_id)
        if budget is None:
            return None
        return {"units": budget["units"], "limit": budget["limit"]}

    def action_ids(self, effect: str) -> tuple[str, ...]:
        return tuple(a for a, r in self._actions.items() if r.get("effect") == effect)

    def verifier_ids(self) -> tuple[str, ...]:
        return tuple(str(v) for v in self._document.content["verifiers"])

    def verifier_version(self, verifier_id: str) -> str:
        return str(self._document.content["verifiers"][verifier_id]["version"])

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        rule = self._actions.get(action.action_id)
        if rule is None:
            return Decision.deny("UNKNOWN_ACTION", "action is not in the intended-use registry")
        if action.effect is not _EFFECTS[str(rule["effect"])]:
            return Decision.deny("EFFECT_MISMATCH", "action effect inconsistent with intended use")
        if a.content_type not in self.content_types:
            return Decision.deny("CONTENT_TYPE_UNOWNED", "this document does not govern that content type")
        if self._data_classes and not (self._data_classes & a.data_classes):
            return Decision.deny("DATA_UNCLASSIFIED", "content must carry the document's data classes")
        if self._payload_ref and not a.payload_ref:
            return Decision.deny("PLAINTEXT_IN_RECORD", "sensitive content requires an encrypted payload reference")
        if rule.get("requires_lineage") and a.lineage is None:
            return Decision.deny("LINEAGE_MISSING", "consequential action requires producer lineage")
        for outcome in rule.get("required_outcomes", ()) or ():
            if a.outcome_for(str(outcome)) is not Outcome.PASS:
                return Decision.deny("CONTROL_MISSING", f"required control absent or failing: {outcome}")
        second = rule.get("second_review")
        if second is not None:
            confidence = _confidence(a)
            threshold = Decimal(str(second["below_confidence"]))
            if confidence is None or confidence < threshold:
                return Decision.require_approval(
                    "SECOND_REVIEW", f"confidence below {threshold}; a second reviewer is required",
                    _requirement(second, action.action_id, f"confidence below {threshold} requires a second reviewer"))
        approval = rule.get("approval")
        if approval is not None:
            return Decision.require_approval("APPROVAL_REQUIRED", "the document requires named approval",
                                             _requirement(approval, action.action_id,
                                                          "the policy document requires named approval"))
        annotations = tuple(Annotation(str(x["kind"]), str(x["text"])) for x in rule.get("annotations", ()) or ())
        if annotations:
            return Decision.allow_with("ALLOWED_WITH_NOTICE", "reversible action with the document's notices",
                                       *annotations)
        return Decision.allow("ALLOWED", "permitted by the document")


__all__ = ["CONTENT_SCHEMA", "DocumentPolicy", "PolicyContentError", "validate_content"]
