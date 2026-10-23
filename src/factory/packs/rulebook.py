"""The rulebook: the pack's policy as DATA, signed, validated against the pack schema, interpreted once.

What a rulebook says, in the words a domain expert reviews: for each action the schema declares,
which checks must pass, whether producer lineage is required, who must approve (role groups drawn
from the schema's roles, how many distinct people, whether the requester may approve, how long an
approval lives), when a second reviewer is required (below a calibrated confidence), what language
is prohibited, how long evidence is retained, which data classes the content carries, and the
advisory card the human sees. Its checks are DECLARATIONS: a host capability with parameters
(``verifiers``), or a platform/model/human check bound at composition; a ``custom`` executable
check is the bounded exception. It is issued as a signed ``PolicyDocument`` (the platform's existing
policy-document seam) so a decision record binds to the exact text in force.

The interpreter is one ``ConsequencePolicy`` for every domain: deny by default, every refusal a
code. Three rulebooks are three documents over this one class.

An OVERLAY (jurisdiction or organization) is a second signed document applied over a base rulebook
under one law: it may tighten, add or localise, never weaken or restructure (more approvers, a higher
confidence threshold, a shorter approval life, more prohibited terms, longer retention, extra
required checks); ``apply_overlay`` refuses everything else. That is the research's third layer
("organization/jurisdiction overlay") kept from "forking the platform or corrupting the reusable
domain semantics".
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from regulated_core.models import (
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
from regulated_core.policy_document import PolicyDocument

from .schema import PackSchema
from .verifiers import CAPABILITY_REF

RULEBOOK_SCHEMA = "lumiwright.rulebook/v1"
OVERLAY_SCHEMA = "lumiwright.rulebook-overlay/v1"
CHECK_KINDS = ("deterministic", "custom", "platform", "model", "human")
_EFFECTS = {"reversible": ActionEffect.REVERSIBLE, "authoritative": ActionEffect.AUTHORITATIVE,
            "external": ActionEffect.EXTERNAL}
_INDICATORS = {"info", "warning", "critical"}
_HOUR_US = 3_600_000_000
DEFAULT_APPROVAL_HOURS = 24
_OVERLAY_KEYS = {"schema", "base", "jurisdiction", "organization", "rules", "prohibited_language", "retention_years", "data_classes"}
_OVERLAY_RULE_KEYS = {"approval", "second_review", "required_checks", "mission_budget"}
_OVERLAY_APPROVAL_KEYS = {"minimum_approvers", "expires_after_hours", "role_groups", "requester_may_approve", "reason",
                          "below_confidence"}


class RulebookError(ValueError):
    """The rulebook (or an overlay) is invalid; every defect is listed."""


def _budget_problems(value: Any, where: str) -> list[str]:
    """A signed charge and ceiling; mission identity comes from the host, not pack data."""
    if not isinstance(value, dict) or set(value) != {"limit", "units"}:
        return [f"{where}: mission_budget requires exactly limit and units"]
    problems = []
    for key, minimum in (("limit", 0), ("units", 1)):
        number = value[key]
        if isinstance(number, bool) or not isinstance(number, int) or number < minimum:
            problems.append(f"{where}.{key}: must be an integer >= {minimum}")
    return problems


def content_digest(content: Mapping[str, Any]) -> str:
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


_CREDENTIAL_KIND = re.compile(r"[a-z][a-z0-9._:-]{0,127}\Z")


def _role_parts(value: object) -> tuple[str, str] | None:
    """Qualified roles reserve one @; the issuer, not this parser, establishes the kind."""
    if not isinstance(value, str) or not value:
        return None
    role, separator, kind = value.partition("@")
    if not role or (separator and not _CREDENTIAL_KIND.fullmatch(kind)):
        return None
    return role, kind


def _approval(spec: Any, where: str, roles: frozenset[str], p: list[str]) -> None:
    if not isinstance(spec, dict):
        p.append(f"{where}: must be an object with role_groups and minimum_approvers")
        return
    groups = spec.get("role_groups")
    if not isinstance(groups, list) or not groups or any(not isinstance(g, list) or not g for g in groups):
        p.append(f"{where}: role_groups must be a non-empty list of non-empty role lists")
    else:
        for group in groups:
            for role in group:
                parts = _role_parts(role)
                if parts is None or parts[0] not in roles:
                    p.append(f"{where}: role {role!r} must name a declared role, optionally @credential-kind ({sorted(roles)})")
    if "requester_may_approve" in spec and not isinstance(spec["requester_may_approve"], bool):
        p.append(f"{where}: requester_may_approve must be a boolean")
    minimum = spec.get("minimum_approvers")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        p.append(f"{where}: minimum_approvers must be an integer >= 1")
    elif isinstance(groups, list) and minimum < len(groups):
        p.append(f"{where}: minimum_approvers cannot be below the number of role groups")
    hours = spec.get("expires_after_hours", DEFAULT_APPROVAL_HOURS)
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24 * 30:
        p.append(f"{where}: expires_after_hours must be an integer from 1 to 720")


def _check_spec_problems(check_id: str, spec: Any) -> list[str]:
    if not isinstance(spec, dict) or spec.get("kind") not in CHECK_KINDS or not str(spec.get("version", "")).strip():
        return [f"check {check_id!r} needs a kind ({'|'.join(CHECK_KINDS)}) and a version"]
    p: list[str] = []
    if spec["kind"] == "deterministic":
        if not CAPABILITY_REF.fullmatch(str(spec.get("capability", ""))):
            p.append(f"check {check_id!r}: a deterministic check names a host capability as id@version")
        if "params" in spec and not isinstance(spec["params"], dict):
            p.append(f"check {check_id!r}: params must be an object")
    elif spec["kind"] == "custom":
        module = str(spec.get("module", ""))
        if not module.startswith("verifiers/") or not module.endswith(".py") or ".." in module:
            p.append(f"check {check_id!r}: a custom check names its module under verifiers/ (host allowance required)")
    return p


def validate_rulebook(content: Any, schema: PackSchema) -> list[str]:
    if not isinstance(content, dict):
        return ["rulebook must be an object"]
    p: list[str] = []
    if content.get("schema") != RULEBOOK_SCHEMA:
        p.append(f"schema must be {RULEBOOK_SCHEMA}")
    types = content.get("content_types")
    if not isinstance(types, list) or not types or any(not isinstance(t, str) or ":" not in t for t in types):
        p.append("content_types must be a non-empty list of 'domain:type' strings")
    for name in content.get("data_classes", ()) or ():
        if not isinstance(name, str) or name.upper() not in DataClass.__members__:
            p.append(f"unknown data class {name!r}; admitted: {sorted(m.lower() for m in DataClass.__members__)}")
    checks = content.get("checks")
    if not isinstance(checks, dict) or not checks:
        p.append("checks must declare every check the rules require (id -> {kind, version, capability, params})")
        checks = {}
    for check_id, spec in checks.items():
        p.extend(_check_spec_problems(str(check_id), spec))
    rules = content.get("rules")
    if not isinstance(rules, dict) or not rules:
        p.append("rules must cover at least one action of the schema")
        rules = {}
    roles = schema.roles()
    for action_id, rule in rules.items():
        action = schema.actions.get(str(action_id))
        if action is None:
            p.append(f"rule {action_id!r}: the schema declares no such action")
            continue
        if not isinstance(rule, dict):
            p.append(f"rule {action_id}: must be an object")
            continue
        if "mission_budget" in rule:
            p.extend(_budget_problems(rule["mission_budget"], f"rule {action_id}.mission_budget"))
        if rule.get("effect", action.effect) != action.effect:
            p.append(f"rule {action_id}: effect {rule.get('effect')!r} contradicts the schema's {action.effect!r}")
        for check_id in rule.get("required_checks", ()) or ():
            if check_id not in checks:
                p.append(f"rule {action_id}: required check {check_id!r} is not declared")
        approval = rule.get("approval")
        if action.effect == "external" and approval is None:
            p.append(f"rule {action_id}: an external action needs an approval requirement")
        if approval is not None:
            _approval(approval, f"rule {action_id}.approval", roles, p)
        second = rule.get("second_review")
        if second is not None:
            _approval(second, f"rule {action_id}.second_review", roles, p)
            try:
                threshold = Decimal(str(second.get("below_confidence", ""))) if isinstance(second, dict) else None
            except InvalidOperation:
                threshold = None
            if threshold is None or not (Decimal(0) < threshold <= Decimal(1)):
                p.append(f"rule {action_id}.second_review: below_confidence must be a decimal in (0, 1]")
        card = rule.get("card")
        if card is not None:
            if not isinstance(card, dict) or card.get("indicator") not in _INDICATORS \
                    or not (1 <= len(str(card.get("summary", ""))) <= 140):
                p.append(f"rule {action_id}.card: needs indicator in {sorted(_INDICATORS)} and a summary under 140 characters")
        for annotation in rule.get("annotations", ()) or ():
            if not isinstance(annotation, dict) or not str(annotation.get("kind", "")) or not str(annotation.get("text", "")):
                p.append(f"rule {action_id}: every annotation needs kind and text")
    for action_id, action in schema.actions.items():
        if action.effect == "external" and action_id not in rules:
            p.append(f"the schema's release action {action_id!r} has no rule; a release without a rule is ungoverned")
    for phrase in content.get("prohibited_language", ()) or ():
        if not isinstance(phrase, str) or not phrase.strip():
            p.append("prohibited_language entries must be non-empty strings")
    retention = content.get("retention_years", 7)
    if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 30:
        p.append("retention_years must be an integer from 1 to 30")
    return p


# -- overlays -----------------------------------------------------------------------------------------------

def _groups(spec: Mapping[str, Any]) -> list[frozenset[str]] | None:
    groups = spec.get("role_groups")
    if not isinstance(groups, list) or not groups:
        return None
    if any(not isinstance(g, list) or not g or any(_role_parts(r) is None for r in g) for g in groups):
        return None
    return [frozenset(g) for g in groups]


def _role_implies(child: str, parent: str) -> bool:
    child_parts, parent_parts = _role_parts(child), _role_parts(parent)
    return (child_parts is not None and parent_parts is not None
            and child_parts[0] == parent_parts[0]
            and (not parent_parts[1] or child_parts[1] == parent_parts[1]))


def _tightening(where: str, base: Mapping[str, Any] | None, over: Any, p: list[str]) -> None:
    if not isinstance(over, dict):
        p.append(f"{where}: must be an object")
        return
    for key in over:
        if key not in _OVERLAY_APPROVAL_KEYS:
            p.append(f"{where}.{key}: not overridable")
    if base is None:
        return                                             # adding a requirement where none existed tightens
    if "minimum_approvers" in over and (isinstance(over["minimum_approvers"], bool)
                                        or not isinstance(over["minimum_approvers"], int)
                                        or over["minimum_approvers"] < int(base.get("minimum_approvers", 1))):
        p.append(f"{where}.minimum_approvers: an overlay may not require fewer approvers than the base")
    if "expires_after_hours" in over and (isinstance(over["expires_after_hours"], bool)
                                          or not isinstance(over["expires_after_hours"], int)
                                          or over["expires_after_hours"] > int(base.get("expires_after_hours", DEFAULT_APPROVAL_HOURS))):
        p.append(f"{where}.expires_after_hours: an overlay may not lengthen an approval's life")
    if "role_groups" in over:
        parent_groups, child_groups = _groups(base), _groups(over)
        if parent_groups is None or child_groups is None:
            p.append(f"{where}.role_groups: require non-empty lists of valid role alternatives")
        else:
            # AND across groups; OR within each. Each parent obligation needs a child
            # group whose EVERY choice satisfies it. Preserving one safe choice is not enough.
            missing = [sorted(parent) for parent in parent_groups if not any(
                all(any(_role_implies(role, allowed) for allowed in parent) for role in child)
                for child in child_groups)]
            if missing:
                p.append(f"{where}.role_groups: an overlay may narrow or add groups, not drop the base's {missing}")
    if "requester_may_approve" in over and not isinstance(over["requester_may_approve"], bool):
        p.append(f"{where}.requester_may_approve: must be a boolean")
    if over.get("requester_may_approve") is True and not base.get("requester_may_approve", False):
        p.append(f"{where}.requester_may_approve: an overlay may not let the requester approve")
    if "below_confidence" in over:
        try:
            if Decimal(str(over["below_confidence"])) < Decimal(str(base.get("below_confidence", "0"))):
                p.append(f"{where}.below_confidence: an overlay may not lower the second-review threshold")
        except InvalidOperation:
            p.append(f"{where}.below_confidence: must be a decimal")


def validate_overlay(overlay: Any, base: Mapping[str, Any]) -> list[str]:
    if not isinstance(overlay, dict):
        return ["overlay must be an object"]
    p: list[str] = []
    if overlay.get("schema") != OVERLAY_SCHEMA:
        p.append(f"schema must be {OVERLAY_SCHEMA}")
    for key in overlay:
        if key not in _OVERLAY_KEYS:
            p.append(f"overlay key {key!r} is not overridable: an overlay may tighten, add or localise, never weaken or restructure")
    if not str(overlay.get("base", "")).strip():
        p.append("base must name the rulebook this overlay tailors (vertical/policy@version)")
    if not (str(overlay.get("jurisdiction", "")).strip() or str(overlay.get("organization", "")).strip()):
        p.append("an overlay names the jurisdiction or the organization it localises for")
    base_rules = base.get("rules", {}) or {}
    base_checks = base.get("checks", {}) or {}
    rules = overlay.get("rules", {}) or {}
    if not isinstance(rules, dict):
        p.append("rules must be an object")
        rules = {}
    for action_id, rule in rules.items():
        base_rule = base_rules.get(action_id)
        if base_rule is None:
            p.append(f"rule {action_id!r}: the base rulebook has no such rule; an overlay cannot govern new actions")
            continue
        if not isinstance(rule, dict):
            p.append(f"rule {action_id}: must be an object")
            continue
        for key in rule:
            if key not in _OVERLAY_RULE_KEYS:
                p.append(f"rule {action_id}.{key}: not overridable")
        if "approval" in rule:
            _tightening(f"rule {action_id}.approval", base_rule.get("approval"), rule["approval"], p)
        if "second_review" in rule:
            _tightening(f"rule {action_id}.second_review", base_rule.get("second_review"), rule["second_review"], p)
        if "mission_budget" in rule:
            budget = rule["mission_budget"]
            problems = _budget_problems(budget, f"rule {action_id}.mission_budget")
            p.extend(problems)
            parent = base_rule.get("mission_budget")
            if parent is not None:
                parent_problems = _budget_problems(parent, f"base rule {action_id}.mission_budget")
                p.extend(parent_problems)
                if not problems and not parent_problems:
                    if budget["limit"] > parent["limit"]:
                        p.append(f"rule {action_id}.mission_budget: an overlay may not raise the mission limit")
                    if budget["units"] < parent["units"]:
                        p.append(f"rule {action_id}.mission_budget: an overlay may not lower the effect charge")
        if "required_checks" in rule:
            extra = rule["required_checks"]
            if not isinstance(extra, list) or any(c not in base_checks for c in extra):
                p.append(f"rule {action_id}.required_checks: may add checks the base declares, nothing else")
    for phrase in overlay.get("prohibited_language", ()) or ():
        if not isinstance(phrase, str) or not phrase.strip():
            p.append("prohibited_language additions must be non-empty strings")
    if "retention_years" in overlay:
        years = overlay["retention_years"]
        if isinstance(years, bool) or not isinstance(years, int) or years < int(base.get("retention_years", 7)) or years > 30:
            p.append("retention_years: an overlay may lengthen retention (up to 30 years), not shorten it")
    for name in overlay.get("data_classes", ()) or ():
        if not isinstance(name, str) or name.upper() not in DataClass.__members__:
            p.append(f"data_classes: unknown data class {name!r}")
    return p


def apply_overlay(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """The effective rulebook: base content with the overlay's tightenings applied. Refuses a weakening."""
    problems = validate_overlay(overlay, base)
    if problems:
        raise RulebookError("; ".join(problems))
    merged: dict[str, Any] = copy.deepcopy(dict(base))
    for action_id, rule in (overlay.get("rules", {}) or {}).items():
        target = merged["rules"][action_id]
        for key in ("approval", "second_review"):
            if key in rule:
                target[key] = {**(target.get(key) or {}), **rule[key]}
        if "mission_budget" in rule:
            target["mission_budget"] = copy.deepcopy(rule["mission_budget"])
        if "required_checks" in rule:
            target["required_checks"] = list(dict.fromkeys([*(target.get("required_checks") or []), *rule["required_checks"]]))
    merged["prohibited_language"] = list(dict.fromkeys([*(merged.get("prohibited_language") or []),
                                                        *(overlay.get("prohibited_language") or [])]))
    if "retention_years" in overlay:
        merged["retention_years"] = overlay["retention_years"]
    merged["data_classes"] = list(dict.fromkeys([*(merged.get("data_classes") or []), *(overlay.get("data_classes") or [])]))
    merged["overlay"] = {"base": str(overlay["base"]), "jurisdiction": str(overlay.get("jurisdiction", "")),
                         "organization": str(overlay.get("organization", ""))}
    return merged


# -- the interpreter ----------------------------------------------------------------------------------------

def _requirement(spec: dict[str, Any], scope: str, default_reason: str) -> ApprovalRequirement:
    groups = tuple(frozenset(str(role) for role in group) for group in spec["role_groups"])
    hours = int(spec.get("expires_after_hours", DEFAULT_APPROVAL_HOURS))
    return ApprovalRequirement(role_groups=groups, minimum_approvers=int(spec["minimum_approvers"]), scope=scope,
                               reason=str(spec.get("reason") or default_reason), expires_after_us=hours * _HOUR_US,
                               requester_may_approve=bool(spec.get("requester_may_approve", False)))


def _confidence(a: Assertion) -> Decimal | None:
    if a.confidence is None:
        return None
    try:
        return Decimal(str(a.confidence.score))
    except InvalidOperation:
        return None


class RulebookPolicy:
    """The one interpreter. ``document`` is the signed PolicyDocument whose ``content`` is the rulebook;
    ``content`` overrides it with the EFFECTIVE content when an overlay has been applied (the overlay's
    own signed document is then ``document``)."""

    def __init__(self, document: PolicyDocument, schema: PackSchema, *, content: Mapping[str, Any] | None = None) -> None:
        effective = copy.deepcopy(dict(content) if content is not None else dict(document.content))
        problems = validate_rulebook(effective, schema)
        if problems:
            raise RulebookError("; ".join(problems))
        self._document = document
        self._schema = schema
        self._content = effective
        self.ref: PolicyRef = document.ref()
        self.content_types: frozenset[str] = frozenset(str(t) for t in effective["content_types"])
        self._rules: dict[str, dict[str, Any]] = {str(k): dict(v) for k, v in effective["rules"].items()}
        self._data_classes = frozenset(DataClass[str(n).upper()] for n in effective.get("data_classes", ()) or ())
        self._prohibited = tuple(re.compile(re.escape(str(x)), re.I) for x in effective.get("prohibited_language", ()) or ())
        self._payload_ref = bool(effective.get("requires_payload_ref", False))

    @property
    def document(self) -> PolicyDocument:
        return self._document

    @property
    def schema(self) -> PackSchema:
        return self._schema

    @property
    def effective_content(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._content)

    @property
    def effective_digest(self) -> str:
        return content_digest(self._content)

    @property
    def reference(self) -> str:
        return f"{self.ref.vertical}/{self.ref.policy_id}@{self.ref.version}"

    @property
    def retention_years(self) -> int:
        return int(self._content.get("retention_years", 7))

    def check_ids(self) -> tuple[str, ...]:
        return tuple(str(c) for c in self._content["checks"])

    def check_spec(self, check_id: str) -> dict[str, Any]:
        return dict(self._content["checks"][check_id])

    def check_kind(self, check_id: str) -> str:
        return str(self._content["checks"][check_id]["kind"])

    def check_version(self, check_id: str) -> str:
        return str(self._content["checks"][check_id]["version"])

    def required_checks(self, action_id: str) -> tuple[str, ...]:
        return tuple(str(c) for c in (self._rules.get(action_id, {}).get("required_checks", ()) or ()))

    def mission_budget(self, action_id: str) -> dict[str, int] | None:
        """Return the effective signed limit/charge, never a producer's requested budget.

        None means the legacy policy declares no budget, not unlimited authority.
        The release gate must refuse it wherever bounded authority is required.
        """
        value = self._rules.get(action_id, {}).get("mission_budget")
        return None if value is None else dict(value)

    def actions(self, effect: str) -> tuple[str, ...]:
        return tuple(a for a, s in self._schema.actions.items() if s.effect == effect and a in self._rules)

    def governed_actions(self) -> tuple[str, ...]:
        return tuple(a for a in self._schema.actions if a in self._rules)

    def card_template(self, action_id: str) -> dict[str, Any] | None:
        card = self._rules.get(action_id, {}).get("card")
        return None if card is None else dict(card)

    def prohibited_hits(self, text: str) -> tuple[str, ...]:
        return tuple(pattern.pattern for pattern in self._prohibited if pattern.search(text))

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        rule = self._rules.get(action.action_id)
        spec = self._schema.actions.get(action.action_id)
        if rule is None or spec is None:
            return Decision.deny("UNKNOWN_ACTION", "action is not in the rulebook")
        if action.effect is not _EFFECTS[spec.effect]:
            return Decision.deny("EFFECT_MISMATCH", "action effect inconsistent with the schema")
        if a.content_type not in self.content_types:
            return Decision.deny("CONTENT_TYPE_UNOWNED", "this rulebook does not govern that content type")
        if self._data_classes and not (self._data_classes & a.data_classes):
            return Decision.deny("DATA_UNCLASSIFIED", "content must carry the rulebook's data classes")
        if self._payload_ref and not a.payload_ref:
            return Decision.deny("PLAINTEXT_IN_RECORD", "sensitive content requires an encrypted payload reference")
        if rule.get("requires_lineage") and a.lineage is None:
            return Decision.deny("LINEAGE_MISSING", "consequential action requires producer lineage")
        for check_id in rule.get("required_checks", ()) or ():
            if a.outcome_for(str(check_id)) is not Outcome.PASS:
                return Decision.deny("CHECK_FAILED", f"required check absent or failing: {check_id}")
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
            return Decision.require_approval("APPROVAL_REQUIRED", "the rulebook requires named approval",
                                             _requirement(approval, action.action_id, "the rulebook requires named approval"))
        annotations = tuple(Annotation(str(x["kind"]), str(x["text"])) for x in rule.get("annotations", ()) or ())
        if annotations:
            return Decision.allow_with("ALLOWED_WITH_NOTICE", "reversible action with the rulebook's notices", *annotations)
        return Decision.allow("ALLOWED", "permitted by the rulebook")


__all__ = ["CHECK_KINDS", "DEFAULT_APPROVAL_HOURS", "OVERLAY_SCHEMA", "RULEBOOK_SCHEMA", "RulebookError", "RulebookPolicy",
           "apply_overlay", "content_digest", "validate_overlay", "validate_rulebook"]
