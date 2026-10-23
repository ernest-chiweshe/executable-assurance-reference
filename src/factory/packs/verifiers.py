"""Host-qualified deterministic verifier capabilities: a pack parameterises them, it never ships code.

The research conclusion this module implements (``docs/verticals - research/00 DOMAIN-PACK-FOUNDATION-
RESEARCH-2026-09-06.md``, "Deterministic verification"): the platform must not import arbitrary pack
Python. A pack's rulebook names a *capability* by id and version (``text.prohibited-terms@1``) and
supplies parameters and thresholds; the host owns the implementation, its qualification evidence
and its version. That is how OPA keeps built-ins in the engine and policy in the bundle, and how a
verifier registry is keyed "by capability, version and qualification, not by domain or import path"
(research gate 5). A genuinely custom executable verifier is a separate, host-allowed, separately
listed component (see ``checks.load_custom_module``), off by default.

Every capability is a pure function of ``(draft, contract)``: no I/O, no clock, no network, so the
same inputs give the same outcome on every host, which is what makes its golden cases meaningful.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from regulated_core.models import Outcome

CheckResult = tuple[Outcome, tuple[str, ...]]
Check = Callable[[str, Mapping[str, Any]], CheckResult]

CAPABILITY_REF = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+@(0|[1-9]\d*)$")
_MAX_PATTERN = 200
_PASS: CheckResult = (Outcome.PASS, ())


class VerifierError(ValueError):
    """A capability is unknown, or a pack's parameters do not fit its parameter schema."""


@dataclass(frozen=True, slots=True)
class Param:
    """One parameter a capability accepts: ``string``, ``strings`` (list of str), ``int`` or ``bool``."""

    type: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class Capability:
    id: str
    version: int
    description: str
    qualification: str                                  # the evidence class the host holds for it
    params: Mapping[str, Param]
    build: Callable[[Mapping[str, Any]], Check]

    @property
    def reference(self) -> str:
        return f"{self.id}@{self.version}"


@dataclass(frozen=True, slots=True)
class BoundCheck:
    """A rulebook check bound to a host capability with validated parameters."""

    check_id: str
    capability: str
    version: str                                        # the rulebook's own version for this check
    params: Mapping[str, Any]
    run: Check
    qualification: str


def _fail(*reasons: str) -> CheckResult:
    return (Outcome.FAIL, tuple(reasons))


def _norm(text: Any) -> str:
    return re.sub(r"\s+", "", str(text)).lower()


def _prohibited_terms(params: Mapping[str, Any]) -> Check:
    compiled = [re.compile(re.escape(str(t)), re.I) for t in params.get("terms", ()) or ()]
    compiled += [re.compile(str(p), re.I) for p in params.get("patterns", ()) or ()]
    reason = str(params.get("reason", "PROHIBITED_TERM"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        return _fail(reason) if any(c.search(str(draft)) for c in compiled) else _PASS
    return check


def _excludes_contract_field(params: Mapping[str, Any]) -> Check:
    field_name = str(params["field"])
    reason = str(params.get("reason", "WITHHELD_VALUE_LEAKED"))
    minimum = int(params.get("min_length", 3))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        value = _norm(contract.get(field_name, ""))
        return _fail(reason) if len(value) >= minimum and value in _norm(draft) else _PASS
    return check


def _fields_present(params: Mapping[str, Any]) -> Check:
    fields = [str(f) for f in params["fields"]]
    reason = str(params.get("reason", "FIELD_MISSING"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        return _fail(reason) if any(contract.get(f) in (None, "", [], {}) for f in fields) else _PASS
    return check


def _list_covers(params: Mapping[str, Any]) -> Check:
    required_field, covered_field = str(params["required_field"]), str(params["covered_field"])
    reason_missing = str(params.get("reason_missing", "ITEM_UNCOVERED"))
    reason_empty = str(params.get("reason_empty", "NOTHING_REQUIRED"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        required = [str(x) for x in contract.get(required_field, ()) or ()]
        covered = {str(x) for x in contract.get(covered_field, ()) or ()}
        if not required:
            return _fail(reason_empty)
        return _fail(reason_missing) if any(r not in covered for r in required) else _PASS
    return check


def _regions_normalized(params: Mapping[str, Any]) -> Check:
    items_field = str(params.get("items_field", "findings"))
    region_field = str(params.get("region_field", "region"))
    media_field = str(params.get("media_field", "media"))
    dims = int(params.get("dimensions", 4))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        items = list(contract.get(items_field, ()) or ())
        if not items:
            return (Outcome.INDETERMINATE, ("NO_LOCALISATION",)) if contract.get(media_field) else _PASS
        for item in items:
            region = item.get(region_field) if isinstance(item, Mapping) else None
            if region is None:
                return _fail("REGION_MISSING")
            try:
                values = [float(v) for v in region]
            except (TypeError, ValueError):
                return _fail("REGION_OUT_OF_BOUNDS")
            if len(values) != dims or any(not 0.0 <= v <= 1.0 for v in values):
                return _fail("REGION_OUT_OF_BOUNDS")
        return _PASS
    return check


def _non_empty(params: Mapping[str, Any]) -> Check:
    reason = str(params.get("reason", "EMPTY"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        return _PASS if str(draft).strip() else _fail(reason)
    return check


def _max_length(params: Mapping[str, Any]) -> Check:
    limit = int(params["max_chars"])
    reason = str(params.get("reason", "TOO_LONG"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        return _PASS if len(str(draft)) <= limit else _fail(reason)
    return check


def _requires_source_citations(params: Mapping[str, Any]) -> Check:
    source_field = str(params.get("source_field", "approved_sources"))
    citation_field = str(params.get("citation_field", "citations"))
    reason = str(params.get("reason", "SOURCE_FIDELITY_UNPROVEN"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        approved = {str(item) for item in contract.get(source_field, ()) or ()}
        cited = {str(item) for item in contract.get(citation_field, ()) or ()}
        return _PASS if approved and cited and cited.issubset(approved) else _fail(reason)
    return check


def _requires_controlled_revision(params: Mapping[str, Any]) -> Check:
    document_field = str(params.get("document_field", "controlled_document_id"))
    revision_field = str(params.get("revision_field", "controlled_revision"))
    reason = str(params.get("reason", "CONTROLLED_REVISION_MISSING"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        present = bool(str(contract.get(document_field, "")).strip() and str(contract.get(revision_field, "")).strip())
        return _PASS if present else _fail(reason)
    return check


def _prohibits_unapproved_commands(params: Mapping[str, Any]) -> Check:
    commands_field = str(params.get("commands_field", "requested_commands"))
    allowlist_field = str(params.get("allowlist_field", "approved_commands"))
    reason = str(params.get("reason", "UNAPPROVED_OPERATIONAL_COMMAND"))

    def check(draft: str, contract: Mapping[str, Any]) -> CheckResult:
        requested = {str(item) for item in contract.get(commands_field, ()) or ()}
        allowed = {str(item) for item in contract.get(allowlist_field, ()) or ()}
        return _PASS if requested.issubset(allowed) else _fail(reason)
    return check


_PURE = "host-deterministic: pure function of (draft, contract); no I/O, clock or network; cased in the platform suite"

HOST_CAPABILITIES: tuple[Capability, ...] = (
    Capability("text.prohibited-terms", 1, "fail when the draft contains any listed term or regex pattern (case-insensitive)",
               _PURE, {"terms": Param("strings", False), "patterns": Param("strings", False), "reason": Param("string", False)},
               _prohibited_terms),
    Capability("text.excludes-contract-field", 1, "fail when a value the contract says to withhold appears in the draft",
               _PURE, {"field": Param("string"), "reason": Param("string", False), "min_length": Param("int", False)},
               _excludes_contract_field),
    Capability("contract.fields-present", 1, "fail when a required contract field is missing or empty",
               _PURE, {"fields": Param("strings"), "reason": Param("string", False)}, _fields_present),
    Capability("contract.list-covers", 1, "fail when any item of one contract list is absent from another (rubric coverage)",
               _PURE, {"required_field": Param("string"), "covered_field": Param("string"),
                       "reason_missing": Param("string", False), "reason_empty": Param("string", False)}, _list_covers),
    Capability("contract.regions-normalized", 1,
               "every localised finding carries a region inside the unit square; media without findings is indeterminate",
               _PURE, {"items_field": Param("string", False), "region_field": Param("string", False),
                       "media_field": Param("string", False), "dimensions": Param("int", False)}, _regions_normalized),
    Capability("text.non-empty", 1, "fail on a blank draft", _PURE, {"reason": Param("string", False)}, _non_empty),
    Capability("text.max-length", 1, "fail when the draft exceeds a character limit", _PURE,
               {"max_chars": Param("int"), "reason": Param("string", False)}, _max_length),
    Capability("evidence.approved-source-citations", 1,
               "require at least one citation and prove every citation belongs to the approved source set",
               _PURE, {"source_field": Param("string", False), "citation_field": Param("string", False),
                       "reason": Param("string", False)}, _requires_source_citations),
    Capability("operations.controlled-revision", 1,
               "require the identifier and revision of the controlled operational document",
               _PURE, {"document_field": Param("string", False), "revision_field": Param("string", False),
                       "reason": Param("string", False)}, _requires_controlled_revision),
    Capability("operations.command-allowlist", 1,
               "fail when an operational command is not in the contract's approved command set",
               _PURE, {"commands_field": Param("string", False), "allowlist_field": Param("string", False),
                       "reason": Param("string", False)}, _prohibits_unapproved_commands),
)


def validate_params(capability: Capability, params: Any) -> list[str]:
    """Every defect: unknown keys, missing required keys, wrong types, regex that will not compile."""
    if not isinstance(params, Mapping):
        return [f"{capability.reference}: params must be an object"]
    p: list[str] = []
    for name in params:
        if name not in capability.params:
            p.append(f"{capability.reference}: unknown parameter {name!r}")
    for name, spec in capability.params.items():
        if name not in params:
            if spec.required:
                p.append(f"{capability.reference}: parameter {name!r} is required")
            continue
        value = params[name]
        ok = {"string": isinstance(value, str) and bool(value.strip()),
              "strings": isinstance(value, list) and all(isinstance(v, str) and v.strip() for v in value),
              "int": isinstance(value, int) and not isinstance(value, bool),
              "bool": isinstance(value, bool)}[spec.type]
        if not ok:
            p.append(f"{capability.reference}: parameter {name!r} must be {spec.type}")
    patterns = params.get("patterns")
    for pattern in patterns if isinstance(patterns, list) else ():
        if not isinstance(pattern, str):
            continue
        if len(pattern) > _MAX_PATTERN:
            p.append(f"{capability.reference}: pattern longer than {_MAX_PATTERN} characters")
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            p.append(f"{capability.reference}: pattern {pattern!r} does not compile: {exc}")
    return p


class VerifierCatalog:
    """The host's registry of capabilities, keyed ``id@version``. Packs bind to it; they do not extend it."""

    def __init__(self, capabilities: tuple[Capability, ...] = HOST_CAPABILITIES) -> None:
        self._by_ref: dict[str, Capability] = {}
        for capability in capabilities:
            self.register(capability)

    def register(self, capability: Capability) -> None:
        if not CAPABILITY_REF.fullmatch(capability.reference):
            raise VerifierError(f"capability reference {capability.reference!r} is malformed")
        if capability.reference in self._by_ref:
            raise VerifierError(f"capability {capability.reference} is already registered")
        self._by_ref[capability.reference] = capability

    def references(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_ref))

    def get(self, reference: str) -> Capability:
        capability = self._by_ref.get(reference)
        if capability is None:
            raise VerifierError(f"capability {reference!r} is not qualified on this host (known: {list(self.references())})")
        return capability

    def bind(self, check_id: str, spec: Mapping[str, Any]) -> BoundCheck:
        reference = str(spec.get("capability", ""))
        if not CAPABILITY_REF.fullmatch(reference):
            raise VerifierError(f"check {check_id!r}: capability must be id@version, got {reference!r}")
        capability = self.get(reference)
        params = spec.get("params") or {}
        problems = validate_params(capability, params)
        if problems:
            raise VerifierError(f"check {check_id!r}: " + "; ".join(problems))
        return BoundCheck(check_id, reference, str(spec.get("version", "")), dict(params), capability.build(params),
                          capability.qualification)


HOST_CATALOG = VerifierCatalog()


def verifier_profile(checks: Mapping[str, Any]) -> dict[str, Any]:
    """The deterministic and custom check declarations only: what the receipt pins as the verifier profile."""
    return {str(k): dict(v) for k, v in checks.items() if isinstance(v, Mapping) and v.get("kind") in ("deterministic", "custom")}


def verifier_profile_digest(checks: Mapping[str, Any]) -> str:
    encoded = json.dumps(verifier_profile(checks), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = ["CAPABILITY_REF", "HOST_CAPABILITIES", "HOST_CATALOG", "BoundCheck", "Capability", "Check", "CheckResult",
           "Param", "VerifierCatalog", "VerifierError", "validate_params", "verifier_profile", "verifier_profile_digest"]
