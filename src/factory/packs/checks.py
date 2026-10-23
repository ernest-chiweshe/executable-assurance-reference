"""Conformance cases for the pack's checks, and the one bounded exception where a pack ships code.

A pack declares its deterministic checks as host capabilities with parameters (``verifiers``) and
ships CASES for each: ``conformance/golden/<check>.json`` (the behaviour the domain expert signed
off), ``conformance/boundary/`` (known edges, including honest over-blocks) and
``conformance/adversarial/`` (inputs written to slip past the check). Installation binds every
check and runs every case; a check with no golden case or a failing case refuses the pack, because
a check that does not behave as its own cases say is not a check (OPA ships tests with policies;
FHIR ships examples with profiles; 1EdTech certifies against a conformance suite).

``load_custom_module`` is the exception the research allows and bounds: a custom executable
verifier is a separately listed file that the HOST must explicitly allow, whose imports stay inside
a standard-library allowance, loaded only after the pack signature verified it. It is off by
default. Sandboxing beyond the import allowance is not implemented in this starter; that is stated
as a gap, not assumed away.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from regulated_core.models import Outcome

from .verifiers import Check

CATEGORIES = ("golden", "boundary", "adversarial")
_STDLIB_ONLY = ("re", "json", "math", "decimal", "datetime", "typing", "dataclasses", "collections", "hashlib",
                "string", "unicodedata", "fractions", "statistics", "itertools", "functools")


class CheckError(ValueError):
    """A case file, a case, or a custom verifier module is invalid; the message names it."""


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    category: str
    draft: str
    contract: Mapping[str, Any]
    expected: Outcome
    expected_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CaseFailure:
    check_id: str
    case: str
    category: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return f"{self.check_id}/{self.category}/{self.case}: expected {self.expected}, got {self.actual}"


@dataclass(frozen=True, slots=True)
class CaseReport:
    check_id: str
    passed: int
    by_category: Mapping[str, int] = field(default_factory=dict)
    failures: tuple[CaseFailure, ...] = ()

    @property
    def ok(self) -> bool:
        """No failure, and at least one golden case: boundary and adversarial cases never substitute for it."""
        return not self.failures and self.by_category.get("golden", 0) > 0

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check_id, "passed": self.passed, "by_category": dict(self.by_category),
                "failures": [str(f) for f in self.failures]}


def case_path(pack_dir: Path, category: str, check_id: str) -> Path:
    return pack_dir / "conformance" / category / f"{check_id.replace(':', '.')}.json"


def load_cases(pack_dir: Path, check_id: str) -> tuple[Case, ...]:
    cases: list[Case] = []
    for category in CATEGORIES:
        path = case_path(pack_dir, category, check_id)
        if not path.is_file():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("cases", ()):
            try:
                expected = Outcome(str(entry["expected"]))
            except (KeyError, ValueError) as exc:
                raise CheckError(f"{path.name}: case {entry.get('name')!r} needs expected pass|fail|indeterminate") from exc
            cases.append(Case(str(entry["name"]), category, str(entry.get("draft", "")), dict(entry.get("contract") or {}),
                              expected, tuple(str(r) for r in entry.get("expected_reasons", ()))))
    return tuple(cases)


def run_cases(check_id: str, check: Check, cases: tuple[Case, ...]) -> CaseReport:
    failures: list[CaseFailure] = []
    counts: dict[str, int] = {}
    for case in cases:
        counts[case.category] = counts.get(case.category, 0) + 1
        try:
            outcome, reasons = check(case.draft, case.contract)
        except Exception as exc:  # noqa: BLE001 - a raising check is a failing check, named
            failures.append(CaseFailure(check_id, case.name, case.category, case.expected.value,
                                        f"raised {type(exc).__name__}: {exc}"))
            continue
        actual = Outcome(outcome) if isinstance(outcome, str) else outcome
        if actual is not case.expected:
            failures.append(CaseFailure(check_id, case.name, case.category, case.expected.value, actual.value))
        elif case.expected_reasons and tuple(reasons) != case.expected_reasons:
            failures.append(CaseFailure(check_id, case.name, case.category, f"reasons {list(case.expected_reasons)}",
                                        f"reasons {list(reasons)}"))
    return CaseReport(check_id, len(cases) - len(failures), counts, tuple(failures))


def module_imports(source: str) -> tuple[str, ...]:
    """The top-level modules a file imports (so a custom verifier can be refused for platform imports)."""
    names: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module.split(".")[0])
    return tuple(sorted(set(names)))


def foreign_imports(source: str) -> tuple[str, ...]:
    return tuple(name for name in module_imports(source) if name not in _STDLIB_ONLY)


def load_custom_module(pack_dir: Path, relative: str, *, verified: bool, allowed: bool) -> dict[str, Check]:
    """Load a pack's custom verifier module and return its ``CHECKS`` mapping. Three refusals precede the
    import: the host has not allowed custom verifiers; the pack signature was not verified; the module
    imports outside the standard-library allowance."""
    if not allowed:
        raise CheckError("custom executable verifiers are not allowed on this host; declare a host capability instead")
    if not verified:
        raise CheckError("refusing to load a custom verifier from a pack whose signature has not been verified")
    if not relative.startswith("verifiers/") or not relative.endswith(".py") or ".." in relative:
        raise CheckError("a custom verifier module must live under verifiers/ in the pack")
    path = pack_dir / relative
    if not path.is_file():
        raise CheckError(f"{relative} is missing")
    source = path.read_text(encoding="utf-8")
    foreign = foreign_imports(source)
    if foreign:
        raise CheckError(f"{relative} imports outside the standard-library allowance: {list(foreign)}")
    name = f"_pack_verifier_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CheckError(f"{relative} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        sys.modules.pop(name, None)
        raise CheckError(f"{relative} failed to import: {exc}") from exc
    checks = getattr(module, "CHECKS", None)
    if not isinstance(checks, dict) or not checks or any(not callable(v) for v in checks.values()):
        raise CheckError(f"{relative} must define CHECKS: a non-empty mapping of check id to callable")
    return {str(k): v for k, v in checks.items()}


__all__ = ["CATEGORIES", "Case", "CaseFailure", "CaseReport", "CheckError", "case_path", "foreign_imports",
           "load_cases", "load_custom_module", "module_imports", "run_cases"]
