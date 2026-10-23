"""The acceptance gate, your bar, and the thing the providers will not build for you.

A gate decides whether a *candidate* (what a harness produced) is good enough to
ship. One rule governs everything in this package: the TRUTH HIERARCHY.

  STRONGEST  deterministic facts, it compiles, types check, policy passes, tests
             pass in a clean sandbox. Same input, same verdict, no opinion.
  WEAKER     heuristic signals, lint, complexity. Mostly mechanical.
  WEAKEST    an LLM's opinion that the output is "good." Non-deterministic, and
             produced by the same kind of system that wrote the output in the
             first place. Correlated with quality; not evidence of it.

So checks run DETERMINISTIC-FIRST, and that ordering does double duty. It's the
CHEAPEST order, don't pay a model to review code that won't compile, and it's
the AUTHORITY order, a deterministic veto can never be overturned by an opinion.
Cost and truth happen to point the same way.

Two kinds of check, and the distinction is the entire design:
  • DETERMINISTIC checks can VETO. One failure rejects the candidate, full stop.
  • ADVISORY checks (the grounded critic, Module 16) can only annotate and rank.
    They never reject what the deterministic checks passed, and never rescue what
    they failed. The meta-LLM is a ranker, never an arbiter.

Module 12 ships the contract and the ordering. Modules 13 to 16 plug in the concrete
checks: policy (OPA), static + sandbox, input guardrails, and the grounded critic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from factory.harness import RunResult
from factory.profile import ProjectProfile
from factory.tenant import TenantContext


def extract_json(text: str) -> Any:
    """Parse a JSON object an agent produced, tolerating how LLMs actually emit it.

    A model asked for "only JSON" still often wraps it in a ```json fence or a sentence
    of preamble. A gate that demands byte-pure JSON would reject good work for a cosmetic
    reason, so we (1) strip a surrounding code fence, (2) try a direct parse, and (3) fall
    back to the outermost {...} or [...] span. Raises ValueError if no JSON is found, which
    every JSON gate already treats as a fail-closed reject."""
    s = text.strip()
    if s.startswith("```"):
        newline = s.find("\n")
        s = s[newline + 1:] if newline != -1 else s[3:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
        s = s.strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = s.find(opener), s.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(s[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError("no JSON object found in the output")


@dataclass(frozen=True, slots=True)
class Candidate:
    """What the gate judges: a harness's output, where its artifacts live, and the
    request context the run was made under."""

    result: RunResult
    workspace: str = ""  # path to the produced code; deterministic checks read it
    context: dict[str, str] = field(default_factory=dict)
    """The request parameters (e.g. a recipe's count, platform, length). A
    deterministic check can read these to judge output against what was ASKED for,
    not just generic shape: "exactly {count} posts, each within {platform}'s limit".
    Empty for a raw task with no recipe."""


class CheckKind(str, Enum):
    """Whether a check may veto (deterministic) or only rank (advisory). The
    gate's power hierarchy is enforced through this type."""
    DETERMINISTIC = "deterministic"  # may veto
    ADVISORY = "advisory"            # may only annotate / rank


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One check's verdict: passed or not, its kind, a human detail, and an
    optional advisory score."""
    name: str
    passed: bool
    kind: CheckKind
    detail: str = ""
    score: float | None = None  # advisory checks may attach a rank score in [0, 1]


@runtime_checkable
class Check(Protocol):
    """One judgement. Deterministic checks veto; advisory checks only rank."""

    name: str
    kind: CheckKind

    def run(
        self, candidate: Candidate, profile: ProjectProfile, tenant: TenantContext
    ) -> CheckResult: ...


@dataclass(frozen=True, slots=True)
class GateResult:
    """The gate's overall verdict: accepted or not, every check's result, and
    the reason for a rejection."""
    accepted: bool
    results: tuple[CheckResult, ...]
    reason: str = ""

    @property
    def vetoed_by(self) -> tuple[str, ...]:
        return tuple(
            r.name for r in self.results if r.kind is CheckKind.DETERMINISTIC and not r.passed
        )


class Gate:
    """Runs deterministic checks first (a failure is a hard veto), then advisory."""

    def __init__(self, checks: list[Check]) -> None:
        # Fail fast on a duplicate check name. A name is an identifier (profile.applies() selects by it,
        # GateResult.vetoed_by reports it), so two checks sharing one is always a composition bug: both run,
        # double-charging cost and latency, with no way to address them apart. This is the structural guard
        # for the class of drift that put GroundedCritic in the gate twice; the composition root cannot
        # silently register the same check twice again.
        names = [c.name for c in checks]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(
                f"duplicate gate check name(s): {', '.join(duplicates)}. Each check name must be unique; "
                "a repeated name means the same check is wired twice (the GroundedCritic-double-registration bug)."
            )
        self._checks: tuple[Check, ...] = tuple(checks)
        self._deterministic = [c for c in checks if c.kind is CheckKind.DETERMINISTIC]
        self._advisory = [c for c in checks if c.kind is CheckKind.ADVISORY]

    @property
    def check_names(self) -> tuple[str, ...]:
        """Every wired check's name, in registration order (deterministic and advisory alike). The stable
        view a drift test asserts uniqueness over, and the input to the gate composition fingerprint that a
        run record captures (so 'what bar accepted this output?' is answerable)."""
        return tuple(c.name for c in self._checks)

    def fingerprint(self) -> str:
        """A stable hash of this gate's composition: each check's NAME and implementing CLASS, in EVALUATION
        order (every deterministic check, then every advisory one, the order the gate actually runs them).
        Recorded on each run so an audit can tell whether two runs were judged by the same bar and detect
        when the gate changed: renaming a check, swapping its implementing class, or reordering the
        deterministic checks (which changes veto precedence) all change the hash. What it does NOT yet fold
        in: per-check thresholds/config (checks do not expose them uniformly). The run record also carries
        policy_hash and profile_version separately, so the policy input and the product's declared subset of
        this gate are captured alongside this composition hash."""
        import hashlib
        ordered = list(self._deterministic) + list(self._advisory)   # the real evaluation order
        manifest = ";".join(f"{c.name}:{type(c).__name__}" for c in ordered)
        return hashlib.sha256(manifest.encode("utf-8")).hexdigest()[:16]

    def evaluate(
        self, candidate: Candidate, profile: ProjectProfile, tenant: TenantContext
    ) -> GateResult:
        results: list[CheckResult] = []

        # Truth + cost first: any deterministic failure rejects immediately, and
        # we never reach the (expensive, weak) advisory checks for a reject. A check
        # the product did not declare is skipped (profile.applies), so one global
        # gate serves every vertical: a prose product runs prose checks, a code
        # product runs code checks, and neither is failed by the other's rules.
        for check in self._deterministic:
            if not profile.applies(check.name):
                continue
            outcome = check.run(candidate, profile, tenant)
            results.append(outcome)
            if not outcome.passed:
                return GateResult(
                    accepted=False,
                    results=tuple(results),
                    reason=f"vetoed by {outcome.name}: {outcome.detail}",
                )

        # All deterministic checks passed. Advisory checks may annotate and rank,
        # but cannot reject what the facts already accepted.
        for check in self._advisory:
            if not profile.applies(check.name):
                continue
            results.append(check.run(candidate, profile, tenant))

        return GateResult(
            accepted=True, results=tuple(results), reason="all deterministic checks passed"
        )
