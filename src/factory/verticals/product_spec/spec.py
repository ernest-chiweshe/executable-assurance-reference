"""The Product Spec vertical, declared as a `VerticalSpec` over the Project OS engine. INTERNAL builder tool.

A four-stage artifact pipeline that grounds a spec in a problem: problem (who hurts, the pain, why now) ->
solution (the wedge, the value, the differentiation) -> scope (the smallest shippable MVP, must-haves vs
later) -> spec (the PRD that ties it together). Each stage reads the last (the spec reads all three), so the
document is grounded in a stated problem instead of features in a vacuum. Assemble bundles a `product-spec/1.0`
artifact and the readiness gate refuses a spec that is too thin to build from.

Boundary: this is the vertical's own seam-wiring, not the engine. It imports no renderer (the exporter is
injected, Project OS T1) and authors no acceptance (the model verdict is copied from `Factory.run`; assemble's
from the readiness check). The prose gets the house-style de-tell so the PRD reads clean.
"""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from factory.house_style import normalize_prose
from factory.profile import ProjectProfile
from factory.projectos import (
    AXIS_ARTIFACT,
    KIND_ASSEMBLE,
    KIND_MODEL,
    Binding,
    StageOutcome,
    StageRun,
    StageSpec,
    VerticalSpec,
)
from factory.projectos.spec import Runner

# The artifact gate floor: screen for injection/leaked secrets and rank quality. The readiness gate at assemble
# enforces the spec-specific bar (a buildable spec, not a paragraph).
_STAGE_PROFILE = ProjectProfile("product-spec", gate_checks=frozenset({"input-guardrail", "grounded-critic"}))

# A spec worth building from carries at least this many words.
_MIN_SPEC_WORDS = 80

_PROMPTS = {
    "problem": """Frame the PROBLEM for this product idea. Who specifically hurts, what is the pain in their
own terms, the job they are trying to get done, what they do today and why it falls short, and why solving this
matters NOW. Be concrete about the user; avoid a generic market.

Title: {title}
Idea:
{idea}
""",
    "solution": """Define the SOLUTION for this problem. State the core approach in one sentence, the wedge
(the sharp first use case that gets a foot in the door), the value the user gets, and what makes it different
from what they do today. Honest about the one thing it must do well.

Problem:
{problem}
""",
    "scope": """Define the MVP SCOPE. List the must-have capabilities for a first shippable version (the
smallest thing that delivers the value), then what is explicitly deferred to later, and the one risk most
likely to sink it. Ruthless: cut anything not needed to prove the wedge.

Problem:
{problem}
Solution:
{solution}
""",
    "spec": """Write the PRODUCT SPEC (a PRD) that ties this together. Sections: Overview, Target user, Problem,
Solution and value, MVP scope (in and out), Key requirements, Success metrics, and Risks. Tight and concrete,
written so an engineer (or the factory) could build from it.

Problem:
{problem}
Solution:
{solution}
MVP scope:
{scope}
""",
}


def product_spec_spec() -> VerticalSpec:
    """The product-spec pipeline: problem -> solution -> scope -> spec, each chained from the last."""
    return VerticalSpec(
        name="product-spec",
        axis=AXIS_ARTIFACT,
        state_dir="product-spec",
        id_field="spec_id",
        stages=(
            StageSpec("problem", "Frame the problem", kind=KIND_MODEL, inputs=(
                Binding("title", "field:title"), Binding("idea", "field:idea"))),
            StageSpec("solution", "Define the solution", kind=KIND_MODEL, inputs=(
                Binding("problem", "stage:problem"),)),
            StageSpec("scope", "Scope the MVP", kind=KIND_MODEL, inputs=(
                Binding("problem", "stage:problem"), Binding("solution", "stage:solution"))),
            StageSpec("spec", "Write the PRD", kind=KIND_MODEL, inputs=(
                Binding("problem", "stage:problem"), Binding("solution", "stage:solution"),
                Binding("scope", "stage:scope"))),
        ),
    )


def build_product_spec_contract(state: dict[str, Any], approve: bool) -> dict[str, Any]:
    """The `product-spec/1.0` artifact: the problem, solution, MVP scope, and the PRD."""
    stages = state.get("stages", {})

    def _out(stage_id: str) -> str:
        rec = stages.get(stage_id)
        return str(rec["output"]) if rec and rec.get("accepted") else ""

    return {
        "format_version": "product-spec/1.0",
        "spec_id": state["spec_id"],
        "title": state.get("title", state["spec_id"]),
        "approved": bool(approve),
        "problem": _out("problem"),
        "solution": _out("solution"),
        "scope": _out("scope"),
        "spec": _out("spec"),
    }


def make_product_spec_runner(factory: Any) -> Runner:
    """The artifact model runner: each stage runs its prompt through the gated `Factory.run`; assemble runs the
    readiness check (a buildable spec). Every `accepted` is copied from the relevant authority."""

    def run(run: StageRun) -> StageOutcome:
        stage, params, tenant = run.stage, run.params, run.tenant
        if stage.kind == KIND_ASSEMBLE:
            contract = json.loads(params["contract"])
            ready, reason = _readiness(contract)
            return StageOutcome(output=params["contract"], accepted=ready, reason=reason)
        prompt = _PROMPTS[stage.id].format(**params)
        # Honor the operator's provider choice from the UI (options.harness); else let the factory pick.
        harness = str(run.options.get("harness") or "")
        profile = replace(_STAGE_PROFILE, pinned_harness=harness) if harness else _STAGE_PROFILE
        report = factory.run(prompt, profile, tenant, context=params)
        # Strip the machine-writing tells (em dashes, emojis) so the PRD reads clean.
        return StageOutcome(output=normalize_prose(report.output), accepted=bool(report.accepted),
                            reason=getattr(report, "gate_reason", ""), run_id=getattr(report, "run_id", ""),
                            extra={"cost_usd": float(getattr(report, "cost_usd", 0.0)),
                                   "harness": str(getattr(report, "harness_name", "") or harness or "auto")})

    return run


def _readiness(contract: dict[str, Any]) -> tuple[bool, str]:
    """A spec ships only if the PRD is substantive enough to build from. Deterministic, fail-closed: a stub
    spec is not buildable, and says so."""
    spec_words = len(str(contract.get("spec", "")).split())
    if spec_words < _MIN_SPEC_WORDS:
        return False, f"the spec is too thin to build from ({spec_words} words, need {_MIN_SPEC_WORDS})"
    return True, f"a {spec_words}-word PRD, ready to build from"
