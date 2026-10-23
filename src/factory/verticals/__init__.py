"""Verticals: a product name resolves to the profile that governs its runs.

A vertical is not new machinery; it is data on the fixed factory (recipe, profile,
golden tasks, optional policy). This module is the lookup the driving surfaces (CLI,
API) use to turn a `--product NAME` into the right `ProjectProfile`, the one carrying
that product's capabilities, budget, and gate-check set. Known products come from the
recipe book; an unknown name falls back to a code product with the full deterministic
gate, because an unrecognized request should face the STRICTER bar, not the looser one.

research-desk is the first vertical built bulletproof; its golden tasks and Rego live
under `verticals/research_desk/`.
"""
from __future__ import annotations

from dataclasses import replace

from factory.profile import ProjectProfile
from factory.recipes import default_recipe_book

# The general, all-purpose floor for an ad-hoc task: screen the output for injection
# and leaked secrets, and rank quality, but veto NOTHING on shape, because a raw task
# may be prose, a plan, an analysis, or notes, not code. This is the right default for
# `factory run "..."`: safe (the guardrail still vetoes a real leak), but it does not
# judge a brief by the rules for shippable code.
GENERAL_CHECKS = frozenset({"input-guardrail", "grounded-critic"})

# The strict stack a CODE product declares (vertical-saas carries its own copy). Kept
# named so the intent is documented; it is opted INTO, never the surprise default.
DEFAULT_CODE_CHECKS = frozenset(
    {"policy", "input-guardrail", "types", "lint", "cve", "container-sandbox", "grounded-critic"}
)


def profile_for(product: str, max_cost_usd: float | None = None) -> ProjectProfile:
    """The `ProjectProfile` that governs runs for `product`.

    A known product (a recipe name) carries its own capabilities, budget, and
    gate-check set. An unknown or ad-hoc product (including the bare `default` that a
    raw `factory run` uses) gets the GENERAL floor: guardrail + critic, no code checks,
    so a prose task ships on its merits. Code work opts into the strict gate by naming
    a product that declares it (vertical-saas). `max_cost_usd`, when given, overrides
    the product's budget; the governor still enforces the tenant cap.
    """
    book = default_recipe_book()
    if product in book.names():
        profile = book.get(product).profile
    else:
        profile = ProjectProfile(product, gate_checks=GENERAL_CHECKS)
    if max_cost_usd is not None:
        profile = replace(profile, max_cost_usd=max_cost_usd)
    return profile
