"""Project profiles, a product's standards as data, not code.

The factory is the machine. A *profile* is a product line on that machine. When
you ship a second product, a different vertical, a different bar, a different
budget, you write a new `ProjectProfile`, not new factory code. That is the
difference between a tool you reuse and a tool you keep rewriting.

Keep the two axes separate, because they answer different questions:

  • A `ProjectProfile` says what the PRODUCT needs: which capabilities its tasks
    require, what it's allowed to spend, and what bar its output must clear
    (the policy, added in Module 13).

  • A `TenantContext` says what the CUSTOMER is limited to: their budget cap,
    the providers they're permitted to use.

A run is constrained by BOTH. The product asks for capability; the tenant may
forbid a provider; the budget is whichever of the two is tighter; the gate
applies the product's policy. The same runner code serves every product because
the profile, not the code, carries the differences.
"""
from __future__ import annotations

from dataclasses import dataclass

from factory.harness import Capability, HarnessAdapter
from factory.registry import HarnessRegistry
from factory.tenant import TenantContext


class NoEligibleHarnessError(RuntimeError):
    """No registered provider both meets the profile's needs and is permitted to
    the tenant."""


@dataclass(frozen=True, slots=True)
class ProjectProfile:
    """The data that makes one product different from another. Immutable."""

    name: str
    required_capabilities: frozenset[Capability] = frozenset()
    max_cost_usd: float = 5.0
    policy_path: str | None = None
    """Path to this product's Rego policy, the bar its output must clear, judged
    by the policy gate (Module 13). None = no policy gate for this product."""
    gate_checks: frozenset[str] | None = None
    """The gate checks that apply to THIS product, by name. A prose product
    (research-desk) declares only its prose checks; a code product declares the
    code checks. One global gate is wired in the composition root, and each product
    runs its declared subset, so a research brief is never failed by a code sandbox
    and a code product is never failed by a citation rule. None = run every wired
    check (backward compatible; used by ad-hoc and test profiles)."""

    pinned_harness: str | None = None
    """Force a specific registered provider by name while preserving capability checks.
    None keeps the default (pick by capability, never by name). A pin is an explicit
    operator choice, not permission to weaken the product contract: the selected lane
    must still meet every required capability and be permitted to the tenant."""

    version: str = "1"
    """The product bar's version. Recorded on every run (RunRecord.profile_version) so an audit can answer
    'which version of this product's standards accepted that output?'. A recipe stamps its own version here
    when it instantiates, so a recipe-driven run records the recipe's version. Bump it when the bar changes:
    a stricter gate set, a different budget, a new policy. Last field, with a default, so positional
    construction of the existing fields is unaffected."""

    def applies(self, check_name: str) -> bool:
        """Whether a wired gate check runs for this product. None = all checks (the
        legacy default); an explicit set is the product's declared bar."""
        return self.gate_checks is None or check_name in self.gate_checks

    def effective_budget(self, tenant: TenantContext) -> float:
        """The tighter of the product's budget and the tenant's cap.

        A product can't exceed its design budget; a tenant can't exceed their own
        limit. The smaller constraint always wins, constraints compose by
        intersection, never by whoever set the looser number.
        """
        return min(self.max_cost_usd, tenant.budget_or(self.max_cost_usd))

    def select(self, registry: HarnessRegistry, tenant: TenantContext) -> HarnessAdapter:
        """Pick a provider that meets the product's capabilities AND is permitted
        to this tenant. Identical code for every product; the profile decides.

        A `pinned_harness` selects that named provider when it is both tenant-permitted
        and qualified for every required capability. The operator owns the provider
        choice; the product's declared execution contract still fails closed.
        """
        if self.pinned_harness is not None:
            for adapter in registry.all():
                if adapter.info.name == self.pinned_harness:
                    if not tenant.permits(adapter.info.name):
                        raise NoEligibleHarnessError(
                            f"pinned harness '{self.pinned_harness}' is not permitted to tenant '{tenant.tenant_id}'."
                        )
                    if not adapter.supports(self.required_capabilities):
                        missing = sorted(
                            capability.value
                            for capability in self.required_capabilities
                            if capability not in adapter.info.capabilities
                        )
                        raise NoEligibleHarnessError(
                            f"pinned harness '{self.pinned_harness}' does not satisfy profile "
                            f"'{self.name}'; missing capabilities {missing}."
                        )
                    return adapter
            raise NoEligibleHarnessError(
                f"pinned harness '{self.pinned_harness}' is not registered; "
                f"have {sorted(a.info.name for a in registry.all())}."
            )

        for adapter in registry.all():
            if adapter.supports(self.required_capabilities) and tenant.permits(adapter.info.name):
                return adapter
        raise NoEligibleHarnessError(
            f"profile '{self.name}' needs {sorted(c.value for c in self.required_capabilities)}; "
            f"no provider satisfies that and is permitted to tenant '{tenant.tenant_id}'."
        )
