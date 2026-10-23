"""Tenant identity, threaded through every factory operation from commit one.

In Phase 1 there is exactly one tenant: SELF. You never special-case it away,
because the day a paying customer arrives, multi-tenancy must become a new *value*
flowing through parameters that already exist, not a rewrite of every call site.
This is seam one of the no-refactor contract: thread the context now, while it
costs nothing, so it costs nothing later either.

Module 10 deepens the context. The principle is "design for the endgame, implement
for today": the fields a multi-tenant factory needs, a per-tenant budget, a
provider allow-list, exist on the object NOW, so every call already carries them.
In Phase 1 they're simply unset on SELF (no budget, everything allowed). Turning
them on later sets values; it changes no signatures, because the parameter is
already everywhere it needs to be.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Who a unit of work belongs to, and the limits that travel with them.

    Immutable; passed, never mutated. Every field after the identity is an
    endgame field: harmless on SELF today, load-bearing for a real customer later.
    """

    tenant_id: str
    display_name: str
    # --- endgame fields (Module 10): unset on SELF, consumed by later modules ---
    max_cost_usd: float | None = None
    """Per-tenant spend cap for one run. None = use the factory default. Read by
    the cost governor (Module 19)."""
    allowed_providers: frozenset[str] | None = None
    """Provider names this tenant may use. None = no restriction. Honored by
    selection (Module 08 registry) and project profiles (Module 11)."""

    @classmethod
    def self_tenant(cls) -> "TenantContext":
        """The single Phase-1 tenant.

        This is the one place that changes when you go multi-tenant: instead of a
        hardcoded self, a tenant arrives from a request. Every caller already
        accepts a TenantContext, so nothing downstream has to change.
        """
        return cls(tenant_id="self", display_name="Self")

    def permits(self, provider: str) -> bool:
        """Whether this tenant is allowed to use `provider`. Open by default."""
        return self.allowed_providers is None or provider in self.allowed_providers

    def budget_or(self, default: float) -> float:
        """This tenant's per-run budget, falling back to the factory default."""
        return self.max_cost_usd if self.max_cost_usd is not None else default


# Phase-1 convenience singleton. Import and thread this through calls;
# never inline the string "self" at a call site.
SELF = TenantContext.self_tenant()


@dataclass(frozen=True, slots=True)
class TenantPolicy:
    """What a tenant may DO, beyond the budget and provider limits carried on its TenantContext: the
    recipes it may run (None = all allowed), its role, and its abuse-control limits (requests per minute,
    runs per day; None = use the platform default). Kept here, next to TenantContext, so any surface (the
    MCP server, the Postgres directory) can name it without pulling in a heavy optional dependency."""

    allowed_recipes: frozenset[str] | None = None
    role: str = "user"
    rate_per_min: int | None = None
    runs_per_day: int | None = None
    # Code execution (the coding vertical / studio / review) runs the project's tests and builds and an
    # agent on the host. Until that runs in a per-tenant container, it is PRIVILEGED: off by default, so an
    # untrusted tenant cannot make the host execute code. Grant it only to tenants you trust to run code.
    can_execute_code: bool = False
    # Shipping (ship_project: docker build/push, compose up, terraform apply) has a far larger blast radius
    # than running gated code: it mutates infrastructure, a host runtime, or a registry. It is a SEPARATE,
    # stronger grant, deliberately NOT implied by can_execute_code, so a tenant trusted to run a code review
    # is not thereby trusted to deploy. Off by default; grant only to tenants you trust to deploy.
    can_ship_project: bool = False
