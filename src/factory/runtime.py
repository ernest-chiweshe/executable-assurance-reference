"""factory/runtime.py — per-run ambient context that reaches the driver without changing the seam.

The harness seam is `run(task, tenant)`; it deliberately carries no workspace, because almost every run
uses the factory's configured default. The coding vertical is the exception: it runs in a freshly cloned
repo, and the driver's cwd must be THAT directory for this run only.

Rather than widen the seam (and touch every driver and call site), a ContextVar carries the per-run
workspace ambiently: `Factory.run` sets it, the coding drivers read it. It is async- and thread-safe, a
ContextVar is isolated per task and `asyncio.run` copies the current context into the new loop, so the
value reaches an async driver too.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from factory.tenant import TenantContext
from factory.harness import HarnessInfo


class AuthorizedLaneChanged(ValueError):
    """Execution no longer names the tenant, lane, model and billing that were admitted."""


_authorized_lane: ContextVar[tuple[str, str, str, str] | None] = ContextVar(
    "factory_authorized_lane", default=None
)


@contextmanager
def enforce_authorized_lane(*, tenant_id: str, lane: str, model: str,
                            billing_label: str) -> Iterator[None]:
    """Bind all Factory calls in this scope; a nested scope cannot replace the admitted identity."""
    expected = (tenant_id, lane, model, billing_label)
    existing = _authorized_lane.get()
    if existing is not None and existing != expected:
        raise AuthorizedLaneChanged("A nested run cannot change the approved execution lane.")
    token = _authorized_lane.set(expected)
    try:
        yield
    finally:
        _authorized_lane.reset(token)


def require_authorized_lane(info: HarnessInfo, tenant: TenantContext) -> None:
    """Check the actual selected adapter before admission or any provider execution."""
    expected = _authorized_lane.get()
    if expected is None:
        return
    label = (info.advisory.billing if info.advisory is not None else "") or info.billing
    if expected != (tenant.tenant_id, info.name, info.default_model, label):
        raise AuthorizedLaneChanged(
            "The selected tenant, lane, model or billing mode differs from the approved work. "
            "No provider call was made; review the current connection and approve again."
        )

# The workspace the current run must execute in, or None to use the driver's configured default.
active_workspace: ContextVar[str | None] = ContextVar("factory_active_workspace", default=None)


def resolve_cwd(default: str) -> str:
    """The cwd a driver should use: the per-run workspace when one is active, else the configured default.
    Coding drivers call this in place of reading the config workspace directly."""
    return active_workspace.get() or default


# The per-run cost ceiling (USD) the governor approved for THIS run, or None when none is active. A driver that
# can self-limit (the Agent SDK's max_budget_usd) reads it so the PROVIDER halts a runaway mid-flight at the same
# per-tenant ceiling the governor reconciles against afterwards. Ambient like the workspace, so the seam stays
# run(task, tenant), and thread/async-safe for the same ContextVar reason.
active_run_budget: ContextVar[float | None] = ContextVar("factory_active_run_budget", default=None)

# A caller-authorized ceiling can only tighten the product and tenant limits.
# Customer one-shot approvals and standing authorities set this around the real
# ProjectSurface call; Factory.run intersects it immediately before execution.
authorized_run_budget: ContextVar[float | None] = ContextVar(
    "factory_authorized_run_budget", default=None
)
authorized_budget_audit: ContextVar[dict[str, Any] | None] = ContextVar(
    "factory_authorized_budget_audit", default=None
)
active_tenant: ContextVar[TenantContext | None] = ContextVar(
    "factory_active_tenant", default=None
)


def resolve_budget() -> float | None:
    """The per-run provider budget a self-limiting driver should apply, or None when the core set none."""
    return active_run_budget.get()


@contextmanager
def enforce_authorized_budget(
    ceiling_usd: float, *, maximum_calls: int
) -> Iterator[dict[str, Any]]:
    """Apply one aggregate caller-approved budget and call bound.

    A stage may internally invoke ``Factory.run`` more than once.  The mutable
    audit is shared by those calls so each sees only the remaining authorization,
    rather than accidentally receiving the full per-stage ceiling again.
    """
    ceiling = float(ceiling_usd)
    if ceiling < 0 or maximum_calls < 1:
        raise ValueError("authorized run ceiling must be non-negative")
    current = authorized_run_budget.get()
    effective = ceiling if current is None else min(current, ceiling)
    existing_audit = authorized_budget_audit.get()
    audit = existing_audit or {
        "ceiling_usd": effective,
        "spent_usd": 0.0,
        "maximum_calls": int(maximum_calls),
        "admitted_calls": 0,
        "provider_failures": [],
        "ceiling_breached": False,
        "run_breached": False,
        # Calls whose cost the harness could not observe (``raw["cost_observed"] is False``). ``spent_usd`` stays
        # the OBSERVED subtotal; one unobserved call stops every further call under this authority (ledger 4127).
        "unobserved_cost_calls": 0,
    }
    audit["ceiling_usd"] = min(float(audit["ceiling_usd"]), effective)
    audit["maximum_calls"] = min(int(audit["maximum_calls"]), int(maximum_calls))
    budget_token = authorized_run_budget.set(effective)
    audit_token = authorized_budget_audit.set(audit)
    try:
        yield audit
    finally:
        authorized_budget_audit.reset(audit_token)
        authorized_run_budget.reset(budget_token)


def audit_cost(audit: Mapping[str, Any]) -> float | None:
    """The cost one authorized budget spent, or None when any of its calls' cost was not observed (ledger 4141).

    ``spent_usd`` is only the OBSERVED subtotal once a call reported ``cost_observed: False``; presenting it as the
    whole would read an unpriced run as cheaper than it was. Every reader of an audit's cost goes through here."""
    if int(audit.get("unobserved_cost_calls", 0)) > 0:
        return None
    return float(audit["spent_usd"])


def resolve_tenant(default: TenantContext) -> TenantContext:
    """The authenticated per-request tenant, or the legacy/default operator."""
    return active_tenant.get() or default


@contextmanager
def customer_tenant(tenant: TenantContext) -> Iterator[None]:
    """Bind a customer workspace tenant through vertical engines and ledgers."""
    token = active_tenant.set(tenant)
    try:
        yield
    finally:
        active_tenant.reset(token)


# --- live agent events ---
# The same ambient pattern carries a per-run EVENT SINK to the driver: when a surface (the CLI, a cockpit)
# wants to watch the agent work, it sets a callback here; the agent drivers emit their stream to it as it
# arrives. None means nobody is listening, so emitting is a cheap no-op and the seam is unchanged.
EventSink = Callable[[dict[str, Any]], None]
active_event_sink: ContextVar["EventSink | None"] = ContextVar("factory_active_event_sink", default=None)


def emit_event(event: dict[str, Any]) -> None:
    """A driver calls this for each agent event it observes (a message, a tool use, a file edit). It is a
    no-op when no surface is listening, so drivers can always emit without a branch. A misbehaving sink must
    never break the run, so its errors are swallowed."""
    sink = active_event_sink.get()
    if sink is None:
        return
    try:
        sink(event)
    except Exception:  # noqa: BLE001 - a broken display sink must not take down the agent run
        pass


@contextmanager
def capture_events(sink: EventSink) -> Iterator[None]:
    """Install an event sink for the duration of the block, so any agent run inside it streams its events to
    `sink`. The CLI wraps a coding run in this to print the agent's steps live."""
    token = active_event_sink.set(sink)
    try:
        yield
    finally:
        active_event_sink.reset(token)
