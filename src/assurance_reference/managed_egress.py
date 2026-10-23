"""Reference managed host with enforced egress admission (X-15 "egress enforced").

The pinned reference host composition (``compose_reference_host``) is retained
unchanged. This managed composer adds the installation's one egress admission
(the admission, refusal sink and composition types recovered unchanged from the
frozen ``factory/egress_composition.py``) over two dedicated least-privilege
logins, never the receiver and never migration credentials:

* ``egress_reader`` may only SELECT tenant scope history. The send-time
  admission reads and holds the tenant's scope lock through this login, so a
  covered send cannot itself enrol or inventory anything.
* ``egress_scope`` may SELECT and INSERT scope events only (the table is
  append-only and tenant-forced by row-level security). Explicit inventory and
  regulated-vertical enrolment write through this login.

Refusals are signed onto the host's shared regulated recorder under the egress
admission's policy reference. A managed host never runs unenforced: an unset or
"off" setting refuses composition, and any other value refuses as a
configuration error. Composition performs no I/O, inventories no tenant and
signs nothing. A tenant whose readable history is empty reads Unknown, so every
covered send for it refuses until its explicit inventory is recorded.

Outbound delivery (X-8, X-15 "egress enforced") goes through the managed host only: ``deliver`` admits the exact
request against the tenant's scope and, holding that scope lock, commits the permit through the budget-bound egress
delivery target (``assurance_reference.governed_egress``) built over this host's own engine, budget, permit-use
store, target authority and governance log. A send therefore needs both a scope admission and a governed permit.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.governed_egress import egress_delivery_target
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from factory.egress_composition import EGRESS_SETTING, ENFORCE, EgressComposition, egress_enforced
from regulated_core import IntendedUse, IntendedUseRegistry, PolicyRegistry
from regulated_core.choke_points import EGRESS_OPERATION
from regulated_core.egress_admission import EgressAdmission, EgressRequest, RecorderRefusals, evidence_refusal_sink
from regulated_core.persistence_pg import PostgresEgressScopeStore

# Logins an egress duty must never share: each holds unrelated authority.
_SEPARATE_FROM = ("receiver", "allocator", "recorder", "governor", "delegation_issuer")


@dataclass(frozen=True)
class ReferenceManagedHost:
    """The composed reference host and the egress admission every covered outbound path must use."""

    runtime: Any
    egress: EgressComposition
    attempts_pool: Any
    governance_pool: Any

    def egress_engine(self, policy: Any) -> Any:
        """The host engine's sibling for outbound sends under an explicit host egress policy; every other authority
        (recorder, approvals, emission, targets, budget, clock) is this host's own."""
        registry = PolicyRegistry()
        registry.register(policy)
        uses = IntendedUseRegistry()
        uses.declare(IntendedUse("egress", EGRESS_OPERATION, 2))
        base = self.runtime.factory.engine
        return base.for_policy(registry=registry, preflight=base._preflight.for_uses(uses))

    def delivery_target(self, endpoint: Any, *, request: Any, engine: Any) -> Any:
        """The budget-bound egress delivery target over this host's engine and stores."""
        log = TenantFencedGovernanceLog(pool=self.governance_pool, tenant=endpoint.tenant_id)
        return egress_delivery_target(endpoint, pool=self.attempts_pool, request=request, budget=engine._budget,
                                      authority=engine.targets, uses=engine._emission.uses, log=log)

    def deliver(self, engine: Any, authorization: Any, output: bytes, target: Any, *, subject: str,
                purpose: str) -> Any:
        """Admit the exact send against the tenant's scope, then commit the permit while the scope lock is held."""
        request = EgressRequest(target.tenant_id, subject, purpose, target._subject, sha256(output).hexdigest(),
                                len(output))
        admission = self.egress.for_tenant(target.tenant_id)
        admitted = admission.admit(request)
        return admission.send(admitted, request, lambda: engine.commit(authorization, output, target))


def _egress_logins(roles: Any) -> tuple[Any, Any]:
    reader, writer = getattr(roles, "egress_reader", None), getattr(roles, "egress_scope", None)
    if reader is None or writer is None:
        raise ValueError("reference managed host requires explicit egress_reader and egress_scope logins")
    names = (getattr(reader, "role", None), getattr(writer, "role", None))
    if not all(isinstance(name, str) and name for name in names) or names[0] == names[1]:
        raise ValueError("egress reader and scope writer logins must be distinct")
    others = {getattr(getattr(roles, kind, None), "role", None) for kind in _SEPARATE_FROM} - {None}
    if set(names) & others:
        raise ValueError("egress logins must be separate from receiver, allocator, recorder, governor"
                         " and delegation issuer")
    return reader, writer


def compose_reference_managed_host(stores, authorities, *, roles: Any, env: Mapping[str, str],
                                   **host: Any) -> ReferenceManagedHost:
    """Compose the reference host with enforced egress, or refuse before any service is returned."""
    if not egress_enforced(env):
        raise ValueError(f"reference managed host requires {EGRESS_SETTING}={ENFORCE}")
    reader, writer = _egress_logins(roles)
    runtime = compose_reference_host(stores, authorities, **host)
    sink = evidence_refusal_sink(RecorderRefusals(stores.recorder), clock_us=authorities.clock.now_us)
    admission = EgressAdmission(store=PostgresEgressScopeStore(pool=reader), refusal_sink=sink)
    egress = EgressComposition(store=PostgresEgressScopeStore(pool=writer), admission=admission)
    return ReferenceManagedHost(runtime, egress, attempts_pool=roles.receiver, governance_pool=roles.governor)


__all__ = ["ReferenceManagedHost", "compose_reference_managed_host"]
