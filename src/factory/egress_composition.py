"""The installation's egress admission, composed once and handed to every covered outbound path (architecture 14).

Nothing here is on by default. FACTORY_EGRESS_ADMISSION unset, empty or "off" composes nothing and every path behaves
exactly as before; "enforce" composes the Postgres scope store, a signed refusal sink over the installation's shared
regulated recorder, the tenant-agnostic admission, and the per-tenant views the call sites use; any other value refuses
startup, so a mistyped setting can never silently leave enforcement off (review 3382).

Composing it does not inventory anyone. A tenant without a recorded inventory reads Unknown and every covered send for
it refuses until the explicit inventory command has run for that tenant: that is the fail-closed intent of enforce.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from factory.governed_http import HttpEndpoint, RequestPort
    from regulated_core.governance_targets import GovernanceTarget
    from regulated_core.target import TargetAuthority

from regulated_core.egress_admission import (EgressAdmission, EgressScopeStore, RecorderRefusals, TenantBoundAdmission,
                                             evidence_refusal_sink, project_enrollment)

EGRESS_SETTING = "FACTORY_EGRESS_ADMISSION"
ENFORCE = "enforce"


def egress_enforced(env: Mapping[str, str]) -> bool:
    """True for "enforce", False for unset, empty or "off"; any other value is a configuration error."""
    value = env.get(EGRESS_SETTING, "").strip()
    if value in ("", "off"):
        return False
    if value == ENFORCE:
        return True
    raise ValueError(f"{EGRESS_SETTING} must be unset, 'off' or '{ENFORCE}'")


@dataclass(frozen=True)
class EgressComposition:
    """The installation's one egress admission: its scope store and the views each covered path needs."""

    store: EgressScopeStore
    admission: EgressAdmission

    def for_tenant(self, tenant: str) -> TenantBoundAdmission:
        """The admission a per-tenant path holds: it refuses any request naming another tenant."""
        return TenantBoundAdmission(self.admission, tenant)

    def project_enrollment(self, tenant: str) -> Callable[[str, str], None]:
        """The ProjectEngine regulated_scope port for a tenant's regulated verticals."""
        return project_enrollment(self.store, tenant)


def compose_egress(env: Mapping[str, str], *, store: EgressScopeStore, recorder: Any,
                   clock_us: Callable[[], int]) -> EgressComposition | None:
    """The installation's composition under enforce, else None. The store and the recorder are the host's own
    durable ones; refusals are signed onto that recorder under the egress admission's policy reference."""
    if not egress_enforced(env):
        return None
    sink = evidence_refusal_sink(RecorderRefusals(recorder), clock_us=clock_us)
    return EgressComposition(store=store, admission=EgressAdmission(store=store, refusal_sink=sink))


__all__ = ["EGRESS_SETTING", "ENFORCE", "EgressComposition", "compose_egress", "egress_enforced", "compose_http_delivery_target"]


def compose_http_delivery_target(endpoint: "HttpEndpoint", *, pool: Any,
                                 authority: "TargetAuthority",
                                 request: "RequestPort | None" = None) -> "GovernanceTarget":
    """Compose a receipt-capable host destination with durable authority stores.

    The host supplies an explicitly registered endpoint and its target authority.
    Schema installation and grants are separate deployment steps. This factory
    does not activate a route or substitute for the caller's approval workflow.
    """
    from factory.governed_http import HttpEgressTransport, public_http_request
    from factory.governed_http_pg import PostgresHttpAttempts
    from regulated_core.choke_points import egress_target
    from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresPermitUseStore

    log = PostgresGovernanceLog(pool=pool)
    transport = HttpEgressTransport(endpoint, PostgresHttpAttempts(log),
                                    request if request is not None else public_http_request)
    return egress_target(transport, endpoint.endpoint_id, tenant_id=endpoint.tenant_id,
                         authority=authority, uses=PostgresPermitUseStore(pool=pool),
                         log=log, max_bytes=endpoint.max_payload_bytes)
