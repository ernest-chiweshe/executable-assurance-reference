"""B-F7b tenant-scoped governance fences on actual restricted logins; isolated PostgreSQL, fictional tenants.

Two tenants each deliver once through the managed host's governed egress, so each tenant's egress scope records its
open and closed attempt fences. Every runtime login that may read the tenant fence table, set to one tenant, sees that
tenant's populated fence rows and none of the other's; the installation-wide fence table holds no egress scope at all.
The egress and epoch-withdrawal factories refuse a shared or another tenant's governance log, so a tenant-scoped scope
cannot fall back to the installation table. The database administrator is excluded from the threat model.
"""
import uuid

import pytest
from psycopg import sql

from assurance_reference.governed_egress import egress_delivery_target
from assurance_reference.role_contract import ROLES, expected_privileges
from assurance_reference.tenant_fences import TABLE, TenantFencedGovernanceLog
from factory.governed_http import HttpEndpoint
from regulated_core.persistence_pg import PostgresGovernanceLog
from regulated_core.target import Outcome
from test_x15_managed_delivery_pg import _send, managed  # noqa: F401
from test_x8_governed_egress_pg import SyntheticDestination


def _fence_rows(pool, table, tenant):
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        return conn.execute(sql.SQL("SELECT tenant, scope FROM {}").format(sql.Identifier(table))).fetchall()


def test_each_tenants_fences_are_visible_only_to_that_tenant(managed):  # noqa: F811
    roles, host = managed
    tenants = ["synthetic-fence-" + uuid.uuid4().hex[:8] for _ in range(2)]
    for tenant in tenants:
        engine, destination, target, authorized, output = _send(roles, host, tenant, scope="unregulated")
        result = host.deliver(engine, authorized, output, target, subject="publisher", purpose="publish:bulletin")
        assert result.outcome is Outcome.COMMITTED, result
    readers = [kind for kind in ROLES if "SELECT" in expected_privileges(kind, TABLE)]
    assert readers  # The governance log login reads its own fences.
    for kind in readers:
        pool = getattr(roles, kind)
        for own, other in (tenants, tenants[::-1]):
            rows = _fence_rows(pool, TABLE, own)
            assert rows and {row[0] for row in rows} == {own}, (kind, rows)  # Populated, own tenant only.
            assert all(other not in row[1] for row in rows)
    # The installation-wide table holds installation scopes only: no tenant's egress scope reached it.
    with roles.governor.connection() as conn, conn.transaction():
        shared = conn.execute("SELECT scope FROM regulated_governance_fences_v1 WHERE scope LIKE 'egress:%'").fetchall()
    assert shared == []


def test_tenant_scoped_factories_refuse_a_shared_or_foreign_log(managed):  # noqa: F811
    roles, host = managed
    destination = SyntheticDestination("https://destination.example.org")
    endpoint = HttpEndpoint(tenant_id="synthetic-fence-owner", endpoint_id="synthetic-publication",
                            delivery_url=destination.origin + "/deliver", receipt_url=destination.origin + "/receipts")
    engine = host.runtime.factory.engine
    common = dict(pool=roles.receiver, request=destination, budget=engine._budget, authority=engine.targets,
                  uses=engine._emission.uses)
    for log in (PostgresGovernanceLog(pool=roles.governor),
                TenantFencedGovernanceLog(pool=roles.governor, tenant="synthetic-other-tenant")):
        with pytest.raises(TypeError, match="fenced governance log"):
            egress_delivery_target(endpoint, log=log, **common)
