"""Tenant-scoped governance roster storage (B-F7b, candidate 060).

The recovered roster store keeps each installation's roster chain in ``regulated_governance_rosters_v1``. Its signed
authority verifier already accepts a chain only when every row belongs to the one configured authority tenant, so a
chain is one tenant's authority record; the table nevertheless had no row-level security, and the governance login
could read every tenant's roster rows. Here the table gets forced row-level security on ``tenant = app.tenant`` and
the recovered store is given a pool that binds its configured authority tenant on every connection it takes. The
installation-wide ``(installation, version)`` key is unchanged: it is the chain head, so another tenant can neither
start nor extend an installation's chain. The recovered store, its lock, verification and receipt protocol are unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from regulated_core.persistence_pg import PostgresRosterStore

TABLE = "regulated_governance_rosters_v1"


def migrate_roster_tenancy(owner: Any) -> None:
    """After the recovered schema: forced row-level security on the roster table by authority tenant."""
    with owner.connection() as conn, conn.transaction():
        conn.execute("ALTER TABLE regulated_governance_rosters_v1 ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE regulated_governance_rosters_v1 FORCE ROW LEVEL SECURITY")
        conn.execute("DROP POLICY IF EXISTS regulated_roster_tenant_v1 ON regulated_governance_rosters_v1")
        conn.execute("CREATE POLICY regulated_roster_tenant_v1 ON regulated_governance_rosters_v1"
                     " USING (tenant = current_setting('app.tenant', true))"
                     " WITH CHECK (tenant = current_setting('app.tenant', true))")


class TenantScopedPool:
    """Bind one exact tenant on every connection taken from ``pool``, restoring the prior value when it is returned."""

    def __init__(self, pool: Any, tenant: str) -> None:
        if not isinstance(tenant, str) or not tenant or tenant != tenant.strip():
            raise ValueError("a tenant-scoped pool is bound to one exact tenant")
        self._pool, self.tenant = pool, tenant

    @contextmanager
    def connection(self) -> Iterator[Any]:
        with self._pool.connection() as conn:
            prior = conn.execute("SELECT current_setting('app.tenant', true)").fetchone()[0]
            conn.execute("SELECT set_config('app.tenant', %s, false)", (self.tenant,))
            try:
                yield conn
            finally:
                if not conn.closed:
                    conn.execute("SELECT set_config('app.tenant', %s, false)", (prior or "",))


def tenant_roster_store(pool: Any, *, proof_verifier: Any, guard: Any = None) -> PostgresRosterStore:
    """The recovered roster store, reading and writing only its configured authority tenant's rows."""
    tenant = getattr(proof_verifier, "tenant", None)
    return PostgresRosterStore(pool=TenantScopedPool(pool, tenant), guard=guard, proof_verifier=proof_verifier)
