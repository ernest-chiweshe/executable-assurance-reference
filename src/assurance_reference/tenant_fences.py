"""Tenant-isolated governance fences for tenant-scoped governed effects (B-F7b).

The recovered governance log records each attempt's open/closed fence in ``regulated_governance_fences_v1``, an
installation-wide table with no tenant column, so a tenant-scoped scope such as an egress endpoint or an epoch
withdrawal would place its tenant's attempt rows where every installation duty can read them. This reference log
keeps the fences of one tenant's scopes in ``reference_tenant_fences_v1`` instead: forced row-level security admits a
row only when ``tenant = app.tenant``, rows are append-only, and every read and write sets the bound tenant first.
Installation scopes (pack lifecycle, governance roster) keep the recovered table unchanged.

The governance events themselves were already tenant-scoped (``regulated_governance_events_v1``). Only the fence
location changes; the lock, event and receipt protocol of the recovered log is unchanged.
"""
from __future__ import annotations

from typing import Any

from psycopg import sql

from regulated_core.canonical import canonical_bytes
from regulated_core.governance_targets import COMMITTED, NOT_COMMITTED, PREPARED, attempt_key, event_body
from regulated_core.persistence_pg import PersistenceError, PostgresGovernanceLog, _tenant

TABLE = "reference_tenant_fences_v1"


def migrate_tenant_fences(owner: Any, *, writers: tuple[str, ...] = ()) -> None:
    """Fresh schema only: the tenant fence table, forced RLS, append-only, and SELECT/INSERT for named writers."""
    with owner.connection() as conn, conn.transaction():
        name = sql.Identifier(TABLE)
        conn.execute(sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} (tenant TEXT NOT NULL CHECK (length(tenant) > 0),"
            " scope TEXT NOT NULL CHECK (length(scope) > 0), attempt TEXT NOT NULL CHECK (length(attempt) = 64),"
            " phase TEXT NOT NULL CHECK (phase IN ('open', 'closed')),"
            " recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant, attempt, phase))")
            .format(name))
        conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("DROP POLICY IF EXISTS tenant_fence_scope ON {}").format(name))
        conn.execute(sql.SQL("CREATE POLICY tenant_fence_scope ON {} USING (tenant = current_setting('app.tenant', true))"
                             " WITH CHECK (tenant = current_setting('app.tenant', true))").format(name))
        conn.execute(sql.SQL("DROP TRIGGER IF EXISTS tenant_fence_immutable ON {}").format(name))
        conn.execute(sql.SQL("CREATE TRIGGER tenant_fence_immutable BEFORE UPDATE OR DELETE ON {} FOR EACH ROW "
                             "EXECUTE FUNCTION regulated_authority_no_mutation_v1()").format(name))
        conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
        for role in writers:
            conn.execute(sql.SQL("GRANT SELECT, INSERT ON {} TO {}").format(name, sql.Identifier(role)))


class TenantFencedGovernanceLog(PostgresGovernanceLog):
    """The recovered governance log bound to one tenant, with that tenant's fences under forced RLS."""

    def __init__(self, *, pool: Any, tenant: str) -> None:
        if not isinstance(tenant, str) or not tenant or tenant != tenant.strip():
            raise ValueError("a tenant fence log is bound to one exact tenant")
        super().__init__(pool=pool)
        self.tenant = tenant

    def append(self, event: Any) -> str:
        if event.phase not in (PREPARED, COMMITTED, NOT_COMMITTED) or not event.scope:
            raise PersistenceError("a governance event needs a known phase and a scope")
        if event.tenant_id != self.tenant:
            raise PersistenceError("a tenant fence log records only its bound tenant's events")
        with self._session() as conn, conn.transaction():
            _tenant(conn, event.tenant_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         ("regulated-governance-log:" + event.tenant_id,))
            row = conn.execute("SELECT COALESCE(MAX(seq) + 1, 0) FROM regulated_governance_events_v1 WHERE tenant = %s",
                               (event.tenant_id,)).fetchone()
            conn.execute("INSERT INTO regulated_governance_events_v1 (tenant, seq, nonce, phase, scope, event_digest, body)"
                         " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                         (event.tenant_id, row[0], event.nonce, event.phase, event.scope, event.digest(),
                          canonical_bytes(event_body(event)).decode("utf-8")))
            conn.execute("INSERT INTO reference_tenant_fences_v1 (tenant, scope, attempt, phase) VALUES (%s, %s, %s, %s)"
                         " ON CONFLICT DO NOTHING",
                         (event.tenant_id, event.scope, attempt_key(event.tenant_id, event.nonce),
                          "open" if event.phase == PREPARED else "closed"))
        return self.root(event.tenant_id)

    def unresolved(self, scope: str) -> str | None:
        with self._session() as conn, conn.transaction():
            _tenant(conn, self.tenant)
            row = conn.execute("SELECT o.attempt FROM reference_tenant_fences_v1 o WHERE o.tenant = %s AND o.scope = %s"
                               " AND o.phase = 'open' AND NOT EXISTS (SELECT 1 FROM reference_tenant_fences_v1 c"
                               " WHERE c.tenant = o.tenant AND c.attempt = o.attempt AND c.phase = 'closed') LIMIT 1",
                               (self.tenant, scope)).fetchone()
        return None if row is None else str(row[0])


__all__ = ["TABLE", "TenantFencedGovernanceLog", "migrate_tenant_fences"]
