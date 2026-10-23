"""Append-only HTTP attempt identities in the standing PostgreSQL substrate."""

from __future__ import annotations

from typing import Any

from psycopg import sql

from factory.governed_http import HttpAttempt
from regulated_core.choke_points import EGRESS_OPERATION
from regulated_core.persistence_pg import _tenant

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
 tenant TEXT NOT NULL, delivery_key TEXT NOT NULL CHECK (delivery_key ~ '^[0-9a-f]{{64}}$'),
 endpoint_id TEXT NOT NULL, endpoint_digest TEXT NOT NULL,
 request_digest TEXT NOT NULL, payload_digest TEXT NOT NULL, nonce TEXT NOT NULL,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY (tenant, delivery_key), UNIQUE (tenant, nonce)
);
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS http_attempt_tenant_v1 ON {table};
CREATE POLICY http_attempt_tenant_v1 ON {table}
 USING (tenant=current_setting('app.tenant',true))
 WITH CHECK (tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS http_attempt_immutable_v1 ON {table};
CREATE TRIGGER http_attempt_immutable_v1 BEFORE UPDATE OR DELETE ON {table}
 FOR EACH ROW EXECUTE FUNCTION {immutable}();
DROP TRIGGER IF EXISTS http_attempt_no_truncate_v1 ON {table};
CREATE TRIGGER http_attempt_no_truncate_v1 BEFORE TRUNCATE ON {table}
 FOR EACH STATEMENT EXECUTE FUNCTION {immutable}();
"""


def migrate_http_attempts(pool: Any, *, receivers: tuple[str, ...] = ()) -> None:
    """Install the table; optionally grant its existing declared receivers SELECT/INSERT."""
    with pool.connection() as conn, conn.transaction():
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("regulated-http-attempts-v1",)
        )
        schema = conn.execute("SELECT current_schema()").fetchone()[0]
        if not isinstance(schema, str) or not schema:
            raise ValueError("HTTP attempt migration requires an owning schema")
        conn.execute(
            sql.SQL(_SCHEMA).format(
                table=sql.Identifier(schema, "regulated_http_attempts_v1"),
                immutable=sql.Identifier(schema, "regulated_authority_no_mutation_v1"),
            )
        )
        if receivers:
            declared = {
                row[0]
                for row in conn.execute(
                    sql.SQL("SELECT role_name FROM {} WHERE kind='consume'").format(
                        sql.Identifier(schema, "regulated_budget_writer_roles_v1")
                    )
                ).fetchall()
            }
            if not set(receivers).issubset(declared):
                raise ValueError("HTTP grants require existing declared receiver logins")
            for role in sorted(set(receivers)):
                conn.execute(
                    sql.SQL("GRANT SELECT, INSERT ON {} TO {}").format(
                        sql.Identifier(schema, "regulated_http_attempts_v1"), sql.Identifier(role)
                    )
                )


class PostgresHttpAttempts:
    """Retain one send attempt only when its prepared governance event matches."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def record(self, attempt: HttpAttempt) -> bool:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, attempt.tenant_id)
            result = conn.execute(
                "INSERT INTO regulated_http_attempts_v1 "
                "(tenant,delivery_key,endpoint_id,endpoint_digest,request_digest,payload_digest,nonce) "
                "SELECT %s,%s,%s,%s,%s,%s,%s WHERE EXISTS ("
                "SELECT 1 FROM regulated_governance_events_v1 WHERE tenant=%s AND nonce=%s "
                "AND phase='prepared' AND body::jsonb->>'subject'=%s AND body::jsonb->>'prior_state'=%s "
                "AND body::jsonb->>'change_digest'=%s AND body::jsonb->>'operation'=%s) "
                "ON CONFLICT DO NOTHING RETURNING delivery_key",
                (
                    attempt.tenant_id,
                    attempt.key,
                    attempt.endpoint_id,
                    attempt.endpoint_digest,
                    attempt.request_digest,
                    attempt.payload_digest,
                    attempt.nonce,
                    attempt.tenant_id,
                    attempt.nonce,
                    attempt.endpoint_id,
                    attempt.endpoint_digest,
                    attempt.request_digest,
                    EGRESS_OPERATION,
                ),
            )
            return result.fetchone() is not None

    def get(self, tenant_id: str, key: str) -> HttpAttempt | None:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            row = conn.execute(
                "SELECT tenant,delivery_key,endpoint_id,endpoint_digest,request_digest,payload_digest,nonce "
                "FROM regulated_http_attempts_v1 WHERE tenant=%s AND delivery_key=%s",
                (tenant_id, key),
            ).fetchone()
        return None if row is None else HttpAttempt(*row)
