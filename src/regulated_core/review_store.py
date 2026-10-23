"""Durable, serialized human-review snapshots in the host's existing Postgres.

Snapshots contain signed decision evidence, approval grants and certificates;
the approval service verifies those authorities on every read. The store adds
atomic versioning and tenant scope, not a new source of signing authority.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

from .canonical import canonical_bytes, digest_hex
from .persistence_pg import PersistenceError, _tenant

Mutation = Callable[[dict[str, Any] | None], dict[str, Any]]
TimedMutation = Callable[[dict[str, Any] | None, int], dict[str, Any]]


class ReviewStore(Protocol):
    """One tenant/request transaction prevents lost or duplicate human grants."""

    durable: bool
    def get(self, tenant: str, review_id: str) -> dict[str, Any] | None: ...
    def transact(self, tenant: str, review_id: str, mutation: Mutation) -> dict[str, Any]: ...


class PostgresReviewStore:
    """Append-only request versions; construction performs no migration or I/O."""

    durable = True

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    @staticmethod
    def _payload(row: Any) -> dict[str, Any]:
        value = json.loads(row[2]) if isinstance(row[2], (str, bytes)) else row[2]
        if not isinstance(value, dict) or digest_hex(value) != row[1]:
            raise PersistenceError("stored regulated review failed integrity")
        return value

    @staticmethod
    def _latest(conn: Any, tenant: str, review_id: str) -> Any:
        if not isinstance(review_id, str) or not review_id.strip():
            raise PersistenceError("explicit review ID required")
        return conn.execute(
            "SELECT version, payload_digest, payload FROM regulated_reviews_v1"
            " WHERE tenant = %s AND review_id = %s ORDER BY version DESC LIMIT 1", (tenant, review_id),
        ).fetchone()

    @classmethod
    def read_locked_on(cls, conn: Any, tenant: str, review_id: str) -> dict[str, Any] | None:
        """Hold a shared review lock through the caller's scoped transaction.

        Customer authority locks, when needed, must be acquired first, matching
        review writers that authenticate the caller before appending a version.
        The caller must reread and verify this snapshot after acquiring the lock.
        """
        from psycopg.pq import TransactionStatus

        if conn.info.transaction_status != TransactionStatus.INTRANS:
            raise PersistenceError("locked review read requires an active transaction")
        scope, isolation = conn.execute(
            "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
        ).fetchone()
        if scope != tenant or isolation != "read committed":
            raise PersistenceError("locked review read requires matching READ COMMITTED tenant")
        if not isinstance(review_id, str) or not review_id.strip():
            raise PersistenceError("explicit review ID required")
        conn.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
                     ("regulated-review-v1:" + digest_hex([tenant, review_id]),))
        row = cls._latest(conn, tenant, review_id)
        return cls._payload(row) if row is not None else None

    def get(self, tenant: str, review_id: str) -> dict[str, Any] | None:
        """Read only the supplied tenant's latest review snapshot."""
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant)
            row = self._latest(conn, tenant, review_id)
        return self._payload(row) if row is not None else None

    def transact(self, tenant: str, review_id: str, mutation: Mutation) -> dict[str, Any]:
        """Apply one validated service mutation under a request-scoped lock."""
        return self.transact_timed(tenant, review_id, lambda state, now_us: mutation(state))

    def transact_timed(self, tenant: str, review_id: str, mutation: TimedMutation) -> dict[str, Any]:
        """Supply database time after the exclusive review lock is held.

        Issue external credentials before entering this transaction. A mutation
        must not borrow another connection for clock or credential queries.
        If a writer needs customer authority locks, it must take them before
        this review lock, matching the receiving transaction's lock order.
        """
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         ("regulated-review-v1:" + digest_hex([tenant, review_id]),))
            row = self._latest(conn, tenant, review_id)
            now_us = int(conn.execute(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
            ).fetchone()[0])
            result = mutation(self._payload(row) if row is not None else None, now_us)
            fingerprint = digest_hex(result)
            if row is not None and fingerprint == row[1]:
                return result
            version = int(row[0]) + 1 if row is not None else 0
            conn.execute(
                "INSERT INTO regulated_reviews_v1 (tenant, review_id, version, payload_digest, payload)"
                " VALUES (%s, %s, %s, %s, %s::jsonb)",
                (tenant, review_id, version, fingerprint, canonical_bytes(result).decode("utf-8")),
            )
        return result
