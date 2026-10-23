"""Transaction-scoped revocation locks for database-owned effects.

These locks order PostgreSQL effects with tenant and ancestor revocation.
They do not fence filesystem writes or remote requests after connection loss.
The receiver must separately authenticate the permit, its complete grant chain,
and retained authorization evidence before relying on this primitive.
"""
from __future__ import annotations

from typing import Any

from .canonical import canonical_bytes
from .permit import EmissionError


def grant_revocation_key(tenant_id: str, grant_digest: str) -> str:
    """Return the shared lock identity used by grant revokers and receivers."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise EmissionError("a revocation fence requires a tenant")
    if (
        not isinstance(grant_digest, str)
        or len(grant_digest) != 64
        or any(character not in "0123456789abcdef" for character in grant_digest)
    ):
        raise EmissionError("a revocation fence requires a canonical grant digest")
    return canonical_bytes(["delegation-revocation", tenant_id, grant_digest]).decode("utf-8")


def lock_current_authority(
    connection: Any,
    *,
    tenant_id: str,
    expected_epoch: int,
    grant_digests: tuple[str, ...] = (),
) -> None:
    """Lock and check revocation in the effect's existing transaction.

    The caller supplies every ancestor of an independently authenticated chain.
    Lock order is tenant, then sorted grant keys, before target and mission locks.
    Locks remain held until the caller commits or rolls back this transaction.

    READ COMMITTED is required: a snapshot taken before waiting for a revoker
    must not conceal its committed revocation. A refusal must abort the caller's
    effect transaction. This function neither opens a connection nor retries.
    """
    from psycopg.pq import TransactionStatus

    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise EmissionError("authority fencing requires an active transaction")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise EmissionError("authority fencing requires a tenant")
    if type(expected_epoch) is not int or expected_epoch < 0:
        raise EmissionError("authority fencing requires a nonnegative epoch")
    if not isinstance(grant_digests, tuple):
        raise EmissionError("authority fencing requires a tuple of grant digests")
    keys = sorted(grant_revocation_key(tenant_id, digest) for digest in grant_digests)
    if len(set(keys)) != len(keys):
        raise EmissionError("authority fencing requires distinct grant digests")
    isolation, scoped_tenant = connection.execute(
        "SELECT current_setting('transaction_isolation'), current_setting('app.tenant', true)"
    ).fetchone()
    if isolation != "read committed":
        raise EmissionError("authority fencing requires READ COMMITTED isolation")
    if scoped_tenant != tenant_id:
        raise EmissionError("authority fence tenant differs from the transaction tenant")
    connection.execute(
        "SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
        ("regulated-revocation:" + tenant_id,),
    )
    for key in keys:
        connection.execute(
            "SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))", (key,)
        )
    epoch = connection.execute(
        "SELECT COALESCE(MAX(epoch), 0) FROM regulated_revocation_events_v1 WHERE tenant = %s",
        (tenant_id,),
    ).fetchone()[0]
    if int(epoch) != expected_epoch:
        raise EmissionError("permit revoked in durable tenant authority state")
    if grant_digests:
        revoked = connection.execute(
            "SELECT grant_digest FROM regulated_delegation_revocations_v1"
            " WHERE tenant = %s AND grant_digest = ANY(%s)",
            (tenant_id, list(grant_digests)),
        ).fetchall()
        if revoked:
            raise EmissionError("permit revoked in durable delegated authority state")

def database_target_key(tenant_id: str, target_digest: str) -> str:
    """Return the target lock identity shared by effects and reconciliation."""
    if not tenant_id or len(target_digest) != 64 or any(c not in "0123456789abcdef" for c in target_digest):
        raise EmissionError("invalid database target identity")
    return canonical_bytes(["regulated-database-target", tenant_id, target_digest]).decode("utf-8")


def lock_database_target(connection: Any, *, tenant_id: str, target_digest: str) -> None:
    """Serialize one target inside the caller's READ COMMITTED transaction.

    Effect callers acquire authenticated authority fences before this lock and
    mission locks afterwards. Reconciliation takes only this target lock.
    """
    from psycopg.pq import TransactionStatus

    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise EmissionError("target locking requires an active transaction")
    isolation, tenant = connection.execute(
        "SELECT current_setting('transaction_isolation'),current_setting('app.tenant',true)"
    ).fetchone()
    if isolation != "read committed" or tenant != tenant_id:
        raise EmissionError("target transaction scope mismatch")
    connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                       (database_target_key(tenant_id, target_digest),))
