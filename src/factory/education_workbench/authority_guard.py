"""Serialize enrollment/appointment changes with credentialed grant and emission.

Uses the already composed bounded Postgres session; no extra pool or outer
transaction. The lock namespace is common to ordinary enrollment and appointments.
"""
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from hashlib import sha256
import json

from factory.packs.collections import InMemoryPackCollectionStore, PackCollectionStore, PostgresPackCollectionStore
from factory.pg_session import SessionBoundPool


@contextmanager
def authority_guard(store: PackCollectionStore, tenant: str, class_id: str,
                    principals: Sequence[str], *, exclusive: bool = False) -> Iterator[None]:
    if isinstance(store, InMemoryPackCollectionStore):
        with store._lock:
            yield
        return
    if not isinstance(store, PostgresPackCollectionStore) or not isinstance(store._pool, SessionBoundPool):
        raise ValueError("education authority needs the composed bounded Postgres session")
    keys = sorted({int.from_bytes(sha256(json.dumps(
        ["education-authority/v1", tenant, class_id, principal], separators=(",", ":")).encode()).digest()[:8],
        byteorder="big", signed=True) for principal in principals})
    suffix = "" if exclusive else "_shared"
    with store._pool.reuse_or_open_session() as conn:
        held: list[int] = []
        try:
            for key in keys:
                try:
                    conn.execute(f"SELECT pg_advisory_lock{suffix}(%s)", (key,))
                    held.append(key)
                except BaseException:
                    conn.close()  # Acquisition may have succeeded before a lost reply.
                    raise
            yield
        finally:
            if not conn.closed:
                for key in reversed(held):
                    try:
                        if conn.execute(f"SELECT pg_advisory_unlock{suffix}(%s)", (key,)).fetchone()[0] is not True:
                            raise RuntimeError("education authority lock release was not confirmed")
                    except BaseException:
                        conn.close()
                        raise
