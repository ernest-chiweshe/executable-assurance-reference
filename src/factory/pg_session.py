"""Explicit synchronous session scope over an existing bounded Postgres pool.

Compose ONE adapter into every store used inside the scope. It holds one physical
connection, not one outer transaction: each store's transaction commits before
the next operation. Ordinary shared-pool users retain their existing semantics.
This is not an async context and must never span an await or change threads.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class SessionBoundPool:
    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._local = threading.local()

    @staticmethod
    def _idle(conn: Any) -> None:
        from psycopg.pq import TransactionStatus

        if conn.info.transaction_status != TransactionStatus.IDLE:
            raise RuntimeError("session-bound operation requires an independent transaction")

    @contextmanager
    def session(self) -> Iterator[Any]:
        if getattr(self._local, "connection", None) is not None:
            raise RuntimeError("nested session scopes are not supported")
        with self._pool.connection() as conn:
            self._idle(conn)
            if not conn.autocommit:
                raise RuntimeError("session-bound pool requires autocommit connections")
            self._local.connection = conn
            try:
                yield conn
                self._idle(conn)
            finally:
                del self._local.connection

    @contextmanager
    def reuse_or_open_session(self) -> Iterator[Any]:
        """Join an existing synchronous host scope, or own one for a standalone operation.

        Unlike session(), this is explicitly a participant when already bound;
        it never clears the owning scope and still requires transaction-idle entry.
        """
        conn = getattr(self._local, "connection", None)
        if conn is not None:
            self._idle(conn)
            yield conn
            self._idle(conn)
        else:
            with self.session() as owned:
                yield owned

    @contextmanager
    def connection(self) -> Iterator[Any]:
        conn = getattr(self._local, "connection", None)
        if conn is None:
            with self._pool.connection() as borrowed:
                yield borrowed
            return
        self._idle(conn)
        try:
            yield conn
            self._idle(conn)
        except BaseException:
            # Never leave an aborted or implicit transaction in the session.
            # Completed store transactions remain durable across this rollback.
            conn.rollback()
            raise
