"""Opt-in observation for isolated qualification, never a runtime authority gate.

Proxies forward operations and exceptions unchanged. Counts describe returned
rows, not PostgreSQL's internal rows scanned; query plans remain separate evidence.
SQL text, parameters, credentials and record bodies are never recorded.
"""
from collections import Counter
from contextlib import contextmanager
import re
from threading import Lock
from unittest.mock import patch


TABLE = re.compile(
    r"\b(?:regulated|reference|collaboration)_[a-z0-9_]+\b", re.I)


class WorkCounts:
    def __init__(self):
        self._counts = Counter()
        self._lock = Lock()
        self._enabled = False

    def add(self, name, amount=1):
        with self._lock:
            if self._enabled:
                self._counts[name] += amount

    @contextmanager
    def measuring(self):
        with self._lock:
            if self._enabled:
                raise RuntimeError("nested work-count measurement is ambiguous")
            self._counts.clear()
            self._enabled = True
        try:
            yield self
        finally:
            with self._lock:
                self._enabled = False

    def snapshot(self):
        with self._lock:
            return dict(sorted(self._counts.items()))

    @contextmanager
    def observe(self, owner, method, label, amount=None):
        """Count entry to a method while always invoking the original method.

        Use only in an isolated process with no unrelated users of the object.
        This hook does not remove, skip or substitute any security check.
        """
        original = getattr(owner, method)

        def observed(*args, **kwargs):
            self.add(label, 1 if amount is None else amount(*args, **kwargs))
            return original(*args, **kwargs)

        with patch.object(owner, method, observed):
            yield


class CursorObservation:
    def __init__(self, cursor, counts, query=""):
        self._cursor, self._counts = cursor, counts
        self._tables = self._names(query)

    @staticmethod
    def _names(query):
        if isinstance(query, bytes):
            query = query.decode("utf-8", errors="replace")
        return tuple(sorted(set(TABLE.findall(query)))) if isinstance(query, str) else ()

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def execute(self, query, *args, **kwargs):
        self._tables = self._names(query)
        self._counts.add("sql_statements")
        self._cursor.execute(query, *args, **kwargs)
        return self

    def executemany(self, query, parameters, *args, **kwargs):
        # Do not consume or copy the caller's parameter iterator for counting.
        self._counts.add("sql_executemany_calls")
        self._tables = self._names(query)
        return self._cursor.executemany(query, parameters, *args, **kwargs)

    def _returned(self, count):
        self._counts.add("rows_returned", count)
        for table in self._tables:
            self._counts.add("rows_returned_referencing:" + table.lower(), count)

    def fetchone(self):
        row = self._cursor.fetchone()
        self._returned(0 if row is None else 1)
        return row

    def fetchmany(self, *args, **kwargs):
        rows = self._cursor.fetchmany(*args, **kwargs)
        self._returned(len(rows))
        return rows

    def fetchall(self):
        rows = self._cursor.fetchall()
        self._returned(len(rows))
        return rows

    def __iter__(self):
        for row in self._cursor:
            self._returned(1)
            yield row

    def __enter__(self):
        self._cursor.__enter__()
        return self

    def __exit__(self, *args):
        return self._cursor.__exit__(*args)


class ConnectionObservation:
    def __init__(self, connection, counts):
        self._connection, self._counts = connection, counts

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def execute(self, query, *args, **kwargs):
        self._counts.add("sql_statements")
        cursor = self._connection.execute(query, *args, **kwargs)
        return CursorObservation(cursor, self._counts, query)

    def cursor(self, *args, **kwargs):
        return CursorObservation(self._connection.cursor(*args, **kwargs), self._counts)

    def transaction(self, *args, **kwargs):
        self._counts.add("transaction_scopes")
        return self._connection.transaction(*args, **kwargs)


class PoolObservation:
    def __init__(self, pool, counts):
        self._pool, self._counts = pool, counts

    def __getattr__(self, name):
        return getattr(self._pool, name)

    @contextmanager
    def connection(self, *args, **kwargs):
        self._counts.add("pool_checkouts")
        with self._pool.connection(*args, **kwargs) as connection:
            yield ConnectionObservation(connection, self._counts)
