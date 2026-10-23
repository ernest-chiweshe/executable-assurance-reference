"""One way to open a Postgres connection pool, with a footprint the estate can afford.

Why this module exists (2026-08-23): each managed hub task opened 23-25 separate
``psycopg_pool.ConnectionPool`` instances -- one per store module, every one with
``min_size=1`` and ``open=True`` -- so a single process held ~25 idle connections from
the moment it started and could grow past 100. A blue/green canary runs two of every
service, and ``factory-managed-pg`` (db.t4g.micro, ~112 slots) refused 909 connections
in seven minutes. Three rollouts rolled back on that one cause.

The contract here:

* ``min_size`` is always 0. A pool opens with no connection and borrows one on first
  use; idle connections are returned to the server after ``max_idle`` seconds. The
  steady-state footprint of an idle process is therefore near zero instead of ~25.
* ``max_size`` is the caller's, bounded by ``FACTORY_PG_POOL_MAX_SIZE`` when set, so an
  operator can cap every pool in a process without touching 22 files.
* Every pool opened here is registered, so :func:`pool_footprint` can state -- as a
  number, not a guess -- how many connections this process can hold at most. The
  rollout headroom gate consumes that number.

``psycopg_pool.ConnectionPool`` is resolved at call time, on purpose: two composition
probes in the test suite replace that attribute with a fake, and the seam must honour
the replacement.

CONSOLIDATION (2026-09-02): pools are now SHARED BY DSN. Forty-three call sites each
opened their own pool over the one hub database, so the live footprint was the sum of
forty-three maxima (264) against a db.t4g.micro; the customer walkthrough drove RDS
from 14 to 64-70 connections and hit "remaining connection slots are reserved" on
three consecutive staging deployments, and a per-pool cap of 1 (the only cap the
static arithmetic admitted) turned every store into a serialised queue. Now
:func:`open_pool` keys on (conninfo, connection kwargs, max_idle): the first caller
creates the underlying pool, later callers receive a refcounted handle onto the SAME
pool, and a handle's ``close()`` releases its share rather than closing what others
hold. One hub database therefore holds a handful of pools (one per kwargs variant -
autocommit, row_factory) instead of forty-three, :func:`pool_footprint` reports the
LIVE truth (underlying pools, counted once), and the static inventory remains what it
always was: the upper bound of call sites, not the number of live pools.
"""
from __future__ import annotations

import logging
import os
import threading
import traceback
import weakref
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, cast

#: Idle connections are handed back to the server after this many seconds. psycopg's
#: default is 600; a canary bake is 10+10 minutes, so a shorter idle window is what lets
#: the OLD tasks' connections drain while the candidate is coming up.
DEFAULT_MAX_IDLE_SECONDS = 120.0

_REGISTRY: weakref.WeakSet[Any] = weakref.WeakSet()
_REGISTRY_LOCK = threading.Lock()


#: The managed estate's per-SHARED-pool cap when the operator set none. Why 3,
#: derived not chosen (tests/test_production_hub_pool_cap.py pins the arithmetic
#: against deploy/pool-inventory.json): the estate's RDS is a db.t4g.micro (~112
#: max_connections less reserved slots, usable 99) with a measured idle baseline
#: of 14; the inventory's 43 sites collapse to 6 connection shapes, i.e. 6 live
#: pools per process; during a rolling deploy FOUR processes hold pools (hub and
#: health, old task and new). 6 x 3 x 4 = 72, + 14 = 86 fits; cap 4 = 110 does
#: not. It lives HERE, not only in the hub entrypoint, because health runs
#: uvicorn on factory.health_ui.app and the migrate task runs its own module -
#: a default applied by one entrypoint bounded one of the four processes
#: (reviewer finding 2026-09-02). The explicit contract is
#: FACTORY_PG_POOL_MAX_SIZE in deploy/config/service-shared.env; this default is
#: the fail-safe for a task whose environment predates that line. An explicit
#: operator value always wins.
MANAGED_POOL_CAP = 3

#: Managed identity: the ECS agent sets these for every task container; local
#: estates never do. The same marker the fake-provider guard uses (reviewer-
#: accepted 2026-09-01), so "managed" means one thing across the codebase.
MANAGED_IDENTITY_MARKERS = ("ECS_CONTAINER_METADATA_URI_V4",
                            "ECS_CONTAINER_METADATA_URI", "AWS_EXECUTION_ENV")


def managed_identity(env: Mapping[str, str]) -> bool:
    """True when this process runs as a managed (ECS) task."""
    return any(env.get(name, "").strip() for name in MANAGED_IDENTITY_MARKERS)


def _pool_cap(env: Mapping[str, str]) -> int | None:
    """The operator's per-pool cap, or the managed default, or None.

    Non-positive or malformed values are refused rather than ignored.
    """
    raw = env.get("FACTORY_PG_POOL_MAX_SIZE", "").strip()
    if not raw:
        return MANAGED_POOL_CAP if managed_identity(env) else None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("FACTORY_PG_POOL_MAX_SIZE must be a positive integer") from exc
    if value < 1:
        raise ValueError("FACTORY_PG_POOL_MAX_SIZE must be a positive integer")
    return value


def open_pool(
    conninfo: str,
    *,
    max_size: int,
    autocommit: bool | None = None,
    name: str | None = None,
    max_idle: float = DEFAULT_MAX_IDLE_SECONDS,
    kwargs: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Any:
    """Open a registered pool with ``min_size=0``.

    ``autocommit`` is a convenience for the common ``kwargs={"autocommit": True}``;
    an explicit ``kwargs`` mapping wins when both are given and disagree, which is
    refused rather than silently resolved.
    """
    if max_size < 1:
        raise ValueError("max_size must be at least 1")
    environment = os.environ if env is None else env
    cap = _pool_cap(environment)
    bounded = max_size if cap is None else min(max_size, cap)
    connection_kwargs: dict[str, Any] = dict(kwargs or {})
    if autocommit is not None:
        existing = connection_kwargs.get("autocommit")
        if existing is not None and bool(existing) != autocommit:
            raise ValueError("autocommit and kwargs['autocommit'] disagree")
        connection_kwargs["autocommit"] = autocommit
    import psycopg_pool  # resolved late: tests substitute psycopg_pool.ConnectionPool

    key = _share_key(conninfo, connection_kwargs, max_idle)
    with _REGISTRY_LOCK:
        shared = _SHARED.get(key)
        if shared is not None and getattr(shared.pool, "closed", False):
            shared = None
        if shared is None:
            pool = psycopg_pool.ConnectionPool(
                conninfo,
                min_size=0,
                max_size=bounded,
                open=True,
                max_idle=max_idle,
                name=name,
                kwargs=connection_kwargs or None,
            )
            shared = _Shared(pool)
            _SHARED[key] = shared
            _REGISTRY.add(pool)
        elif bounded > int(getattr(shared.pool, "max_size", 0) or 0):
            # A later caller asked for more than the first: grow the shared pool
            # to the largest bounded request so no store is starved by whoever
            # happened to open first. psycopg_pool's contract is
            # resize(min_size, max_size=None) - min_size is REQUIRED, so it is
            # passed explicitly and stays 0 (reviewer note 2026-09-02).
            shared.pool.resize(min_size=0, max_size=bounded)
        shared.refs += 1
        return SharedPool(shared)


def _share_key(conninfo: str, kwargs: Mapping[str, Any], max_idle: float) -> tuple[Any, ...]:
    """Two callers share a pool only when every connection-shaping input agrees."""
    return (conninfo, tuple(sorted((k, repr(v)) for k, v in kwargs.items())), float(max_idle))


class _Shared:
    __slots__ = ("pool", "refs")

    def __init__(self, pool: Any) -> None:
        self.pool = pool
        self.refs = 0


class SharedPool:
    """A refcounted handle onto one underlying pool shared by every caller of its DSN.

    Everything a store does with a pool is forwarded (``connection()``,
    ``getconn``/``putconn``, ``submit``, ``open``, attributes). ``close()`` releases this
    handle's share; the underlying pool closes only when the last handle releases.
    Closing twice is idempotent.
    """

    def __init__(self, shared: _Shared) -> None:
        self._shared = shared
        self._released = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._shared.pool, name)

    # NESTED-BORROW DETECTION. Sharing turns forty-three independent pools into a
    # handful, so a store that borrows a second connection while still holding
    # one now borrows from the SAME bounded pool - under a small cap, enough
    # concurrent requests doing that deadlock until psycopg's pool timeout.
    # Per-site pools never had this class. Borrows are counted per thread per
    # underlying pool (stores are synchronous: a request's borrows stay on its
    # worker thread); a second concurrent borrow logs a WARNING naming the pool
    # and the caller, so the walkthrough log scan surfaces the path instead of
    # a bare PoolTimeout. Diagnostic, never a refusal.
    def _borrow(self) -> None:
        depths = _borrow_depths()
        key = id(self._shared)
        depths[key] = depth = depths.get(key, 0) + 1
        if depth > 1:
            # The frames outside this module and contextlib, innermost first: the
            # store that borrowed twice AND what called it, because the store's
            # own line ("product_store.py:109 __init__") names the mechanism, not
            # the route - channels-32 showed exactly that and nothing more.
            frames = [f for f in reversed(traceback.extract_stack()[:-1])
                      if not f.filename.endswith(("pg_pool.py", "contextlib.py"))][:4]
            chain = " <- ".join(f"{f.filename}:{f.lineno} {f.name}" for f in frames)
            _LOG.warning(
                "nested borrow on shared pool %r (depth %d): a second connection was "
                "borrowed while one is still held from the same pool; under a per-pool "
                "cap this can deadlock. callers %s",
                getattr(self._shared.pool, "name", None), depth, chain)

    def _unborrow(self) -> None:
        depths = _borrow_depths()
        key = id(self._shared)
        remaining = depths.get(key, 1) - 1
        if remaining <= 0:
            depths.pop(key, None)
        else:
            depths[key] = remaining

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """One synchronous unit of work across stores sharing this physical pool.

        Nested connection contexts borrow this transaction's connection without
        committing or returning it. Nested transaction scopes use savepoints.
        Scope is thread-local: do not suspend it across an async await or hand
        its connection to another thread. Other pools remain independent.
        """
        scopes = _transaction_connections()
        key = id(self._shared)
        previous = scopes.get(key)
        with self.connection() as conn, conn.transaction():
            scopes[key] = conn
            try:
                yield conn
            finally:
                if previous is None:
                    scopes.pop(key, None)
                else:
                    scopes[key] = previous

    @contextmanager
    def connection(self, timeout: float | None = None) -> Iterator[Any]:
        active = _transaction_connections().get(id(self._shared))
        if active is not None:
            # The outer transaction exclusively owns commit/rollback and release.
            yield active
            return
        self._borrow()
        try:
            with self._shared.pool.connection(timeout=timeout) as conn:
                yield conn
        finally:
            self._unborrow()

    def getconn(self, timeout: float | None = None) -> Any:
        # Count BEFORE the acquisition, which is the call that blocks: the
        # product-store facade borrows this way, so the warning must be on the
        # log while the second borrow waits, not after it was granted
        # (reviewer finding 2026-09-02). A refused acquisition unwinds the count.
        self._borrow()
        try:
            return self._shared.pool.getconn(timeout=timeout)
        except BaseException:
            self._unborrow()
            raise

    def putconn(self, conn: Any) -> None:
        try:
            self._shared.pool.putconn(conn)
        finally:
            self._unborrow()

    # ``with open_pool(...) as pool:`` (managed_migration) resolves __enter__/__exit__
    # on the TYPE, so __getattr__ forwarding cannot supply them.
    def __enter__(self) -> "SharedPool":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return bool(getattr(self._shared.pool, "closed", False))

    def close(self, *args: Any, **kwargs: Any) -> None:
        with _REGISTRY_LOCK:
            if self._released:
                return
            self._released = True
            self._shared.refs -= 1
            last = self._shared.refs <= 0
        if last:
            self._shared.pool.close(*args, **kwargs)


_SHARED: dict[tuple[Any, ...], _Shared] = {}
_BORROWS = threading.local()
_LOG = logging.getLogger(__name__)


def _borrow_depths() -> dict[int, int]:
    depths = getattr(_BORROWS, "depths", None)
    if depths is None:
        depths = _BORROWS.depths = {}
    return cast(dict[int, int], depths)


def pool_footprint() -> dict[str, int]:
    """What this process can hold against the database, measured from the registry.

    ``max_total`` is the sum of every live pool's ``max_size`` -- the worst case the
    headroom gate must budget for. ``min_total`` is always 0 by construction and is
    reported so a reader can see the invariant rather than trust it.
    """
    with _REGISTRY_LOCK:
        pools = [pool for pool in _REGISTRY if not getattr(pool, "closed", False)]
    max_total = 0
    min_total = 0
    for pool in pools:
        max_total += int(getattr(pool, "max_size", 0) or 0)
        min_total += int(getattr(pool, "min_size", 0) or 0)
    return {"pools": len(pools), "max_total": max_total, "min_total": min_total}


def close_pools_for(conninfo: str, *, timeout: float = 5.0) -> int:
    """Close every shared pool opened for exactly ``conninfo``; returns how many. For a caller that owns a
    disposable database (a per-test schema) and must not leave its connections open after it is dropped.

    ``timeout`` bounds how long each close waits for the pool's worker threads. The default matches
    psycopg's own. A caller closing many short-lived pools in sequence should lower it: the wait is per
    pool, and waiting five seconds each to tidy up a database that is about to be emptied anyway turns a
    fast test suite into a slow one. The connections still close; only the waiting is skipped."""
    with _REGISTRY_LOCK:
        keys = [key for key in _SHARED if key[0] == conninfo]
        closing = [_SHARED.pop(key).pool for key in keys]
    for pool in closing:
        pool.close(timeout=timeout)
    return len(closing)


def _reset_registry_for_tests() -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.clear()
        _SHARED.clear()


def _transaction_connections() -> dict[int, Any]:
    scopes = getattr(_BORROWS, "transactions", None)
    if scopes is None:
        scopes = {}
        _BORROWS.transactions = scopes
    return scopes


@contextmanager
def transaction_scope(pool: Any) -> Iterator[Any]:
    """Opt in to transaction composition; ordinary pool borrowing is unchanged."""
    if isinstance(pool, SharedPool):
        with pool.transaction() as conn:
            yield conn
    else:
        with pool.connection() as conn, conn.transaction():
            yield conn
