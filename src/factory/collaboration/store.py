"""Append-only durable stores for the collaboration supervisor.

All lifecycle decisions are made by a planner while the backend holds one
per-run transaction lock.  The planner receives the backend's clock value and
the complete immutable history, then returns events to append. Postgres is the durable backend in every
environment. The explicit memory double is for deterministic logic tests only;
restart and cross-process laws are verified against real Postgres.
"""
from __future__ import annotations

import atexit
import hashlib
import importlib
import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, TypeVar, cast

from factory.collaboration.contracts import ContractViolation


class StoreConflict(RuntimeError):
    """An atomic guard or identity binding refused a mutation."""


class SupervisorEventType(str, Enum):
    RUN_CREATED = "run_created"
    AUTHORIZATION_CHANGED = "authorization_changed"
    AUTHORIZATION_REFUSED = "authorization_refused"
    TICKET_QUEUED = "ticket_queued"
    BUDGET_RESERVED = "budget_reserved"
    TICKET_DISPATCHED = "ticket_dispatched"
    DISPATCH_RECORDED = "dispatch_recorded"
    TICKET_ACKNOWLEDGED = "ticket_acknowledged"
    HEARTBEAT_RECORDED = "heartbeat_recorded"
    TICKET_STRANDED = "ticket_stranded"
    RESERVATION_RELEASED = "reservation_released"
    BUDGET_SETTLED = "budget_settled"
    AUTHORSHIP_TRANSFERRED = "authorship_transferred"
    ARTIFACT_SUBMITTED = "artifact_submitted"
    REVIEW_QUEUED = "review_queued"
    REVISION_REQUESTED = "revision_requested"
    TICKET_COMPLETED = "ticket_completed"
    TICKET_FAILED = "ticket_failed"
    STOPPING = "stopping"
    STOPPED = "stopped"
    HARD_STOPPED = "hard_stopped"
    RUN_PAUSED = "run_paused"
    RUN_RESUMED = "run_resumed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCEL_ANSWERED = "cancel_answered"
    # An in-process worker's exclusive "the one provider call for this attempt begins now" marker. It lands
    # BEFORE the call, so a crash afterwards reads as an unknown outcome and the call is never made again.
    WORKER_CALL_STARTED = "worker_call_started"
    # The verbatim worker output (bounded), its digest, run id and reported cost, retained BEFORE any
    # lifecycle transition consumes it, so recovery never needs a second call.
    WORKER_OUTPUT_RETAINED = "worker_output_retained"
    # One explicit re-attempt of a stranded ticket, granted by the run's authority (never automatic).
    ATTEMPT_GRANTED = "attempt_granted"
    BATCH_CONFIRMED = "batch_confirmed"
    BATCH_STARTED = "batch_started"
    BATCH_FINISHED = "batch_finished"


@dataclass(frozen=True, slots=True)
class SupervisorEvent:
    event_id: str
    sequence: int
    tenant_id: str
    run_id: str
    ticket_id: str
    event_type: SupervisorEventType
    recorded_at: float
    idempotency_key: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, SupervisorEventType):
            raise ContractViolation("event_type must be SupervisorEventType")
        if self.sequence < 1:
            raise ContractViolation("event sequence must be positive")
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.event_id, self.tenant_id, self.run_id, self.idempotency_key)):
            raise ContractViolation("event identity fields must be non-blank")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


@dataclass(frozen=True, slots=True)
class EventDraft:
    event_type: SupervisorEventType
    idempotency_key: str
    payload: Mapping[str, object]
    ticket_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, SupervisorEventType):
            raise ContractViolation("draft event_type must be SupervisorEventType")
        if not self.idempotency_key.strip():
            raise ContractViolation("draft idempotency_key must be non-blank")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class StorePlan:
    additions: tuple[EventDraft, ...]
    value: object = None


@dataclass(frozen=True, slots=True)
class StoreResult:
    appended: tuple[SupervisorEvent, ...]
    value: object
    now: float


Planner = Callable[[tuple[SupervisorEvent, ...], float], StorePlan]


class CollaborationStore(Protocol):
    def ensure_schema(self) -> None: ...
    def events(self, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]: ...
    def transact(self, tenant_id: str, run_id: str, planner: Planner) -> StoreResult: ...
    def list_runs(self, tenant_id: str) -> tuple[str, ...]: ...
    def close(self) -> None: ...


POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS collaboration_events (
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    sequence        BIGINT NOT NULL,
    event_id        TEXT NOT NULL,
    ticket_id       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    recorded_at     DOUBLE PRECISION NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload         JSONB NOT NULL,
    PRIMARY KEY (tenant_id, run_id, sequence),
    UNIQUE (tenant_id, run_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS collaboration_event_ticket
    ON collaboration_events (tenant_id, run_id, ticket_id, sequence);
"""


def _event_from_row(tenant_id: str, run_id: str, row: tuple[object, ...]) -> SupervisorEvent:
    payload = row[7]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return SupervisorEvent(
        sequence=int(cast(int, row[0])),
        event_id=str(row[1]),
        tenant_id=tenant_id,
        run_id=run_id,
        ticket_id=str(row[2]),
        event_type=SupervisorEventType(str(row[3])),
        recorded_at=float(cast(float, row[4])),
        idempotency_key=str(row[5]),
        payload=cast(Mapping[str, object], payload),
    )


# Rows selected by both backends include a reserved column at index 6.  Keeping
# the shape identical makes the parser and semantic tests backend-independent.
_SELECT = ("SELECT sequence, event_id, ticket_id, event_type, recorded_at, "
           "idempotency_key, tenant_id, payload FROM collaboration_events "
           "WHERE tenant_id = {p} AND run_id = {p} ORDER BY sequence")


def _materialize(tenant_id: str, run_id: str, history: tuple[SupervisorEvent, ...],
                 now: float, drafts: tuple[EventDraft, ...]) -> tuple[SupervisorEvent, ...]:
    existing = {event.idempotency_key: event for event in history}
    seen: set[str] = set()
    appended: list[SupervisorEvent] = []
    for draft in drafts:
        prior = existing.get(draft.idempotency_key)
        if prior is not None:
            if (prior.event_type is not draft.event_type or prior.ticket_id != draft.ticket_id
                    or dict(prior.payload) != dict(draft.payload)):
                raise StoreConflict("idempotency key reused for different event content")
            continue
        if draft.idempotency_key in seen:
            raise StoreConflict("duplicate idempotency key inside one mutation")
        seen.add(draft.idempotency_key)
        appended.append(SupervisorEvent(
            event_id=uuid.uuid4().hex,
            sequence=len(history) + len(appended) + 1,
            tenant_id=tenant_id,
            run_id=run_id,
            ticket_id=draft.ticket_id,
            event_type=draft.event_type,
            recorded_at=now,
            idempotency_key=draft.idempotency_key,
            payload=draft.payload,
        ))
    return tuple(appended)


class InMemoryCollaborationStore:
    """Explicit non-durable test double; never selected by runtime configuration."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._closed = False
        self._gate = threading.RLock()
        self._events: dict[tuple[str, str], tuple[SupervisorEvent, ...]] = {}

    def ensure_schema(self) -> None:
        return

    def close(self) -> None:
        self._closed = True

    def events(self, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]:
        with self._gate:
            return self._events.get((tenant_id, run_id), ())

    def list_runs(self, tenant_id: str) -> tuple[str, ...]:
        with self._gate:
            return tuple(sorted(run for tenant, run in self._events if tenant == tenant_id))

    def transact(self, tenant_id: str, run_id: str, planner: Planner) -> StoreResult:
        with self._gate:
            if self._closed:
                raise RuntimeError("collaboration store is closed")
            history = self.events(tenant_id, run_id)
            now = float(self._clock())
            plan = planner(history, now)
            appended = _materialize(tenant_id, run_id, history, now, plan.additions)
            self._events[(tenant_id, run_id)] = history + appended
            return StoreResult(appended, plan.value, now)


def _lock_key(tenant_id: str, run_id: str) -> int:
    digest = hashlib.sha256(f"{tenant_id}:{run_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class PgCollaborationStore:
    """Postgres backend with DB clock and cross-process per-run atomicity."""

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 1,
        max_size: int = 8,
        pool: Any = None,
        project_assignment_attempts: bool = False,
    ) -> None:
        self._closed = False
        self._project_assignment_attempts = project_assignment_attempts
        if pool is not None:
            self._pool = pool
            return
        # Optional production extra: keep the free/local import path fail-dark.
        # ``min_size`` stays in the public constructor for compatibility but is not
        # honoured: every production pool opens EMPTY (owner decision DB-001 part A).
        # Laws 12+17 keep factory.pg_pool out of this package, so the footprint contract
        # is stated inline and pinned by the tree scan in tests/test_pg_pool.py.
        del min_size
        pool_type = cast(Any, importlib.import_module("psycopg_pool")).ConnectionPool
        self._pool = pool_type(dsn, min_size=0, max_size=max_size, open=True, max_idle=120.0,
                              kwargs={"autocommit": True})
        atexit.register(self.close)

    @property
    def connection_pool(self) -> Any:
        """Borrow this store-owned pool for metadata in the same composition."""
        return self._pool

    def ensure_schema(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(POSTGRES_SCHEMA)
            if self._project_assignment_attempts:
                from factory.collaboration.assignment_bundles_pg import POSTGRES_SCHEMA as assignment_schema

                conn.execute(assignment_schema)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._pool.close()
        except Exception:  # noqa: BLE001 - teardown must be best effort
            pass

    def _load(self, conn: Any, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]:
        rows = conn.execute(_SELECT.format(p="%s"), (tenant_id, run_id)).fetchall()
        return tuple(_event_from_row(tenant_id, run_id, cast(tuple[object, ...], row)) for row in rows)

    def events(self, tenant_id: str, run_id: str) -> tuple[SupervisorEvent, ...]:
        with self._pool.connection() as conn:
            return self._load(conn, tenant_id, run_id)

    def list_runs(self, tenant_id: str) -> tuple[str, ...]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT run_id FROM collaboration_events WHERE tenant_id = %s "
                "ORDER BY run_id", (tenant_id,)).fetchall()
        return tuple(str(row[0]) for row in rows)

    def transact(self, tenant_id: str, run_id: str, planner: Planner) -> StoreResult:
        if self._closed:
            raise RuntimeError("collaboration store is closed")
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_lock_key(tenant_id, run_id),))
            history = self._load(conn, tenant_id, run_id)
            row = conn.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp())").fetchone()
            if row is None:
                raise RuntimeError("Postgres store clock unavailable")
            now = float(row[0])
            plan = planner(history, now)
            appended = _materialize(tenant_id, run_id, history, now, plan.additions)
            for event in appended:
                conn.execute(
                    "INSERT INTO collaboration_events "
                    "(tenant_id, run_id, sequence, event_id, ticket_id, event_type, "
                    "recorded_at, idempotency_key, payload) VALUES "
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
                    (tenant_id, run_id, event.sequence, event.event_id, event.ticket_id,
                     event.event_type.value, event.recorded_at, event.idempotency_key,
                     json.dumps(dict(event.payload), sort_keys=True, separators=(",", ":"))),
                )
            if self._project_assignment_attempts and appended:
                from factory.collaboration.assignment_bundles import AssignmentBundleError
                from factory.collaboration.assignment_bundles_pg import (
                    project_assignment_attempt_events,
                )

                try:
                    project_assignment_attempt_events(conn, history, appended)
                except AssignmentBundleError as exc:
                    raise StoreConflict(
                        "assignment attempt projection refused lifecycle transaction"
                    ) from exc
        return StoreResult(appended, plan.value, now)


def build_collaboration_store(root: "str | Path") -> "CollaborationStore":
    """Require explicit Postgres configuration in development and production."""
    import os

    del root  # retained API parameter; never creates a local database or directory
    if os.environ.get("FACTORY_COLLABORATION", "").strip().casefold() != "pg":
        raise RuntimeError("FACTORY_COLLABORATION must be pg; SQLite is no longer a runtime backend")
    dsn = os.environ.get("FACTORY_DB_URL", "").strip()
    if not dsn:
        raise RuntimeError("FACTORY_COLLABORATION=pg requires FACTORY_DB_URL to be set")
    schema_mode = os.environ.get("FACTORY_PRODUCT_SCHEMA_MODE", "bootstrap-on-start").strip()
    if schema_mode not in {"bootstrap-on-start", "external-migration-task"}:
        raise RuntimeError("FACTORY_PRODUCT_SCHEMA_MODE must be bootstrap-on-start or external-migration-task")
    if os.environ.get("FACTORY_COLLABORATION_BUNDLE_METADATA", "").strip().casefold() != "pg":
        raise RuntimeError("FACTORY_COLLABORATION_BUNDLE_METADATA must be pg")
    store = PgCollaborationStore(dsn, project_assignment_attempts=True)
    with _COMPOSED_LOCK:
        _COMPOSED.setdefault(dsn, []).append(store)
    if schema_mode == "bootstrap-on-start":
        store.ensure_schema()
    return store


#: Stores this composition opened, per DSN. Each owns a pool (up to 8 connections) that is otherwise closed
#: only at process exit - right for one Hub per process, but a process that composes many Hubs (the test
#: suite does, once per test) kept every pool open: measured 2026-09-22 as one leaked server connection per
#: Hub-composing test until PostgreSQL refused with "too many clients already".
_COMPOSED: dict[str, list[PgCollaborationStore]] = {}
_COMPOSED_LOCK = threading.Lock()


def close_collaboration_stores_for(dsn: str) -> int:
    """Close every store build_collaboration_store opened for exactly ``dsn``; returns how many.

    For a caller that owns a disposable database, such as a per-test schema - the counterpart of
    factory.pg_pool.close_pools_for for this package, which laws 12+17 keep out of factory.pg_pool."""
    with _COMPOSED_LOCK:
        stores = _COMPOSED.pop(dsn, [])
    for store in stores:
        store.close()
    return len(stores)
