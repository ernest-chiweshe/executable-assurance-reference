"""PostgreSQL pointer and lease authority for collaboration bundles.

Construction never applies DDL. ``apply_assignment_bundle_migration`` is the
schema entry point. Managed deployment uses the external migration task;
an explicitly configured local bootstrap may call it during composition.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from factory.collaboration.assignment_bundles import (
    AssignmentAttempt,
    AssignmentBundleError,
    AssignmentPointer,
    _ALL_STATES,
    _transition_allowed,
)

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS collaboration_assignment_pointers (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('author', 'reviewer')),
    subject_digest TEXT NOT NULL CHECK (length(subject_digest) = 64),
    bundle_digest TEXT NOT NULL CHECK (length(bundle_digest) = 64),
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, run_id, ticket_id, role, subject_digest),
    UNIQUE (tenant_id, run_id, ticket_id, role, bundle_digest)
);
CREATE TABLE IF NOT EXISTS collaboration_assignment_attempts (
    tenant_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('author', 'reviewer')),
    bundle_digest TEXT NOT NULL CHECK (length(bundle_digest) = 64),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    ack_deadline_at DOUBLE PRECISION NOT NULL,
    lease_expires_at DOUBLE PRECISION NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('claimed', 'acknowledged', 'completed', 'stranded')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, run_id, ticket_id, role, bundle_digest)
      REFERENCES collaboration_assignment_pointers
        (tenant_id, run_id, ticket_id, role, bundle_digest)
);
CREATE INDEX IF NOT EXISTS collaboration_assignment_attempts_ticket
    ON collaboration_assignment_attempts (tenant_id, run_id, ticket_id, attempt_number DESC);
CREATE UNIQUE INDEX IF NOT EXISTS collaboration_assignment_one_active_attempt
    ON collaboration_assignment_attempts (tenant_id, run_id, ticket_id, role)
    WHERE state IN ('claimed', 'acknowledged');
"""


def apply_assignment_bundle_migration(*, pool: Any) -> None:
    """Apply additive DDL from an explicitly invoked migration task."""

    with pool.connection() as conn, conn.transaction():
        conn.execute(POSTGRES_SCHEMA)


def _payload(attempt: AssignmentAttempt) -> str:
    return json.dumps(
        {name: getattr(attempt, name) for name in attempt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
    )


def _attempt(row: Any) -> AssignmentAttempt | None:
    if row is None:
        return None
    payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    try:
        return AssignmentAttempt(**payload)
    except Exception as exc:
        raise AssignmentBundleError("stored assignment attempt is invalid") from exc


class PostgresAssignmentBundleAuthority:
    """Exact-replay pointer and compare-and-swap lease authority."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    @staticmethod
    def _lock(conn: Any, *identity: str) -> None:
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (":".join(identity),),
        )

    def publish(self, pointer: AssignmentPointer) -> AssignmentPointer:
        with self._pool.connection() as conn, conn.transaction():
            self._lock(conn, pointer.tenant_id, pointer.run_id, pointer.ticket_id, pointer.role)
            inserted = conn.execute(
                "INSERT INTO collaboration_assignment_pointers "
                "(tenant_id, run_id, ticket_id, role, subject_digest, bundle_digest, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT DO NOTHING RETURNING 1",
                (pointer.tenant_id, pointer.run_id, pointer.ticket_id, pointer.role,
                 pointer.subject_digest, pointer.bundle_digest, pointer.created_at),
            ).fetchone()
            if inserted is not None:
                return pointer
            existing = self._pointer(conn, pointer.tenant_id, pointer.run_id,
                                     pointer.ticket_id, pointer.role, pointer.subject_digest)
            if existing is None or (
                existing.tenant_id,
                existing.run_id,
                existing.ticket_id,
                existing.role,
                existing.subject_digest,
                existing.bundle_digest,
            ) != (
                pointer.tenant_id,
                pointer.run_id,
                pointer.ticket_id,
                pointer.role,
                pointer.subject_digest,
                pointer.bundle_digest,
            ):
                raise AssignmentBundleError("assignment pointer is immutable")
            return existing

    @staticmethod
    def _pointer(
        conn: Any, tenant_id: str, run_id: str, ticket_id: str, role: str,
        subject_digest: str,
    ) -> AssignmentPointer | None:
        row = conn.execute(
            "SELECT tenant_id, run_id, ticket_id, role, subject_digest, "
            "bundle_digest, created_at "
            "FROM collaboration_assignment_pointers WHERE tenant_id=%s AND run_id=%s "
            "AND ticket_id=%s AND role=%s AND subject_digest=%s",
            (tenant_id, run_id, ticket_id, role, subject_digest),
        ).fetchone()
        return AssignmentPointer(*row) if row else None

    def pointer(
        self, tenant_id: str, run_id: str, ticket_id: str, role: str,
        subject_digest: str,
    ) -> AssignmentPointer | None:
        with self._pool.connection() as conn:
            return self._pointer(conn, tenant_id, run_id, ticket_id, role, subject_digest)

    def claim(self, attempt: AssignmentAttempt) -> AssignmentAttempt:
        with self._pool.connection() as conn, conn.transaction():
            self._lock(conn, attempt.tenant_id, attempt.attempt_id)
            self._lock(conn, attempt.tenant_id, attempt.run_id, attempt.ticket_id, attempt.role)
            pointer_row = conn.execute(
                "SELECT tenant_id, run_id, ticket_id, role, subject_digest, "
                "bundle_digest, created_at FROM collaboration_assignment_pointers "
                "WHERE tenant_id=%s AND run_id=%s AND ticket_id=%s AND role=%s "
                "AND bundle_digest=%s",
                (attempt.tenant_id, attempt.run_id, attempt.ticket_id, attempt.role,
                 attempt.bundle_digest),
            ).fetchone()
            pointer = AssignmentPointer(*pointer_row) if pointer_row else None
            if pointer is None or pointer.bundle_digest != attempt.bundle_digest:
                raise AssignmentBundleError("attempt is not bound to the published bundle")
            active = _attempt(
                conn.execute(
                    "SELECT payload FROM collaboration_assignment_attempts "
                    "WHERE tenant_id=%s AND run_id=%s AND ticket_id=%s AND role=%s "
                    "AND state IN ('claimed', 'acknowledged') AND attempt_id<>%s FOR UPDATE",
                    (attempt.tenant_id, attempt.run_id, attempt.ticket_id, attempt.role,
                     attempt.attempt_id),
                ).fetchone()
            )
            if active is not None:
                raise AssignmentBundleError("assignment already has an active attempt")
            inserted = conn.execute(
                "INSERT INTO collaboration_assignment_attempts "
                "(tenant_id, attempt_id, run_id, ticket_id, participant_id, role, bundle_digest, "
                "attempt_number, ack_deadline_at, lease_expires_at, state, revision, payload) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb) "
                "ON CONFLICT DO NOTHING RETURNING 1",
                (attempt.tenant_id, attempt.attempt_id, attempt.run_id, attempt.ticket_id,
                 attempt.participant_id, attempt.role, attempt.bundle_digest,
                 attempt.attempt_number, attempt.ack_deadline_at, attempt.lease_expires_at,
                 attempt.state, attempt.revision, _payload(attempt)),
            ).fetchone()
            if inserted is not None:
                return attempt
            existing = self._attempt(conn, attempt.tenant_id, attempt.attempt_id)
            if existing != attempt:
                raise AssignmentBundleError("assignment attempt identity changed")
            return existing

    @staticmethod
    def _attempt(conn: Any, tenant_id: str, attempt_id: str) -> AssignmentAttempt | None:
        row = conn.execute(
            "SELECT payload FROM collaboration_assignment_attempts "
            "WHERE tenant_id=%s AND attempt_id=%s", (tenant_id, attempt_id)
        ).fetchone()
        return _attempt(row)

    def attempt(self, tenant_id: str, attempt_id: str) -> AssignmentAttempt | None:
        with self._pool.connection() as conn:
            return self._attempt(conn, tenant_id, attempt_id)

    def transition(
        self,
        tenant_id: str,
        attempt_id: str,
        *,
        expected_revision: int,
        state: str,
        lease_expires_at: float | None = None,
    ) -> AssignmentAttempt:
        if state not in _ALL_STATES:
            raise AssignmentBundleError("invalid assignment attempt state")
        with self._pool.connection() as conn, conn.transaction():
            self._lock(conn, tenant_id, attempt_id)
            current = self._attempt(conn, tenant_id, attempt_id)
            if (
                current is None
                or current.revision != expected_revision
                or not _transition_allowed(current.state, state)
            ):
                raise AssignmentBundleError("stale assignment attempt transition")
            values = {name: getattr(current, name) for name in current.__dataclass_fields__}
            values["state"] = state
            values["revision"] = current.revision + 1
            if lease_expires_at is not None:
                if lease_expires_at <= current.lease_expires_at:
                    raise AssignmentBundleError("lease renewal must extend the lease")
                values["lease_expires_at"] = lease_expires_at
            updated = AssignmentAttempt(**values)
            changed = conn.execute(
                "UPDATE collaboration_assignment_attempts SET state=%s, revision=%s, "
                "lease_expires_at=%s, payload=%s::jsonb WHERE tenant_id=%s AND attempt_id=%s "
                "AND revision=%s RETURNING 1",
                (updated.state, updated.revision, updated.lease_expires_at, _payload(updated),
                 tenant_id, attempt_id, expected_revision),
            ).fetchone()
            if changed is None:
                raise AssignmentBundleError("stale assignment attempt transition")
            return updated


def _event_kind(event: Any) -> str:
    kind = event.event_type
    return str(getattr(kind, "value", kind))


def _subject_digest(events: Iterable[Any], ticket_id: str, role: str) -> str:
    """Resolve the semantic bundle subject from canonical supervisor history."""

    for event in reversed(tuple(events)):
        if event.ticket_id != ticket_id:
            continue
        kind = _event_kind(event)
        if role == "reviewer" and kind == "review_queued":
            return str(event.payload.get("artifact_digest", ""))
        if role == "author" and kind == "revision_requested":
            return str(event.payload.get("findings_digest", ""))
        if role == "author" and kind == "ticket_queued":
            ticket = event.payload.get("ticket")
            if isinstance(ticket, dict):
                return str(ticket.get("source_snapshot_digest", ""))
    raise AssignmentBundleError("assignment bundle subject is unavailable")


def _project_claim(conn: Any, event: Any, history: tuple[Any, ...]) -> None:
    payload = event.payload
    role = str(payload.get("role", ""))
    subject_digest = _subject_digest(history, event.ticket_id, role)
    pointer = conn.execute(
        "SELECT bundle_digest FROM collaboration_assignment_pointers "
        "WHERE tenant_id=%s AND run_id=%s AND ticket_id=%s AND role=%s "
        "AND subject_digest=%s",
        (event.tenant_id, event.run_id, event.ticket_id, role, subject_digest),
    ).fetchone()
    if pointer is None:
        raise AssignmentBundleError(
            "dispatched attempt has no published assignment bundle"
        )
    attempt = AssignmentAttempt(
        tenant_id=event.tenant_id,
        run_id=event.run_id,
        ticket_id=event.ticket_id,
        attempt_id=str(payload.get("attempt_id", "")),
        participant_id=str(payload.get("participant_id", "")),
        role=role,
        bundle_digest=str(pointer[0]),
        attempt_number=int(payload.get("attempt_number", 0)),
        ack_deadline_at=float(payload.get("ack_deadline_at", 0.0)),
        lease_expires_at=float(payload.get("lease_expires_at", 0.0)),
    )
    inserted = conn.execute(
        "INSERT INTO collaboration_assignment_attempts "
        "(tenant_id, attempt_id, run_id, ticket_id, participant_id, role, bundle_digest, "
        "attempt_number, ack_deadline_at, lease_expires_at, state, revision, payload) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb) "
        "ON CONFLICT DO NOTHING RETURNING 1",
        (
            attempt.tenant_id,
            attempt.attempt_id,
            attempt.run_id,
            attempt.ticket_id,
            attempt.participant_id,
            attempt.role,
            attempt.bundle_digest,
            attempt.attempt_number,
            attempt.ack_deadline_at,
            attempt.lease_expires_at,
            attempt.state,
            attempt.revision,
            _payload(attempt),
        ),
    ).fetchone()
    if inserted is None and PostgresAssignmentBundleAuthority._attempt(
        conn, attempt.tenant_id, attempt.attempt_id
    ) != attempt:
        raise AssignmentBundleError("assignment attempt identity changed")


def _project_transition(conn: Any, event: Any, state: str) -> None:
    attempt_id = str(event.payload.get("attempt_id", ""))
    current = _attempt(
        conn.execute(
            "SELECT payload FROM collaboration_assignment_attempts "
            "WHERE tenant_id=%s AND attempt_id=%s FOR UPDATE",
            (event.tenant_id, attempt_id),
        ).fetchone()
    )
    if current is None or not _transition_allowed(current.state, state):
        raise AssignmentBundleError("stale assignment attempt transition")
    values = {name: getattr(current, name) for name in current.__dataclass_fields__}
    values["state"] = state
    values["revision"] = current.revision + 1
    if _event_kind(event) in {"ticket_acknowledged", "heartbeat_recorded"}:
        lease_expires_at = float(event.payload.get("lease_expires_at", 0.0))
        if lease_expires_at <= current.lease_expires_at:
            raise AssignmentBundleError("lease renewal must extend the lease")
        values["lease_expires_at"] = lease_expires_at
    updated = AssignmentAttempt(**values)
    changed = conn.execute(
        "UPDATE collaboration_assignment_attempts SET state=%s, revision=%s, "
        "lease_expires_at=%s, payload=%s::jsonb WHERE tenant_id=%s AND attempt_id=%s "
        "AND revision=%s RETURNING 1",
        (
            updated.state,
            updated.revision,
            updated.lease_expires_at,
            _payload(updated),
            updated.tenant_id,
            updated.attempt_id,
            current.revision,
        ),
    ).fetchone()
    if changed is None:
        raise AssignmentBundleError("stale assignment attempt transition")


def project_assignment_attempt_events(
    conn: Any, history: tuple[Any, ...], appended: tuple[Any, ...]
) -> None:
    """Project lifecycle events in the caller's existing PostgreSQL transaction.

    ``collaboration_events`` remains canonical. This function deliberately
    accepts a connection rather than opening one so event append and attempt
    lease metadata can never commit independently.
    """

    visible = list(history)
    terminal = {
        "artifact_submitted": "completed",
        "revision_requested": "completed",
        "ticket_completed": "completed",
        "ticket_stranded": "stranded",
    }
    for event in appended:
        visible.append(event)
        kind = _event_kind(event)
        if kind == "ticket_dispatched":
            _project_claim(conn, event, tuple(visible))
        elif kind in {"ticket_acknowledged", "heartbeat_recorded"}:
            _project_transition(conn, event, "acknowledged")
        elif kind in terminal:
            _project_transition(conn, event, terminal[kind])
