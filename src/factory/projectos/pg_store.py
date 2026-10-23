"""PostgreSQL authority for Project OS choreography state.

This stores the data formerly held in project.json. It intentionally does not
claim vertical-owned source media, exports, settings, or colocated databases;
those need their own durable authorities for fully replaceable tasks.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Iterator

from factory.projectos.engine import ProjectEngineError, _validate_project_id

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS projectos_states (
  tenant_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  project_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision > 0),
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, namespace, project_id)
);
"""


class _DirectPool:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    @contextmanager
    def connection(self) -> Iterator[Any]:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            yield conn

    def close(self) -> None:
        return


class PostgresProjectStateStore:
    """Tenant- and vertical-scoped project state with optimistic writes."""

    def __init__(
        self,
        dsn: str,
        *,
        namespace: str,
        tenant_id: str = "self",
        ensure_schema: bool = True,
        pool: Any = None,
    ) -> None:
        self._namespace = namespace.strip()
        self._tenant_id = tenant_id.strip()
        if not self._namespace:
            raise ValueError("Project OS namespace is required")
        if not self._tenant_id:
            raise ValueError("Project OS tenant id is required")
        self._observed_revisions: dict[str, int] = {}
        if pool is not None:
            self._pool = pool
        else:
            # Vertical surfaces construct short-lived engines per request. A
            # pool per engine would strand connections, so the no-injection
            # path intentionally opens one connection per store operation.
            self._pool = _DirectPool(dsn)
        if ensure_schema:
            self.ensure_schema()

    def ensure_schema(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(POSTGRES_SCHEMA)

    def create(self, project_id: str, state: dict[str, Any]) -> None:
        _validate_project_id(project_id)
        encoded = _encode_state(state)
        with self._pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO projectos_states"
                " (tenant_id,namespace,project_id,revision,state)"
                " VALUES (%s,%s,%s,1,%s::jsonb)"
                " ON CONFLICT (tenant_id,namespace,project_id) DO NOTHING"
                " RETURNING revision",
                (self._tenant_id, self._namespace, project_id, encoded),
            ).fetchone()
        if row is None:
            raise ProjectEngineError(f"project {project_id!r} already exists")
        self._observed_revisions[project_id] = int(row[0])

    def load(self, project_id: str) -> dict[str, Any]:
        _validate_project_id(project_id)
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT state,revision FROM projectos_states"
                " WHERE tenant_id = %s AND namespace = %s AND project_id = %s",
                (self._tenant_id, self._namespace, project_id),
            ).fetchone()
        if row is None:
            raise ProjectEngineError(f"no project {project_id!r}")
        self._observed_revisions[project_id] = int(row[1])
        return _decode_state(row[0])

    def save(self, project_id: str, state: dict[str, Any]) -> None:
        _validate_project_id(project_id)
        expected = self._observed_revisions.get(project_id)
        if expected is None:
            raise ProjectEngineError(
                f"project {project_id!r} must be loaded before it can be saved"
            )
        with self._pool.connection() as conn:
            row = conn.execute(
                "UPDATE projectos_states SET state = %s::jsonb,"
                " revision = revision + 1, updated_at = CURRENT_TIMESTAMP"
                " WHERE tenant_id = %s AND namespace = %s AND project_id = %s"
                " AND revision = %s RETURNING revision",
                (
                    _encode_state(state),
                    self._tenant_id,
                    self._namespace,
                    project_id,
                    expected,
                ),
            ).fetchone()
        if row is None:
            raise ProjectEngineError(
                f"project {project_id!r} changed concurrently or no longer exists; reload and retry"
            )
        self._observed_revisions[project_id] = int(row[0])

    def list_projects(self) -> list[str]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT project_id,state FROM projectos_states"
                " WHERE tenant_id = %s AND namespace = %s",
                (self._tenant_id, self._namespace),
            ).fetchall()
        projects: list[tuple[float, str]] = []
        for project_id, state in rows:
            try:
                created = float(_decode_state(state).get("created", 0.0))
            except (ProjectEngineError, TypeError, ValueError):
                continue
            projects.append((created, str(project_id)))
        return [project_id for _created, project_id in sorted(projects, reverse=True)]

    def delete(self, project_id: str) -> None:
        _validate_project_id(project_id)
        with self._pool.connection() as conn:
            row = conn.execute(
                "DELETE FROM projectos_states"
                " WHERE tenant_id = %s AND namespace = %s AND project_id = %s"
                " RETURNING project_id",
                (self._tenant_id, self._namespace, project_id),
            ).fetchone()
        if row is None:
            raise ProjectEngineError(f"no project {project_id!r}")
        self._observed_revisions.pop(project_id, None)

def _encode_state(state: dict[str, Any]) -> str:
    return json.dumps(state, sort_keys=True, separators=(",", ":"))


def _decode_state(value: Any) -> dict[str, Any]:
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError as exc:
        raise ProjectEngineError("stored project state is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ProjectEngineError("stored project state is not an object")
    return dict(decoded)


__all__ = ["POSTGRES_SCHEMA", "PostgresProjectStateStore"]
