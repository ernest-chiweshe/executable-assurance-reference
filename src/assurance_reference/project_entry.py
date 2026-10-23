"""Server-bound release context at the Project OS entry (X-20).

Generic, transport-agnostic form of the frozen ``factory/public_verticals.py@6bba989a``
entry (``_key``, ``_scoped_key``, ``_owned``, ``_human_actor``, ``_emission_context``):

* every call re-verifies its API key against the durable key store, so a revoked
  key refuses at the next request; the stored secret is a SHA-256 digest compared
  in constant time;
* the tenant comes only from the verified key and the actor only from an
  authenticated individual member session of that same tenant. A request body
  that names any tenant, workspace, actor or principal field refuses rather than
  being silently ignored;
* a workspace is a data boundary, never a person: a key alone, or a session whose
  principal is the tenant/workspace itself, cannot act as a human approver;
* the project must exist in the authenticated tenant's own (row-level-secured)
  project state; another tenant's project is indistinguishable from none.

The returned ``EmissionContext`` grants nothing; the regulated gate still decides.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from typing import Any

import psycopg
from psycopg import sql

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable
from factory.projectos.regulated import EmissionContext
from regulated_core.clock import authority_write_committed

KEY_TABLE = "reference_api_keys_v1"
# Request-body fields that would let a client choose who acts or for which tenant.
CLIENT_AUTHORITY_FIELDS = frozenset({"tenant", "tenant_id", "workspace", "workspace_id", "actor", "actor_id",
                                     "principal", "principal_id", "owner", "owner_id"})
_PREFIX = "rk_"


class EntryRefused(PermissionError):
    """A request refused at the Project OS entry, with the status a transport would answer."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status


@dataclass(frozen=True)
class ApiKey:
    key_id: str
    tenant: str
    scopes: frozenset[str]


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def migrate_api_keys(owner: Any, reader_role: str) -> None:
    """Fresh isolated schema only. Keys are looked up by unguessable id before any tenant is known, so the table is
    host metadata without tenant RLS; the runtime reader may only SELECT, and only digests are stored."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(f"""CREATE TABLE {KEY_TABLE}(
            key_id text PRIMARY KEY CHECK(length(key_id) = 32), tenant text NOT NULL CHECK(length(tenant) > 0),
            secret_sha256 text NOT NULL CHECK(length(secret_sha256) = 64), scopes jsonb NOT NULL,
            issued_at_us bigint NOT NULL, revoked_at_us bigint)""")
        name = sql.Identifier(KEY_TABLE)
        conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
        conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(name, sql.Identifier(reader_role)))


def issue_api_key(owner: Any, *, tenant: str, scopes: tuple[str, ...], issued_at_us: int) -> str:
    """Owner-only issuance; returns the bearer token once. Only its digest is retained."""
    if not isinstance(tenant, str) or not tenant.strip() or not scopes or any(not isinstance(s, str) or not s
                                                                            for s in scopes):
        raise ValueError("an API key needs an explicit tenant and scopes")
    key_id, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
    with owner.connection() as conn, conn.transaction():
        conn.execute(f"INSERT INTO {KEY_TABLE}(key_id,tenant,secret_sha256,scopes,issued_at_us)"
                     " VALUES(%s,%s,%s,%s::jsonb,%s)",
                     (key_id, tenant, _digest(secret), json.dumps(sorted(set(scopes))), issued_at_us))
    return f"{_PREFIX}{key_id}.{secret}"


def revoke_api_key(owner: Any, token_or_id: str, *, revoked_at_us: int) -> bool:
    """Owner-only revocation; it takes effect on the very next request. True when a live key was revoked."""
    key_id = token_or_id[len(_PREFIX):].split(".", 1)[0] if token_or_id.startswith(_PREFIX) else token_or_id
    with owner.connection() as conn, conn.transaction():
        row = conn.execute(f"UPDATE {KEY_TABLE} SET revoked_at_us=%s WHERE key_id=%s AND revoked_at_us IS NULL"
                           " RETURNING key_id", (revoked_at_us, key_id)).fetchone()
    authority_write_committed()
    return row is not None


class ApiKeyVerifier:
    """Durable per-request verification over the dedicated key-reader login; nothing is cached."""

    def __init__(self, *, pool: Any) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("API key verification requires the key reader pool")
        self.pool = pool

    def verify(self, token: str) -> ApiKey:
        if not isinstance(token, str) or not token.startswith(_PREFIX) or "." not in token or len(token) > 512:
            raise EntryRefused(401, "a valid API key is required")
        key_id, secret = token[len(_PREFIX):].split(".", 1)
        try:
            with self.pool.connection() as conn, conn.transaction():
                row = conn.execute(f"SELECT tenant,secret_sha256,scopes,revoked_at_us FROM {KEY_TABLE}"
                                   " WHERE key_id=%s", (key_id,)).fetchone()
        except psycopg.Error as error:
            raise EntryRefused(503, "API key verification is unavailable") from error
        if row is None or row[3] is not None or not hmac.compare_digest(row[1], _digest(secret)):
            raise EntryRefused(401, "a valid API key is required")
        scopes = row[2] if isinstance(row[2], list) else json.loads(row[2])
        return ApiKey(key_id, row[0], frozenset(scopes))


class ProjectEntry:
    """Build the server-bound release context for one request, or refuse it at entry."""

    def __init__(self, *, keys: ApiKeyVerifier, sessions: Any,
                 project_exists: Callable[[AuthenticatedSession, str, str], bool]) -> None:
        if not isinstance(keys, ApiKeyVerifier) or not callable(getattr(sessions, "authenticate", None)) \
                or not callable(project_exists):
            raise TypeError("the Project OS entry requires durable keys, member sessions and project ownership")
        self.keys, self.sessions, self.project_exists = keys, sessions, project_exists

    def context(self, *, api_key: str, session_token: str | None, vertical: str, project_id: str,
                body: Mapping[str, Any] | None) -> EmissionContext:
        body = dict(body or {})
        named = sorted(set(body) & CLIENT_AUTHORITY_FIELDS)
        if named:
            raise EntryRefused(400, "a client cannot choose the tenant or actor: " + ", ".join(named))
        key = self.keys.verify(api_key)
        if vertical not in key.scopes:
            raise EntryRefused(403, f"this key is not scoped to {vertical!r}")
        if not session_token:
            raise EntryRefused(403, "sign in with an individual member account; a workspace never approves")
        try:
            identity = self.sessions.authenticate(key.tenant, session_token)
        except SessionUnavailable as error:
            raise EntryRefused(503, "member authentication is unavailable") from error
        except SessionRefused as error:
            raise EntryRefused(403, "sign in with an individual member account of this workspace") from error
        if (not isinstance(identity, AuthenticatedSession) or identity.tenant != key.tenant
                or identity.principal == key.tenant):
            raise EntryRefused(403, "sign in with an individual member account; a workspace never approves")
        if not self.project_exists(identity, vertical, project_id):
            raise EntryRefused(404, "no such project")
        return EmissionContext(tenant=key.tenant, actor_id=identity.principal, project_id=project_id,
                               vertical_name=vertical, nonce=str(body.get("nonce", "")).strip(),
                               action_id=str(body.get("action_id", "")).strip(),
                               approval=body.get("review_id") or None)


def project_state_ownership(*, pool: Any, sessions: Any) -> Callable[[AuthenticatedSession, str, str], bool]:
    """Ownership from the authenticated tenant's own session-bound project state (vertical as namespace)."""
    from assurance_reference.project_state import compose_project_state
    from factory.projectos.errors import ProjectEngineError

    def exists(identity: AuthenticatedSession, vertical: str, project_id: str) -> bool:
        store = compose_project_state(pool=pool, sessions=sessions, authenticated=identity, namespace=vertical)
        try:
            store.load(project_id)
        except ProjectEngineError:
            return False
        return True

    return exists


__all__ = ["ApiKey", "ApiKeyVerifier", "CLIENT_AUTHORITY_FIELDS", "EntryRefused", "KEY_TABLE", "ProjectEntry",
           "issue_api_key", "migrate_api_keys", "project_state_ownership", "revoke_api_key"]
