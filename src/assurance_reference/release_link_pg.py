"""PostgreSQL goal snapshots and atomic task/review links for local composition.

Provisioning is explicit and owner-only. Runtime can read goal versions, lock a
non-authoritative head anchor and insert immutable links. Goal changes take the
exclusive counterpart of the admission lock. This is a local trusted-host model;
RLS settings and provisioning credentials are not separate-process isolation.
"""
from contextlib import contextmanager
from dataclasses import asdict
import json

from psycopg import sql

from factory.projectos.regulated import ReleaseAuthorityBinding
from regulated_core.canonical import digest_hex
from assurance_reference.release_link import (
    GoalReleaseBinding, ReleaseLink, ReleaseLinkRefused, ReleaseLinkRequest,
    VerifiedReleaseBinding,
)

TABLES = ("reference_release_goal_heads_v1", "reference_release_goal_versions_v1",
          "reference_release_links_v1")


def migrate_release_links(owner, runtime_role):
    """Fresh isolated schema only; caller owns role provisioning."""
    with owner.connection() as conn, conn.transaction():
        conn.execute("""CREATE TABLE reference_release_goal_heads_v1(
            tenant text NOT NULL, goal_id text NOT NULL,
            lock_anchor boolean NOT NULL DEFAULT true CHECK(lock_anchor),
            PRIMARY KEY(tenant,goal_id))""")
        conn.execute("""CREATE TABLE reference_release_goal_versions_v1(
            tenant text NOT NULL, goal_id text NOT NULL, version bigint NOT NULL CHECK(version>=0),
            payload_digest text NOT NULL, payload jsonb NOT NULL,
            PRIMARY KEY(tenant,goal_id,version),
            FOREIGN KEY(tenant,goal_id) REFERENCES reference_release_goal_heads_v1)""")
        conn.execute("""CREATE TABLE reference_release_links_v1(
            tenant text NOT NULL, goal_id text NOT NULL, task_id text NOT NULL,
            payload_digest text NOT NULL, payload jsonb NOT NULL,
            PRIMARY KEY(tenant,goal_id,task_id),
            FOREIGN KEY(tenant,goal_id) REFERENCES reference_release_goal_heads_v1)""")
        for table in TABLES:
            name = sql.Identifier(table)
            conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(name))
            conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(name))
            conn.execute(sql.SQL("CREATE POLICY release_scope ON {} USING "
                "(tenant=current_setting('app.release_tenant',true)) WITH CHECK "
                "(tenant=current_setting('app.release_tenant',true))").format(name))
            conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
            conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(name, sql.Identifier(runtime_role)))
        # PostgreSQL requires an UPDATE privilege for SELECT FOR SHARE. The
        # single checked anchor column carries no ownership or grant authority.
        conn.execute(sql.SQL("GRANT UPDATE(lock_anchor) ON reference_release_goal_heads_v1 TO {}")
                     .format(sql.Identifier(runtime_role)))
        conn.execute(sql.SQL("GRANT INSERT ON reference_release_links_v1 TO {}")
                     .format(sql.Identifier(runtime_role)))


@contextmanager
def _scoped(pool, tenant):
    if not isinstance(tenant, str) or not tenant.strip():
        raise ReleaseLinkRefused("explicit tenant required")
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.release_tenant',%s,true)", (tenant,))
        conn.execute("SET LOCAL lock_timeout='5s'")
        conn.execute("SET LOCAL statement_timeout='10s'")
        yield conn


def _payload(row):
    if row is None:
        return None
    expected, value = row
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict) or digest_hex(value) != expected:
        raise ReleaseLinkRefused("retained release-link state failed integrity")
    return value


def _goal_on(conn, tenant, goal_id):
    row = conn.execute(
        "SELECT payload_digest,payload FROM reference_release_goal_versions_v1 "
        "WHERE tenant=%s AND goal_id=%s ORDER BY version DESC LIMIT 1", (tenant, goal_id),
    ).fetchone()
    value = _payload(row)
    if value is None:
        raise ReleaseLinkRefused("retained goal is unavailable")
    try:
        goal = GoalReleaseBinding(**value)
    except (TypeError, ValueError) as exc:
        raise ReleaseLinkRefused("retained goal is malformed") from exc
    if (goal.tenant, goal.goal_id) != (tenant, goal_id):
        raise ReleaseLinkRefused("retained goal binding differs")
    return goal


def provision_release_goal(owner, goal, *, expected_digest=None):
    """Append an owner-provisioned synthetic goal version with explicit CAS.

    No caller-facing route may receive this owner pool. This does not issue a
    signed review, release grant or effect permit.
    """
    if not isinstance(goal, GoalReleaseBinding):
        raise ValueError("typed host goal required")
    with _scoped(owner, goal.tenant) as conn:
        conn.execute("INSERT INTO reference_release_goal_heads_v1(tenant,goal_id) "
                     "VALUES(%s,%s) ON CONFLICT DO NOTHING", (goal.tenant, goal.goal_id))
        conn.execute("SELECT lock_anchor FROM reference_release_goal_heads_v1 "
                     "WHERE tenant=%s AND goal_id=%s FOR UPDATE", (goal.tenant, goal.goal_id)).fetchone()
        latest = conn.execute("SELECT version,payload_digest FROM reference_release_goal_versions_v1 "
            "WHERE tenant=%s AND goal_id=%s ORDER BY version DESC LIMIT 1",
            (goal.tenant, goal.goal_id)).fetchone()
        if (None if latest is None else latest[1]) != expected_digest:
            raise ReleaseLinkRefused("goal version changed before provisioning")
        body = asdict(goal)
        fingerprint = digest_hex(body)
        if latest is not None and fingerprint == latest[1]:
            return fingerprint
        conn.execute("INSERT INTO reference_release_goal_versions_v1 "
            "(tenant,goal_id,version,payload_digest,payload) VALUES(%s,%s,%s,%s,%s::jsonb)",
            (goal.tenant, goal.goal_id, 0 if latest is None else int(latest[0])+1,
             fingerprint, json.dumps(body)))
        return fingerprint


def _link(value):
    if value is None:
        return None
    try:
        if set(value) != {"request", "goal", "review"}:
            raise ValueError("link fields differ")
        review = dict(value["review"])
        review["authority"] = ReleaseAuthorityBinding(**review["authority"])
        return ReleaseLink(ReleaseLinkRequest(**value["request"]),
            GoalReleaseBinding(**value["goal"]), VerifiedReleaseBinding(**review))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseLinkRefused("retained release link is malformed") from exc


class PostgresGoalReleaseStore:
    """Task+review link is one immutable row; no unlinked task is published."""

    def __init__(self, *, pool):
        self.pool = pool

    @staticmethod
    def _lock_goal(conn, tenant, request):
        row = conn.execute("SELECT lock_anchor FROM reference_release_goal_heads_v1 "
            "WHERE tenant=%s AND goal_id=%s FOR SHARE", (tenant, request.goal_id)).fetchone()
        if row is None:
            raise ReleaseLinkRefused("retained goal head is unavailable")

    def read(self, tenant, request):
        with _scoped(self.pool, tenant) as conn:
            self._lock_goal(conn, tenant, request)
            return _goal_on(conn, tenant, request.goal_id)

    def transact(self, tenant, request, mutation):
        with _scoped(self.pool, tenant) as conn:
            self._lock_goal(conn, tenant, request)
            goal = _goal_on(conn, tenant, request.goal_id)
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                ("reference-release-link:" + digest_hex([tenant, request.goal_id, request.task_id]),))
            old = conn.execute("SELECT payload_digest,payload FROM reference_release_links_v1 "
                "WHERE tenant=%s AND goal_id=%s AND task_id=%s",
                (tenant, request.goal_id, request.task_id)).fetchone()
            existing = _link(_payload(old))
            proposed = mutation(goal, existing, conn)
            if (not isinstance(proposed, ReleaseLink) or proposed.request != request
                    or proposed.goal != goal or goal.tenant != tenant):
                raise ReleaseLinkRefused("publication differs from locked goal and request")
            if existing is not None:
                if proposed != existing:
                    raise ReleaseLinkRefused("task already binds a different release link")
                return existing
            body = asdict(proposed)
            conn.execute("INSERT INTO reference_release_links_v1 "
                "(tenant,goal_id,task_id,payload_digest,payload) VALUES(%s,%s,%s,%s,%s::jsonb)",
                (tenant, request.goal_id, request.task_id, digest_hex(body), json.dumps(body)))
            return proposed

    def retained(self, tenant, request):
        """Observation only: a retained row is not current authority or a permit."""
        with _scoped(self.pool, tenant) as conn:
            row = conn.execute("SELECT payload_digest,payload FROM reference_release_links_v1 "
                "WHERE tenant=%s AND goal_id=%s AND task_id=%s",
                (tenant, request.goal_id, request.task_id)).fetchone()
            return _link(_payload(row))
