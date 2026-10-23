"""Session-bound choreography state using the unchanged pinned Project OS store.

This state records workflow progress, not authority. Signed decisions and target
receipts remain authoritative. The pool is host-owned, never given to a caller.
"""

from contextlib import contextmanager

from factory.projectos.pg_store import POSTGRES_SCHEMA, PostgresProjectStateStore
from assurance_reference.session_credentials import AuthenticatedSession


def provision_project_state(owner):
    """Explicit migration only; ordinary construction cannot create storage."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(POSTGRES_SCHEMA)
        conn.execute("ALTER TABLE projectos_states ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE projectos_states FORCE ROW LEVEL SECURITY")
        conn.execute("CREATE POLICY project_scope ON projectos_states USING "
                     "(tenant_id=current_setting('app.tenant',true) AND "
                     "namespace=current_setting('app.project_namespace',true)) WITH CHECK "
                     "(tenant_id=current_setting('app.tenant',true) AND "
                     "namespace=current_setting('app.project_namespace',true))")


class SessionProjectPool:
    """Bind each operation to an admitted session and host-selected namespace.

    Session row locks cover the complete state transaction. No implicit schema
    creation, alternate login or caller-selected tenant is available here.
    RLS trusts these host-set transaction settings; it is not OS isolation from
    a process which already possesses this database login.
    """

    def __init__(self, *, pool, sessions, authenticated, namespace):
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("project state requires an authenticated session")
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("an explicit project namespace is required")
        self.pool, self.sessions = pool, sessions
        self.authenticated, self.namespace = authenticated, namespace.strip()

    @contextmanager
    def connection(self):
        with self.sessions.admit(self.authenticated) as current:
            current()
            with self.pool.connection() as conn, conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (self.authenticated.tenant,))
                conn.execute("SELECT set_config('app.project_namespace',%s,true)", (self.namespace,))
                conn.execute("SET LOCAL lock_timeout='5s'")
                conn.execute("SET LOCAL statement_timeout='10s'")
                yield conn
                current()


def compose_project_state(*, pool, sessions, authenticated, namespace):
    bound = SessionProjectPool(pool=pool, sessions=sessions, authenticated=authenticated,
                               namespace=namespace)
    return PostgresProjectStateStore("", namespace=bound.namespace,
        tenant_id=authenticated.tenant, ensure_schema=False, pool=bound)
