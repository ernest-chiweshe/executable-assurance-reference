"""Tenant-scoped Education authority stores over the pinned collection store.

Runtime reading and explicit signed-grant provisioning use separate logins.
RLS trusts host-set tenant context; both reader and provisioning passwords are
trusted host material, not process isolation. Construction never changes grants.
"""

from contextlib import contextmanager, nullcontext

from assurance_reference.session_credentials import AuthenticatedSession
from factory.packs.collections import PostgresPackCollectionStore
from factory.pg_session import SessionBoundPool


def provision_education_authority(owner):
    """Migrate fresh isolated storage before granting runtime privileges."""
    PostgresPackCollectionStore("", pool=owner).migrate()
    with owner.connection() as conn, conn.transaction():
        conn.execute("ALTER TABLE pack_documents ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE pack_documents FORCE ROW LEVEL SECURITY")
        conn.execute("CREATE POLICY education_scope ON pack_documents USING "
            "(tenant_id=current_setting('app.education_tenant',true) AND "
            "pack_id='lumiwright.education.formative-feedback' AND "
            "collection IN ('roster-user','reviewer-appointment')) WITH CHECK "
            "(tenant_id=current_setting('app.education_tenant',true) AND "
            "pack_id='lumiwright.education.formative-feedback' AND "
            "collection IN ('roster-user','reviewer-appointment'))")


class _TenantPool:
    def __init__(self, pool, tenant, *, sessions=None, authenticated=None):
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("explicit Education tenant required")
        self.pool, self.tenant = pool, tenant
        self.sessions, self.authenticated = sessions, authenticated

    @contextmanager
    def connection(self):
        admission = (self.sessions.admit(self.authenticated)
                     if self.sessions is not None else nullcontext(None))
        with admission as current:
            if current is not None:
                current()
            with self.pool.connection() as conn:
                # Original authority guards hold one session across several
                # independently committed store transactions. An outer database
                # transaction here would alter that durability contract.
                conn.execute("SELECT set_config('app.education_tenant',%s,false)", (self.tenant,))
                conn.execute("SET lock_timeout='5s'")
                conn.execute("SET statement_timeout='10s'")
                try:
                    yield conn
                    if current is not None:
                        current()
                finally:
                    if not conn.closed:
                        conn.rollback()
                        conn.execute("RESET app.education_tenant")
                        conn.execute("RESET lock_timeout")
                        conn.execute("RESET statement_timeout")


def compose_education_reader(*, pool, sessions, authenticated):
    if (not isinstance(authenticated, AuthenticatedSession)
            or not callable(getattr(sessions, "admit", None))):
        raise ValueError("Education authority reads require an authenticated session")
    return PostgresPackCollectionStore("", pool=SessionBoundPool(_TenantPool(
        pool, authenticated.tenant, sessions=sessions, authenticated=authenticated)))


def compose_education_provisioner(*, pool, tenant):
    """Host-only fixture/operator composition; never expose this login to requests.

    The caller must invoke the original signed enrollment/appointment provisioner.
    The database login can mutate authority rows and remains trusted local setup.
    """
    return PostgresPackCollectionStore("", pool=SessionBoundPool(_TenantPool(pool, tenant)))
