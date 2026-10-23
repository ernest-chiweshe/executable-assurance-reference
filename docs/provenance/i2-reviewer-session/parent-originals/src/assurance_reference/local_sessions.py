"""Password-backed local fixture identities and durable, revocable sessions.

This is an isolated reference driver, not deployed IAM. A provisioning service
owns account creation. Authentication grants no reviewer role; certificates and
the signed policy supply that authority separately. No bearer token is retained.
"""

from contextlib import contextmanager
import hashlib
import hmac
import secrets

import psycopg
from psycopg import sql

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable
from regulated_core.identity_provider import IdentitySubject

ITERATIONS = 600_000


def provision_sessions(owner):
    with owner.connection() as conn, conn.transaction():
        conn.execute("""CREATE TABLE reference_identities_v1 (
            tenant text NOT NULL, principal text NOT NULL, username text NOT NULL,
            salt bytea NOT NULL, password_hash bytea NOT NULL, active boolean NOT NULL,
            lock_anchor boolean NOT NULL DEFAULT false CHECK(lock_anchor=false),
            PRIMARY KEY(tenant,principal), UNIQUE(tenant,username))""")
        conn.execute("""CREATE TABLE reference_sessions_v1 (
            tenant text NOT NULL, reference text NOT NULL, principal text NOT NULL,
            expires_at_us bigint NOT NULL, revoked boolean NOT NULL DEFAULT false,
            lock_anchor boolean NOT NULL DEFAULT false CHECK(lock_anchor=false),
            PRIMARY KEY(tenant,reference), FOREIGN KEY(tenant,principal)
            REFERENCES reference_identities_v1(tenant,principal))""")
        for table in ("reference_identities_v1", "reference_sessions_v1"):
            conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(table)))
            conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(sql.Identifier(table)))
            conn.execute(sql.SQL("CREATE POLICY tenant_scope ON {} USING "
                "(tenant=current_setting('app.tenant',true)) WITH CHECK "
                "(tenant=current_setting('app.tenant',true))").format(sql.Identifier(table)))


def _scope(conn, tenant):
    if not isinstance(tenant, str) or not tenant.strip():
        raise SessionRefused("tenant is required")
    conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
    conn.execute("SET LOCAL lock_timeout='5s'")
    conn.execute("SET LOCAL statement_timeout='10s'")


def _digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


class LocalSessions:
    provider_backed = False

    def __init__(self, *, reader, issuer, clock):
        self.reader, self.issuer, self.clock = reader, issuer, clock

    def provision_identity(self, tenant, principal, username, password):
        """Explicit fixture bootstrap using the identity issuer login, never a request route."""
        if any(not isinstance(v, str) or not v.strip() for v in (tenant, principal, username)):
            raise ValueError("explicit identity fields required")
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ValueError("fixture password length must be between 12 and 1024")
        salt = secrets.token_bytes(32)
        with self.issuer.connection() as conn, conn.transaction():
            _scope(conn, tenant)
            conn.execute("INSERT INTO reference_identities_v1 "
                         "(tenant,principal,username,salt,password_hash,active) VALUES(%s,%s,%s,%s,%s,true)",
                         (tenant, principal, username, salt, _digest(password, salt)))

    def login(self, tenant, username, password, *, ttl_us=300_000_000):
        if type(ttl_us) is not int or not 0 < ttl_us <= 3_600_000_000:
            raise ValueError("session lifetime must be positive and at most one hour")
        if not isinstance(password, str) or len(password) > 1024:
            raise SessionRefused("authentication refused")
        try:
            with self.issuer.connection() as conn, conn.transaction():
                _scope(conn, tenant)
                row = conn.execute("SELECT principal,salt,password_hash,active FROM reference_identities_v1 "
                                   "WHERE tenant=%s AND username=%s FOR SHARE", (tenant, username)).fetchone()
                expected = bytes(row[2]) if row else bytes(32)
                salt = bytes(row[1]) if row else bytes(32)
                correct = hmac.compare_digest(_digest(password, salt), expected)
                if not row or not correct or row[3] is not True:
                    raise SessionRefused("authentication refused")
                token = secrets.token_urlsafe(48)
                reference = hashlib.sha256(token.encode()).hexdigest()
                expires = self.clock.now_us() + ttl_us
                conn.execute("INSERT INTO reference_sessions_v1 "
                             "(tenant,reference,principal,expires_at_us,revoked) VALUES(%s,%s,%s,%s,false)",
                             (tenant, reference, row[0], expires))
            return token
        except psycopg.Error as error:
            raise SessionUnavailable("session issuance unavailable") from error

    def authenticate(self, tenant, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 1024:
            raise SessionRefused("authentication refused")
        reference = hashlib.sha256(token.encode()).hexdigest()
        try:
            with self.reader.connection() as conn, conn.transaction():
                _scope(conn, tenant)
                row = conn.execute("SELECT s.principal,i.username,s.expires_at_us FROM reference_sessions_v1 s "
                    "JOIN reference_identities_v1 i USING(tenant,principal) "
                    "WHERE s.tenant=%s AND s.reference=%s AND NOT s.revoked AND i.active",
                    (tenant, reference)).fetchone()
                if row is None or self.clock.now_us() >= row[2]:
                    raise SessionRefused("authentication refused")
                return AuthenticatedSession(tenant, row[0], row[1], reference, row[2])
        except psycopg.Error as error:
            raise SessionUnavailable("authentication unavailable") from error

    def resolve(self, subject_id, tenant):
        try:
            with self.reader.connection() as conn, conn.transaction():
                _scope(conn, tenant)
                row = conn.execute("SELECT username,active FROM reference_identities_v1 "
                                   "WHERE tenant=%s AND principal=%s", (tenant, subject_id)).fetchone()
                return IdentitySubject(subject_id, tenant, row[0], row[1]) if row else None
        except psycopg.Error as error:
            raise SessionUnavailable("identity unavailable") from error

    def revoke(self, identity):
        try:
            with self.issuer.connection() as conn, conn.transaction():
                _scope(conn, identity.tenant)
                conn.execute("UPDATE reference_sessions_v1 SET revoked=true WHERE tenant=%s AND reference=%s",
                             (identity.tenant, identity.reference))
        except psycopg.Error as error:
            raise SessionUnavailable("revocation unconfirmed") from error

    @contextmanager
    def admit(self, identity, *, not_after_us=None):
        if not isinstance(identity, AuthenticatedSession):
            raise SessionRefused("authenticated session required")
        if not_after_us is not None and (type(not_after_us) is not int or not_after_us <= 0):
            raise SessionRefused("positive effect deadline required")
        try:
            with self.reader.connection() as conn, conn.transaction():
                _scope(conn, identity.tenant)
                # Identity first, then session: updates/revocations serialize
                # with the receiving operation through its final effect check.
                account = conn.execute("SELECT username,active FROM reference_identities_v1 "
                    "WHERE tenant=%s AND principal=%s FOR SHARE", (identity.tenant, identity.principal)).fetchone()
                session = conn.execute("SELECT principal,expires_at_us,revoked FROM reference_sessions_v1 "
                    "WHERE tenant=%s AND reference=%s FOR SHARE", (identity.tenant, identity.reference)).fetchone()
                if (account != (identity.username, True) or session is None
                        or session != (identity.principal, identity.expires_at_us, False)):
                    raise SessionRefused("session authority changed")
                deadline = min(identity.expires_at_us, not_after_us or identity.expires_at_us)
                active = True

                def current():
                    if not active:
                        raise SessionRefused("session admission has ended")
                    try:
                        now = self.clock.now_us()
                    except Exception as error:
                        raise SessionUnavailable("session time unavailable") from error
                    if now >= deadline:
                        raise SessionRefused("session or effect deadline expired")

                try:
                    current()
                    yield current
                finally:
                    active = False
        except psycopg.Error as error:
            raise SessionUnavailable("session admission unavailable; reconcile any attempted effect") from error
