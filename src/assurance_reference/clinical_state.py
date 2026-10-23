"""Retained consultation state under the restricted application-state login.

The original Health document parser and canonical encoding remain authoritative
for the payload shape. This storage adapter adds session-bound tenant/owner RLS
and a database compare-and-set; it does not grant clinical release authority.
"""

from contextlib import contextmanager
import copy
import json
import re

import psycopg

from assurance_reference.project_state import SessionProjectPool
from assurance_reference.session_credentials import SessionRefused, SessionUnavailable
from factory.health_ui.store import StaleSession, StoreDegraded, _canonical_bytes, _digest, _encode, _session


def provision_clinical_state(owner):
    """Explicit local migration; never called by ordinary store construction."""
    with owner.connection() as conn, conn.transaction():
        conn.execute("""CREATE TABLE reference_clinical_state_v1 (
            workspace_id text NOT NULL, owner_id text NOT NULL, session_id text NOT NULL,
            revision bigint NOT NULL CHECK (revision > 0), record_digest text NOT NULL,
            payload jsonb NOT NULL, tombstoned boolean NOT NULL DEFAULT false,
            PRIMARY KEY(workspace_id,owner_id,session_id))""")
        conn.execute("ALTER TABLE reference_clinical_state_v1 ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE reference_clinical_state_v1 FORCE ROW LEVEL SECURITY")
        predicate = ("workspace_id=current_setting('app.tenant',true) AND "
                     "owner_id=current_setting('app.tenant',true)||':'||current_setting('app.clinician',true) "
                     "AND current_setting('app.project_namespace',true)='health'")
        # An append-only removal marker controls visibility. PostgreSQL also
        # applies SELECT policies to updated rows, so hiding the row by its
        # newly updated boolean would correctly refuse the tombstone UPDATE.
        # Update the revisioned record first, then append the marker in the
        # same locked transaction. Neither policy is suspended or relaxed.
        conn.execute("""CREATE TABLE reference_clinical_removals_v1 (
            workspace_id text NOT NULL, owner_id text NOT NULL, session_id text NOT NULL,
            revision bigint NOT NULL CHECK(revision > 1),
            PRIMARY KEY(workspace_id,owner_id,session_id),
            FOREIGN KEY(workspace_id,owner_id,session_id)
                REFERENCES reference_clinical_state_v1(workspace_id,owner_id,session_id))""")
        conn.execute("ALTER TABLE reference_clinical_removals_v1 ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE reference_clinical_removals_v1 FORCE ROW LEVEL SECURITY")
        conn.execute("CREATE POLICY clinical_removal_scope ON reference_clinical_removals_v1 USING (" +
                     predicate + ") WITH CHECK (" + predicate + ")")
        visible = ("NOT EXISTS (SELECT 1 FROM reference_clinical_removals_v1 r "
                   "WHERE r.workspace_id=reference_clinical_state_v1.workspace_id "
                   "AND r.owner_id=reference_clinical_state_v1.owner_id "
                   "AND r.session_id=reference_clinical_state_v1.session_id)")
        conn.execute("CREATE POLICY clinical_scope ON reference_clinical_state_v1 USING (" +
                     predicate + " AND " + visible + ") WITH CHECK (" + predicate + ")")


class RetainedClinicalStore:
    """One authenticated clinician's consultations; no caller-selected owner."""

    def __init__(self, *, pool, sessions, authenticated):
        self._pool = SessionProjectPool(pool=pool, sessions=sessions,
                                       authenticated=authenticated, namespace="health")
        self._workspace = authenticated.tenant
        self._owner = authenticated.tenant + ":" + authenticated.principal

    @property
    def degraded(self):
        # As in the original PostgreSQL store, failures surface per operation.
        return False

    @property
    def recovery_required(self):
        return False

    @contextmanager
    def _connection(self):
        try:
            with self._pool.connection() as conn:
                conn.execute("SELECT set_config('app.clinician',%s,true)",
                             (self._pool.authenticated.principal,))
                yield conn
        except (psycopg.Error, SessionRefused, SessionUnavailable) as error:
            raise StoreDegraded("retained clinical state unavailable or session refused") from error

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise StoreDegraded("invalid consultation identifier")

    def _decode(self, row, session_id=None):
        try:
            payload, digest, revision = row
            payload = json.loads(payload) if isinstance(payload, str) else payload
            if _digest(_canonical_bytes(payload)) != digest:
                raise ValueError("record digest differs")
            session = _session(payload)
            self._identifier(session.session_id)
            if ((session.workspace_id, session.owner_id, session.revision)
                    != (self._workspace, self._owner, revision)
                    or (session_id is not None and session.session_id != session_id)):
                raise ValueError("retained consultation binding differs")
            return session
        except (KeyError, TypeError, ValueError) as error:
            raise StoreDegraded("retained consultation failed integrity validation") from error

    def save(self, session):
        self._identifier(session.session_id)
        if ((session.workspace_id, session.owner_id) != (self._workspace, self._owner)
                or type(session.revision) is not int or session.revision < 0):
            raise StoreDegraded("consultation must belong to the authenticated clinician")
        written = copy.deepcopy(session)
        written.revision += 1
        payload = _encode(written)
        encoded = _canonical_bytes(payload)
        digest = _digest(encoded)
        self._decode((payload, digest, written.revision), session.session_id)
        with self._connection() as conn:
            if session.revision == 0:
                row = conn.execute("INSERT INTO reference_clinical_state_v1 "
                    "(workspace_id,owner_id,session_id,revision,record_digest,payload) "
                    "VALUES (%s,%s,%s,1,%s,%s::jsonb) ON CONFLICT DO NOTHING RETURNING revision",
                    (self._workspace, self._owner, session.session_id, digest, encoded.decode())).fetchone()
            else:
                row = conn.execute("UPDATE reference_clinical_state_v1 SET "
                    "revision=revision+1,record_digest=%s,payload=%s::jsonb "
                    "WHERE workspace_id=%s AND owner_id=%s AND session_id=%s AND revision=%s "
                    "RETURNING revision", (digest, encoded.decode(), self._workspace,
                    self._owner, session.session_id, session.revision)).fetchone()
            if row != (written.revision,):
                raise StaleSession("consultation changed or no longer exists; reload and retry")
        session.revision = written.revision

    def get(self, session_id, owner_id):
        self._identifier(session_id)
        if owner_id != self._owner:
            return None
        with self._connection() as conn:
            row = conn.execute("SELECT payload,record_digest,revision FROM reference_clinical_state_v1 "
                "WHERE workspace_id=%s AND owner_id=%s AND session_id=%s",
                (self._workspace, self._owner, session_id)).fetchone()
        return None if row is None else self._decode(row, session_id)

    def list_for(self, owner_id):
        if owner_id != self._owner:
            return []
        with self._connection() as conn:
            rows = conn.execute("SELECT payload,record_digest,revision FROM reference_clinical_state_v1 "
                "WHERE workspace_id=%s AND owner_id=%s ORDER BY session_id",
                (self._workspace, self._owner)).fetchall()
        return [self._decode(row) for row in rows]

    def delete(self, session_id, owner_id):
        """Remove an owned unsigned case from ordinary use, retaining its record.

        The original application's frozen-document refusal remains required;
        this storage boundary checks it again while holding the row lock. No
        SQL DELETE grant or caller-selected workspace is involved.
        """
        self._identifier(session_id)
        if owner_id != self._owner:
            return False
        with self._connection() as conn:
            row = conn.execute("SELECT payload,record_digest,revision FROM reference_clinical_state_v1 "
                "WHERE workspace_id=%s AND owner_id=%s AND session_id=%s FOR UPDATE",
                (self._workspace, self._owner, session_id)).fetchone()
            if row is None:
                return False
            session = self._decode(row, session_id)
            if any(document.is_frozen for document in session.documents):
                raise PermissionError("a consultation containing a frozen document cannot be removed")
            revision = session.revision
            session.revision += 1
            encoded = _canonical_bytes(_encode(session))
            changed = conn.execute("UPDATE reference_clinical_state_v1 SET tombstoned=true, "
                "revision=revision+1,payload=%s::jsonb,record_digest=%s "
                "WHERE workspace_id=%s AND owner_id=%s AND session_id=%s AND revision=%s",
                (encoded.decode(), _digest(encoded), self._workspace, self._owner, session_id, revision))
            if changed.rowcount != 1:
                raise StaleSession("consultation changed while removing it; reload and retry")
            conn.execute("INSERT INTO reference_clinical_removals_v1 "
                "(workspace_id,owner_id,session_id,revision) VALUES (%s,%s,%s,%s)",
                (self._workspace, self._owner, session_id, session.revision))
        return True
