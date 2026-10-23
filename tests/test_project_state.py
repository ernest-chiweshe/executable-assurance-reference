"""Durable choreography under its own login, session and tenant namespace."""

from types import SimpleNamespace
import uuid

import psycopg
import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.project_state import compose_project_state
from assurance_reference.session_credentials import SessionRefused, SessionUnavailable
from factory.projectos.errors import ProjectEngineError
from regulated_core.clock_pg import DbClock
from test_local_roles import roles  # noqa: F401

# Imported pytest fixture and arguments deliberately have the same name.
# ruff: noqa: F811


@pytest.fixture
def project_case(roles):
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    principal = "author-" + uuid.uuid4().hex
    sessions.provision_identity("school-a", principal, principal, "fictional-password-001")
    identity = sessions.authenticate("school-a", sessions.login("school-a", principal, "fictional-password-001"))
    def store(namespace="education", authenticated=identity):
        return compose_project_state(pool=roles.project_state, sessions=sessions,
                                     authenticated=authenticated, namespace=namespace)
    return SimpleNamespace(roles=roles, sessions=sessions, identity=identity, store=store,
                           project="lesson-" + uuid.uuid4().hex)


def test_reconstruction_and_stale_writer_refusal_preserve_latest_state(project_case):
    c = project_case
    first, second = c.store(), c.store()
    first.create(c.project, {"body": "first"})
    assert second.load(c.project) == {"body": "first"}
    first.save(c.project, {"body": "second"})
    with pytest.raises(ProjectEngineError, match="changed concurrently"):
        second.save(c.project, {"body": "stale"})
    assert c.store().load(c.project) == {"body": "second"}
    with pytest.raises(ProjectEngineError, match="must be loaded"):
        c.store().save(c.project, {"body": "unobserved"})


def test_tenant_namespace_and_unscoped_sql_visibility(project_case):
    c = project_case
    a = c.store()
    a.create(c.project, {"body": "school-a education"})
    with pytest.raises(ProjectEngineError, match="no project"):
        c.store("health").load(c.project)
    other = "other-" + uuid.uuid4().hex
    c.sessions.provision_identity("school-b", other, other, "fictional-password-002")
    identity = c.sessions.authenticate("school-b", c.sessions.login("school-b", other, "fictional-password-002"))
    b = c.store(authenticated=identity)
    with pytest.raises(ProjectEngineError, match="no project"):
        b.load(c.project)
    b.create(c.project, {"body": "school-b education"})
    assert a.load(c.project)["body"] == "school-a education"
    assert b.load(c.project)["body"] == "school-b education"
    with c.roles.project_state.connection() as conn:
        assert conn.execute("SELECT count(*) FROM projectos_states").fetchone() == (0,)
    # Bypass the store's SQL WHERE only, keeping database RLS intact.
    with a._pool.connection() as conn:
        assert conn.execute("SELECT count(*) FROM projectos_states WHERE tenant_id='school-b'").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("INSERT INTO projectos_states VALUES ('school-b','education','invalid',1,'{}',now())")


def test_revoked_session_cannot_read_or_save_project(project_case):
    c = project_case
    state = c.store()
    state.create(c.project, {"body": "retained"})
    c.sessions.revoke(c.identity)
    with pytest.raises(SessionRefused):
        state.load(c.project)
    with pytest.raises(SessionRefused):
        state.save(c.project, {"body": "changed"})


def test_project_role_has_no_authority_writer_or_delete_privileges(project_case):
    c = project_case
    state = c.store()
    state.create(c.project, {"body": "retained"})
    with pytest.raises(SessionUnavailable) as refusal:
        state.delete(c.project)
    assert isinstance(refusal.value.__cause__, psycopg.errors.InsufficientPrivilege)
    with c.roles.project_state.connection() as conn:
        for table in ("regulated_decision_evidence_v1", "regulated_permit_uses_v1",
                      "reference_alerts_v1", "reference_sessions_v1", "regulated_reviews_v1"):
            assert not conn.execute("SELECT has_table_privilege(session_user,%s,'INSERT,UPDATE,DELETE,TRUNCATE')",
                                    (table,)).fetchone()[0]
    with c.roles.receiver.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM projectos_states")
