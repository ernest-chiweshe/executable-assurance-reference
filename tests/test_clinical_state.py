"""Consultation persistence under real session, owner RLS and runtime-role checks."""

from dataclasses import replace
from types import SimpleNamespace

import psycopg
import pytest

from assurance_reference.clinical_state import RetainedClinicalStore
from factory.health_ui.documents import (FINALISATION_PENDING, FINALISATION_UNKNOWN,
    Finalisation, Session, build_document)
from factory.health_ui.store import StaleSession, StoreDegraded
from factory.health_ui.templates import MEDICO_LEGAL
from test_clinical_sessions import clinical_session  # noqa: F401
from test_local_roles import roles  # noqa: F401

# pytest resolves these imported fixtures by name.
# ruff: noqa: F811


@pytest.fixture
def case(clinical_session, roles):
    c = clinical_session
    def store(authenticated=c.authenticated):
        return RetainedClinicalStore(pool=roles.project_state, sessions=c.sessions, authenticated=authenticated)
    identity = c.bridge.identity
    document = build_document(MEDICO_LEGAL, "Fictional retained case", "fixture", "fixture", [])
    session = Session("case-fixture", "Fictional clinician", "Fixture", "fixture",
        "2026-10-14T00:00:00+00:00", owner_id=identity.owner_id,
        workspace_id=identity.workspace_id, documents=[document])
    return SimpleNamespace(auth=c, roles=roles, store=store, session=session)


def test_consultation_reconstructs_and_stale_copy_cannot_overwrite(case):
    c = case
    c.store().save(c.session)
    assert c.session.revision == 1
    a = c.store().get(c.session.session_id, c.session.owner_id)
    b = c.store().get(c.session.session_id, c.session.owner_id)
    a.title = "New retained version"
    c.store().save(a)
    assert a.revision == 2
    b.title = "Stale version"
    with pytest.raises(StaleSession):
        c.store().save(b)
    found = c.store().list_for(c.session.owner_id)
    assert len(found) == 1 and found[0].title == "New retained version"
    assert found[0].revision == 2


def test_another_authenticated_clinician_cannot_read_or_write_case(case):
    c = case
    c.store().save(c.session)
    sessions, tenant = c.auth.sessions, c.auth.authenticated.tenant
    sessions.provision_identity(tenant, "other-clinician", "other.clinician", "fictional-password-001")
    other = sessions.authenticate(tenant, sessions.login(tenant, "other.clinician", "fictional-password-001"))
    other_store = c.store(other)
    assert other_store.get(c.session.session_id, c.session.owner_id) is None
    assert other_store.list_for(c.session.owner_id) == []
    with pytest.raises(StoreDegraded, match="belong"):
        other_store.save(c.session)
    # Even the same consultation id has no visibility under the other owner.
    assert other_store.get(c.session.session_id, tenant + ":other-clinician") is None


def test_runtime_rls_requires_session_selected_workspace_and_clinician(case):
    c = case
    c.store().save(c.session)
    with c.roles.project_state.connection() as conn, conn.transaction():
        assert conn.execute("SELECT count(*) FROM reference_clinical_state_v1").fetchone() == (0,)
        conn.execute("SELECT set_config('app.tenant',%s,true)", (c.session.workspace_id,))
        conn.execute("SELECT set_config('app.project_namespace','health',true)")
        conn.execute("SELECT set_config('app.clinician','other-clinician',true)")
        assert conn.execute("SELECT count(*) FROM reference_clinical_state_v1").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO reference_clinical_state_v1 "
                         "(workspace_id,owner_id,session_id,revision,record_digest,payload) "
                         "VALUES (%s,%s,'foreign',1,'fixture','{}')",
                         (c.session.workspace_id, c.session.owner_id))
    for pool in (c.roles.receiver, c.roles.recorder, c.roles.session_reader):
        with pool.connection() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("SELECT * FROM reference_clinical_state_v1")


def test_revoked_session_cannot_read_or_save_consultation(case):
    c = case
    c.store().save(c.session)
    c.auth.sessions.revoke(c.auth.authenticated)
    with pytest.raises(StoreDegraded, match="session refused"):
        c.store().get(c.session.session_id, c.session.owner_id)
    with pytest.raises(StoreDegraded, match="session refused"):
        c.store().save(replace(c.session, title="Refused mutation"))


def test_owner_change_is_refused_and_unsigned_owner_deletion_is_retained(case):
    c = case
    with pytest.raises(StoreDegraded, match="belong"):
        c.store().save(replace(c.session, workspace_id="different-workspace"))
    c.store().save(c.session)
    with c.roles.project_state.connection() as conn:
        assert conn.execute("SELECT has_table_privilege(session_user,'reference_clinical_state_v1','DELETE')").fetchone() == (False,)
    assert c.store().delete(c.session.session_id, "foreign-owner") is False
    assert c.store().delete("missing", c.session.owner_id) is False
    assert c.store().delete(c.session.session_id, c.session.owner_id) is True
    assert c.store().get(c.session.session_id, c.session.owner_id) is None
    assert c.store().list_for(c.session.owner_id) == []
    assert c.store().delete(c.session.session_id, c.session.owner_id) is False
    with pytest.raises(StaleSession):
        c.store().save(c.session)
    with c.store()._connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_clinical_state_v1").fetchone() == (0,)
        assert conn.execute("SELECT revision FROM reference_clinical_removals_v1").fetchall() == [(2,)]
        assert conn.execute("SELECT has_table_privilege(session_user,'reference_clinical_removals_v1',"
                            "'UPDATE,DELETE,TRUNCATE')").fetchone() == (False,)


@pytest.mark.parametrize("status", [FINALISATION_PENDING, FINALISATION_UNKNOWN])
def test_unsettled_finalisation_cannot_be_removed(case, status):
    c = case
    document = c.session.documents[0]
    # Synthetic retained observation; no effect is executed to create a fault.
    document.finalisation = Finalisation(status, document.digest(), "1" * 64, "1" * 64,
        "Fictional clinician", "2026-10-14T00:00:00+00:00", "fixture-pending",
        c.auth.clock.now_us())
    c.store().save(c.session)
    with pytest.raises(PermissionError, match="frozen document"):
        c.store().delete(c.session.session_id, c.session.owner_id)
    stored = c.store().get(c.session.session_id, c.session.owner_id)
    assert stored is not None and stored.revision == 1
    assert stored.documents[0].finalisation.state == status
    assert len(c.store().list_for(c.session.owner_id)) == 1
    with c.store()._connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_clinical_removals_v1").fetchone() == (0,)
