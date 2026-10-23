"""Reuse one real restricted connection across admitted tenant operations.

The fixture changes connection reuse only. Session admission, signed Education
provisioning, original stores and all RLS policies remain active. These tests
cover scope cleanup, not every table or a complete application release.
"""

from contextlib import contextmanager, nullcontext

from psycopg.pq import TransactionStatus
import pytest

from assurance_reference.clinical_state import RetainedClinicalStore
from assurance_reference.education_authority_store import compose_education_reader
from assurance_reference.project_state import compose_project_state
from factory.health_ui.documents import Session, build_document
from factory.health_ui.templates import MEDICO_LEGAL
from factory.packs.examples import EDUCATION_ID
from test_education_authority_store import school  # noqa: F401

# pytest resolves the imported fixture by name.
# ruff: noqa: F811


class InterruptedOperation(RuntimeError):
    pass


class ReusedConnection:
    """Borrow one already-owned runtime connection without resetting its state."""

    def __init__(self, connection):
        self.connection_handle = connection

    @contextmanager
    def connection(self):
        yield self.connection_handle


def assert_idle_unscoped(conn, *settings):
    assert conn.info.transaction_status == TransactionStatus.IDLE
    for setting in settings:
        assert conn.execute("SELECT current_setting(%s,true)", (setting,)).fetchone()[0] in (None, "")


@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("namespace", ["education", "health", "product-spec"])
def test_project_scope_clears_before_next_tenant_on_same_connection(school, namespace, interrupted):
    s = school
    project = "reused-connection-fixture"
    # Use the unchanged original store to seed lawful independent tenant rows.
    for tenant, identity in s.identities.items():
        store = compose_project_state(pool=s.roles.project_state, sessions=s.sessions,
                                      authenticated=identity, namespace=namespace)
        store.create(project, {"fixture_tenant": tenant})
    with s.roles.project_state.connection() as conn:
        backend = conn.info.backend_pid
        reused = ReusedConnection(conn)
        for tenant in ("school-a", "school-b", "school-a"):
            store = compose_project_state(pool=reused, sessions=s.sessions,
                authenticated=s.identities[tenant], namespace=namespace)
            assert store.load(project) == {"fixture_tenant": tenant}
            assert_idle_unscoped(conn, "app.tenant", "app.project_namespace")
            expectation = pytest.raises(InterruptedOperation) if interrupted else nullcontext()
            with expectation:
                with store._pool.connection() as scoped:
                    assert scoped.info.backend_pid == backend
                    assert scoped.execute("SELECT tenant_id,namespace,state FROM projectos_states").fetchall() == [
                        (tenant, namespace, {"fixture_tenant": tenant})]
                    if interrupted:
                        raise InterruptedOperation("fixture operation interrupted after scoped read")
            assert conn.info.backend_pid == backend
            assert_idle_unscoped(conn, "app.tenant", "app.project_namespace")
            assert conn.execute("SELECT count(*) FROM projectos_states").fetchone() == (0,)
        # All observations were reads; every lawful stored row remains unchanged.
        for tenant, identity in s.identities.items():
            store = compose_project_state(pool=reused, sessions=s.sessions,
                                          authenticated=identity, namespace=namespace)
            assert store.load(project) == {"fixture_tenant": tenant}


@pytest.mark.parametrize("interrupted", [False, True])
def test_signed_education_reads_clear_scope_and_timeouts_on_reused_connection(school, interrupted):
    s = school
    with s.roles.education_reader.connection() as conn:
        backend = conn.info.backend_pid
        timeouts = conn.execute("SELECT current_setting('lock_timeout'),current_setting('statement_timeout')").fetchone()
        reused = ReusedConnection(conn)
        for tenant in ("school-a", "school-b", "school-a"):
            reader = compose_education_reader(pool=reused, sessions=s.sessions,
                                             authenticated=s.identities[tenant])
            doc = s.documents[tenant]
            assert reader.get(EDUCATION_ID, "roster-user", tenant, doc.key) == doc
            assert_idle_unscoped(conn, "app.education_tenant")
            expectation = pytest.raises(InterruptedOperation) if interrupted else nullcontext()
            with expectation:
                with reader._pool.session() as scoped:
                    assert scoped.info.backend_pid == backend
                    assert scoped.execute("SELECT DISTINCT tenant_id FROM pack_documents").fetchall() == [(tenant,)]
                    if interrupted:
                        raise InterruptedOperation("fixture operation interrupted after scoped read")
            assert conn.info.backend_pid == backend
            assert_idle_unscoped(conn, "app.education_tenant")
            assert conn.execute("SELECT count(*) FROM pack_documents").fetchone() == (0,)
            assert conn.execute("SELECT current_setting('lock_timeout'),current_setting('statement_timeout')").fetchone() == timeouts


@pytest.mark.parametrize("interrupted", [False, True])
def test_consultation_owner_and_workspace_clear_on_reused_connection(school, interrupted):
    s = school
    s.sessions.provision_identity("school-a", "other-clinician", "other.clinician", "fictional-password-002")
    other = s.sessions.authenticate("school-a", s.sessions.login(
        "school-a", "other.clinician", "fictional-password-002"))
    identities = [s.identities["school-a"], other, s.identities["school-b"]]
    # These are private fictional consultations, not clinical qualifications or
    # released documents. The same consultation id exists under all three owners.
    for identity in identities:
        store = RetainedClinicalStore(pool=s.roles.project_state, sessions=s.sessions,
                                      authenticated=identity)
        consultation = Session("scope-fixture", "Fictional clinician", "Private fixture", "fixture",
            "2026-10-15T00:00:00+00:00", owner_id=identity.tenant + ":" + identity.principal,
            workspace_id=identity.tenant, documents=[build_document(
                MEDICO_LEGAL, "Fictional scope case", "fixture", "fixture", [])])
        store.save(consultation)
    with s.roles.project_state.connection() as conn:
        backend = conn.info.backend_pid
        reused = ReusedConnection(conn)
        for identity in [*identities, identities[0]]:
            owner = identity.tenant + ":" + identity.principal
            store = RetainedClinicalStore(pool=reused, sessions=s.sessions, authenticated=identity)
            found = store.get("scope-fixture", owner)
            assert found is not None and found.owner_id == owner and found.revision == 1
            assert_idle_unscoped(conn, "app.tenant", "app.project_namespace", "app.clinician")
            expectation = pytest.raises(InterruptedOperation) if interrupted else nullcontext()
            with expectation:
                with store._connection() as scoped:
                    assert scoped.info.backend_pid == backend
                    assert scoped.execute(
                        "SELECT workspace_id,owner_id,session_id,revision FROM reference_clinical_state_v1"
                    ).fetchall() == [(identity.tenant, owner, "scope-fixture", 1)]
                    if interrupted:
                        raise InterruptedOperation("fixture consultation read interrupted")
            assert conn.info.backend_pid == backend
            assert_idle_unscoped(conn, "app.tenant", "app.project_namespace", "app.clinician")
            assert conn.execute("SELECT count(*) FROM reference_clinical_state_v1").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM reference_clinical_removals_v1").fetchone() == (0,)
