"""B-F7b on lawful two-tenant population: clinical state and clinical removals.

Two fictional clinics, each with its own authenticated clinician, write through the real RetainedClinicalStore on
the restricted project_state login: one consultation kept and one removed per clinic, so both tables hold rows for
both clinics. No administrator seeding. Each clinic's own authenticated connection then sees only its own rows in
both tables, and the other clinic's consultation is neither readable nor removable through the store.
"""
from types import SimpleNamespace
from uuid import uuid4

import pytest

from assurance_reference.clinical_sessions import RetainedClinicalSessions
from assurance_reference.clinical_state import RetainedClinicalStore
from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_sessions import LocalSessions
from factory.health_ui.documents import Session, build_document
from factory.health_ui.templates import MEDICO_LEGAL
from regulated_core.clock_pg import DbClock
from test_local_roles import roles  # noqa: F401

# ruff: noqa: F811


def _clinic(roles, clock, name):
    sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    tenant = f"clinic-{name}-" + uuid4().hex[:8]
    sessions.provision_identity(tenant, "fixture-user", "fixture.user", "fictional-password-001")
    authenticated = sessions.authenticate(tenant, sessions.login(tenant, "fixture.user", "fictional-password-001"))
    identity = RetainedClinicalSessions(sessions, authenticated).identity
    store = RetainedClinicalStore(pool=roles.project_state, sessions=sessions, authenticated=authenticated)

    def session(case_id):
        document = build_document(MEDICO_LEGAL, "Fictional retained case", "fixture", "fixture", [])
        return Session(case_id, "Fictional clinician", "Fixture", "fixture", "2026-10-14T00:00:00+00:00",
                       owner_id=identity.owner_id, workspace_id=identity.workspace_id, documents=[document])

    return SimpleNamespace(tenant=tenant, identity=identity, store=store, session=session)


@pytest.fixture
def two_clinics(roles):
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         recovery_not_used_reason="Synthetic clinical isolation fixture")
    clinics = [_clinic(roles, clock, name) for name in ("a", "b")]
    for clinic in clinics:
        clinic.store.save(clinic.session("kept-case"))
        clinic.store.save(clinic.session("removed-case"))
        assert clinic.store.delete("removed-case", clinic.identity.owner_id) is True
    return clinics


def test_each_clinic_sees_only_its_own_state_and_removal_rows(two_clinics):
    for clinic, other in (two_clinics, two_clinics[::-1]):
        with clinic.store._connection() as conn:
            for table in ("reference_clinical_state_v1", "reference_clinical_removals_v1"):
                rows = conn.execute(f"SELECT workspace_id, owner_id FROM {table}").fetchall()
                assert rows, (table, clinic.tenant)  # populated for this clinic: the check is not vacuous
                assert set(rows) == {(clinic.identity.workspace_id, clinic.identity.owner_id)}, (table, rows)
        assert [s.session_id for s in clinic.store.list_for(clinic.identity.owner_id)] == ["kept-case"]
        assert clinic.store.get("kept-case", other.identity.owner_id) is None
        assert clinic.store.delete("kept-case", other.identity.owner_id) is False
    for clinic in two_clinics:  # the refused cross-clinic attempts changed nothing
        assert clinic.store.get("kept-case", clinic.identity.owner_id) is not None
