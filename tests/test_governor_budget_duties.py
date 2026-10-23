"""Synthetic governor duty contracts; database cases require isolated PostgreSQL."""
import os

import psycopg
import pytest

from assurance_reference.local_roles import provision_local_roles
from assurance_reference.role_contract import expected_privileges
from regulated_core.persistence_pg import PostgresMissionBudget
from regulated_core.budget import BudgetError
from test_core_budget_transaction_contract import approved


def test_governor_budget_acl_contract_adds_no_metadata_write_or_event_update():
    assert expected_privileges("governor", "regulated_mission_budget_events_v1") == {"SELECT", "INSERT"}
    assert expected_privileges("governor", "regulated_budget_writer_roles_v1") == {"SELECT"}
    for role in ("recorder", "clock", "alerts", "session_reader", "session_issuer", "monitor_ingress"):
        assert "INSERT" not in expected_privileges(role, "regulated_mission_budget_events_v1")


def test_governor_core_consumption_preserves_allocator_duties_and_tenant_scope(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test required; no skipped qualification"
    roles = provision_local_roles(dsn)
    signed, binding = approved(tmp_path)
    p = signed.permit
    allocator = PostgresMissionBudget(pool=roles.allocator)
    governor = PostgresMissionBudget(pool=roles.governor)
    allocator.reserve(p.tenant_id, p.mission, reservation_id=p.budget_reservation,
                      units=p.budget_units, limit=p.budget_units)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        governor.reserve(p.tenant_id, p.mission, reservation_id="other", units=1, limit=2)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        governor.release(p.tenant_id, p.mission, p.budget_reservation)
    with roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", ("other-synthetic-tenant",))
        assert conn.execute(
            "SELECT count(*) FROM regulated_mission_budget_events_v1 WHERE tenant=%s",
            (p.tenant_id,)).fetchone() == (0,)
        with pytest.raises(BudgetError, match="permit tenant"):
            governor.consume_permit_on(conn, signed, **binding)
    # An ordinary transaction rollback leaves the reservation live; this is not
    # yet evidence of atomic governance effect/receipt rollback.
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with roles.governor.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant', %s, true)", (p.tenant_id,))
            governor.consume_permit_on(conn, signed, **binding)
            raise RuntimeError("synthetic rollback")
    assert governor.committed(p.tenant_id, p.mission) == 0
    with roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", (p.tenant_id,))
        governor.consume_permit_on(conn, signed, **binding)
    assert governor.committed(p.tenant_id, p.mission) == p.budget_units
    with roles.governor.connection() as conn:
        assert conn.execute(
            "SELECT kind FROM regulated_budget_writer_roles_v1 WHERE role_name=session_user ORDER BY kind"
        ).fetchall() == [("consume",)]
