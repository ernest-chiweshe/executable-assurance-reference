"""B-F7b seeded-row isolation on actual restricted logins; fictional school, isolated PostgreSQL.

A complete lawful Education release populates the authority tables for one tenant. Every runtime login is then
queried as another tenant on every row-level-secured table it may read: it sees no row, while the owning tenant's
populated rows stay visible to the logins whose duty includes them. No runtime login may update or delete evidence,
permit uses, reviews or alerts. Alerts (row-level secured although listed for scope review) are seeded through the
ordinary alert store and included; logins whose duty is a column-only read see no other tenant's row through the
columns they may read. The remaining shared stores under SCOPE_REVIEW stay outside this demonstration, and the
database administrator is excluded from the threat model.
"""
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.role_contract import RLS_TABLES, ROLES, SCOPE_REVIEW, expected_privileges
from test_education_session_release import approved_request

OWNER, OTHER = "school-a", "synthetic-other-tenant"
EVIDENCE = ("regulated_decision_evidence_v1", "regulated_permit_uses_v1", "regulated_reviews_v1",
            "reference_alerts_v1")


@pytest.fixture(scope="module")
def populated(tmp_path_factory):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path_factory.mktemp("isolation"))
    context, decision = approved_request(app)
    result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract, decision=decision,
                                                   artifact=app.body, out_path=str(app.path), context=context)
    assert result.state == "committed", result
    # One ordinary operator alert for the owning tenant, through the alert store's own append path.
    app.alerts.append_refusal(tenant_id=OWNER, request_hash="0" * 64, decision_hash=None, code="ADMISSION_REFUSED")
    return roles


def _count(conn, table, tenant):
    with conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        # The alert store scopes by its own setting; set both so every table is read as exactly this tenant.
        conn.execute("SELECT set_config('app.alert_tenant',%s,true)", (tenant,))
        return conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]


def test_no_runtime_login_sees_another_tenants_rows(populated):
    roles, seen_owned = populated, {}
    checked = 0
    for kind in ROLES:
        with getattr(roles, kind).connection() as conn:
            for table in sorted(RLS_TABLES):
                if "SELECT" not in expected_privileges(kind, table):
                    continue
                assert _count(conn, table, OTHER) == 0, (kind, table)
                owned = _count(conn, table, OWNER)
                seen_owned[table] = max(seen_owned.get(table, 0), owned)
                checked += 1
    assert checked >= 20
    # The release really populated the core authority tables the isolation is shown on.
    for table in ("regulated_decision_evidence_v1", "regulated_permit_uses_v1", "regulated_reviews_v1",
                  "regulated_mission_budget_events_v1", "reference_alerts_v1"):
        assert seen_owned.get(table, 0) > 0, table


def _column_reads():
    """(login, table, readable columns) for every column-only read duty on a row-level-secured table."""
    found = []
    for kind in ROLES:
        for table in sorted(RLS_TABLES):
            if "SELECT" in expected_privileges(kind, table):
                continue
            columns = sorted(c for c in COLUMNS.get(table, ()) if "SELECT" in expected_privileges(kind, table, c))
            if columns:
                found.append((kind, table, columns))
    return found


COLUMNS = {"reference_identities_v1": ("tenant", "principal", "username", "active", "lock_anchor"),
           "regulated_monitor_clearances_v1": ("tenant", "decision_record_id")}


def test_column_only_reads_see_no_other_tenants_rows(populated):
    roles, checked = populated, []
    for kind, table, columns in _column_reads():
        with getattr(roles, kind).connection() as conn:
            def count(tenant):
                with conn.transaction():
                    conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
                    return conn.execute(sql.SQL("SELECT count({}) FROM {}").format(
                        sql.Identifier(columns[0]), sql.Identifier(table))).fetchone()[0]
            assert count(OTHER) == 0, (kind, table)
            checked.append((kind, table, count(OWNER)))
    duties = {(kind, table) for kind, table, _ in checked}
    assert {("session_reader", "reference_identities_v1"), ("owner_reader", "reference_identities_v1")} <= duties
    # The owning tenant's identities are really there, so the zero above is isolation, not an empty table.
    assert all(owned > 0 for kind, table, owned in checked if table == "reference_identities_v1"), checked


@pytest.mark.parametrize("table", EVIDENCE)
def test_no_runtime_login_updates_or_deletes_evidence_permits_reviews_or_alerts(populated, table):
    roles = populated
    for kind in ROLES:
        with getattr(roles, kind).connection() as conn:
            column = conn.execute("SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum = 1",
                                  (table,)).fetchone()[0]
            for statement in (sql.SQL("DELETE FROM {}").format(sql.Identifier(table)),
                              sql.SQL("UPDATE {} SET {} = {}").format(sql.Identifier(table), sql.Identifier(column),
                                                                      sql.Identifier(column))):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("SELECT set_config('app.tenant',%s,true)", (OWNER,))
                        conn.execute(statement)
