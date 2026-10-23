"""B-F7b populated two-tenant isolation on every row-level-secured authority table; isolated PostgreSQL.

The excluded database administrator (the isolated cluster's superuser; frozen limit) seeds one row for each of two
tenants into all 35 RLS tables of a freshly provisioned schema, with triggers and foreign keys deferred to replica mode
so that rows not reachable through a lawful flow can still be placed; CHECK, UNIQUE and primary-key constraints still
apply. Every value that the row policy compares is set for its tenant (tenant columns, the alert payload tenant, the
education pack and collection, the project namespace and the clinician owner). The clinical state row also carries
an unrelated removal so that the removed-session condition is exercised.

Then, for every runtime login and every RLS table it may read (whole-table or column privilege): under each tenant's
request settings the login sees exactly that tenant's row and never the other's. For every table it may insert into,
a row tagged with the other tenant is refused and nothing is written. For every column it may update, an update
under one tenant's settings leaves the other tenant's row untouched (same xmin). Tables with no runtime read are
refused outright to every login. Catalog and fixture evidence; no guard is changed.
"""
import hashlib
import json
import os

import psycopg
from psycopg import sql
import pytest

from assurance_reference.local_roles import provision_local_roles
from assurance_reference.role_contract import RLS_TABLES as CONTRACT_RLS_TABLES, ROLES, expected_privileges as contract

# Every provisioned schema uses the tenant-partitioned pack lifecycle (candidate 060), which adds its own forced-RLS
# tenant table to the contract's RLS tables.
RLS_TABLES = CONTRACT_RLS_TABLES | {"reference_pack_tenants_v1"}


def expected_privileges(kind, table, column=None):
    return contract(kind, table, column, partitioned_lifecycle=True)


TENANTS = ("tenant-a", "tenant-b")
CLINICIAN = "clinician-1"
NAMESPACE = "health"
EDUCATION_PACK = "lumiwright.education.formative-feedback"
# Values a CHECK constraint or the row policy fixes; every other text column gets a 64-hex value unique to the tenant.
FIXED = {
    ("pack_documents", "pack_id"): EDUCATION_PACK,
    ("pack_documents", "collection"): "roster-user",
    ("reference_epoch_withdrawal_receipts_v1", "operation"): "governance:withdraw-tenant-epoch",
    ("reference_release_settlements_v1", "state"): "settling",
    ("reference_tenant_fences_v1", "phase"): "open",
    # not_committed: a seeded committed receipt has no cluster deadline, which the R-1b commit trigger refuses even
    # for restore-style writes (ENABLE ALWAYS). Row isolation does not depend on the outcome.
    ("regulated_database_receipts_v1", "outcome"): "not_committed",
    ("regulated_egress_scope_v1", "kind"): "inventoried",
    ("regulated_egress_scope_v1", "pack_ref"): "",
    ("regulated_governance_events_v1", "phase"): "prepared",
    ("regulated_mission_budget_events_v1", "kind"): "reserve",
    ("reference_release_goal_heads_v1", "lock_anchor"): True,
    ("reference_release_materials_v1", "lock_anchor"): True,
    ("reference_clinical_removals_v1", "session_id"): "removed-session",
}
TENANT_COLUMNS = {"tenant", "tenant_id", "workspace_id"}
# Tables whose BEFORE INSERT trigger already refuses a row for a tenant other than the request's, before the row
# policy's WITH CHECK is reached; every other insertable table must be refused by the row policy itself.
TENANT_TRIGGERS = {
    "regulated_mission_budget_events_v1": "budget write requires matching READ COMMITTED tenant",
    "regulated_preparations_v1": "preparation writer or tenant not authorized",
}
ROW_POLICY = "new row violates row-level security policy"
# Every column UPDATE the privilege contract grants on an RLS table (role_contract.COLUMN_UPDATES), pinned.
EXPECTED_UPDATES = [
    ("education_governor", "pack_documents", column)
    for column in ("version", "payload", "record_digest", "updated_at", "schema_version")
] + [("project_state", "projectos_states", column) for column in ("state", "revision", "updated_at")] + [
    ("project_state", "reference_clinical_state_v1", column)
    for column in ("payload", "record_digest", "revision", "tombstoned")
] + [
    ("session_issuer", "reference_identities_v1", "active"), ("session_issuer", "reference_identities_v1", "lock_anchor"),
    ("session_reader", "reference_identities_v1", "lock_anchor"),
    ("release_linker", "reference_release_goal_heads_v1", "lock_anchor"),
    ("release_linker", "reference_release_materials_v1", "lock_anchor"),
    ("settlement_writer", "reference_release_settlements_v1", "state"),
    ("settlement_writer", "reference_release_settlements_v1", "authorization_body"),
    ("session_issuer", "reference_sessions_v1", "revoked"), ("session_issuer", "reference_sessions_v1", "lock_anchor"),
    ("session_reader", "reference_sessions_v1", "lock_anchor"),
] + [("governor", "reference_pack_tenants_v1", column)
       for column in ("pack_id", "tenant_id", "revision", "payload", "state_digest")]


def _settings(tenant):
    return {"app.tenant": tenant, "app.education_tenant": tenant, "app.release_tenant": tenant,
            "app.alert_tenant": tenant, "app.pack_tenant": tenant, "app.project_namespace": NAMESPACE, "app.clinician": CLINICIAN}


def _value(table, column, kind, tenant):
    if (table, column) in FIXED:
        return FIXED[(table, column)]
    if column in TENANT_COLUMNS:
        return tenant
    if column == "namespace":
        return NAMESPACE
    if column == "owner_id":
        return f"{tenant}:{CLINICIAN}"
    if table == "reference_alerts_v1" and column == "envelope":
        return json.dumps({"payload": {"tenant_id": tenant}}).encode()
    if kind in ("bigint", "integer"):
        return 2
    if kind == "boolean":
        return False
    if kind == "jsonb":
        return json.dumps({"tenant": tenant})
    if kind == "bytea":
        return tenant.encode()
    if kind.startswith("timestamp"):
        return "2026-10-18T00:00:00Z"
    return hashlib.sha256(f"{tenant}/{table}/{column}".encode()).hexdigest()


@pytest.fixture(scope="module")
def seeded():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    rows = {}
    with psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True) as admin:
        admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
        admin.execute("SET session_replication_role = replica")
        for table in sorted(RLS_TABLES):
            columns = admin.execute(
                "SELECT column_name, data_type, is_nullable = 'YES', column_default IS NOT NULL "
                "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (roles.schema, table)).fetchall()
            for tenant in TENANTS:
                row = {name: _value(table, name, kind, tenant) for name, kind, nullable, default in columns
                       if (table, name) in FIXED or not (nullable or default)}
                admin.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(table), sql.SQL(", ").join(map(sql.Identifier, row)),
                    sql.SQL(", ").join(sql.Placeholder() * len(row))), list(row.values()))
                rows[(table, tenant)] = row
        # The clinical session is not removed; the removal row names another session of the same clinician.
        for tenant in TENANTS:
            assert rows[("reference_clinical_state_v1", tenant)]["session_id"] != "removed-session"
        admin.execute("SET session_replication_role = origin")
        counts = {table: admin.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]
                  for table in RLS_TABLES}
    assert all(count == 2 for count in counts.values()), counts
    yield roles, rows
    for kind in ROLES:
        getattr(roles, kind).close()


def _apply(conn, tenant):
    for name, value in _settings(tenant).items():
        conn.execute("SELECT set_config(%s, %s, true)", (name, value))


def _readable(kind, table, columns):
    if "SELECT" in expected_privileges(kind, table):
        return list(columns)
    return [column for column in columns if "SELECT" in expected_privileges(kind, table, column)]


def _columns(roles, table):
    with psycopg.connect(os.environ["FACTORY_TEST_DB_URL"]) as admin:
        return [name for name, in admin.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = %s "
            "ORDER BY ordinal_position", (roles.schema, table)).fetchall()]


def _xmin(roles, table, tenant):
    """Every row the administrator attributes to the tenant, with its xmin; the alert tenant is in its payload."""
    where = (sql.SQL("(convert_from(envelope, 'UTF8')::jsonb->'payload'->>'tenant_id') = %s")
             if table == "reference_alerts_v1" else
             sql.SQL("{} = %s").format(sql.Identifier(next(c for c in _columns(roles, table) if c in TENANT_COLUMNS))))
    with psycopg.connect(os.environ["FACTORY_TEST_DB_URL"]) as admin:
        admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
        return admin.execute(sql.SQL("SELECT ctid::text, xmin::text FROM {} WHERE {} ORDER BY 1").format(
            sql.Identifier(table), where), (tenant,)).fetchall()


def test_every_rls_table_is_populated_for_two_tenants(seeded):
    roles, rows = seeded
    assert {table for table, _ in rows} == set(RLS_TABLES) and len(RLS_TABLES) == 35


def test_each_login_reads_only_its_tenants_row_on_every_rls_table(seeded):
    roles, rows = seeded
    checked, refused = [], []
    for table in sorted(RLS_TABLES):
        columns = _columns(roles, table)
        readers = [kind for kind in ROLES if _readable(kind, table, columns)]
        if not readers:
            refused.append(table)
        for kind in ROLES:
            readable = _readable(kind, table, columns)
            with getattr(roles, kind).connection() as conn:
                if not readable:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        conn.execute(sql.SQL("SELECT 1 FROM {}").format(sql.Identifier(table))).fetchall()
                    continue
                for tenant in TENANTS:
                    with conn.transaction():
                        _apply(conn, tenant)
                        seen = conn.execute(sql.SQL("SELECT {} FROM {}").format(
                            sql.SQL(", ").join(map(sql.Identifier, readable)), sql.Identifier(table))).fetchall()
                    own = rows[(table, tenant)]
                    other = rows[(table, next(t for t in TENANTS if t != tenant))]
                    assert len(seen) == 1, (kind, table, tenant, seen)
                    distinct = [i for i, column in enumerate(readable) if own.get(column) != other.get(column)
                                and column in own]
                    assert distinct, (kind, table, "no readable column distinguishes the tenants")
                    for i in distinct:
                        value = seen[0][i]
                        expected = own[readable[i]]
                        if isinstance(value, (bytes, memoryview)):
                            value = bytes(value)
                        if isinstance(value, dict):
                            expected = json.loads(expected)
                        assert value == expected, (kind, table, tenant, readable[i], value, expected)
                checked.append((kind, table))
    assert len({table for _, table in checked}) + len(refused) == 35
    assert sorted(refused) == ["regulated_decision_inputs_v1", "regulated_decision_uses_v1",
                               "regulated_evidence_checkpoints_v1", "regulated_root_admissions_v1"], refused


def test_no_login_inserts_a_row_for_another_tenant(seeded):
    roles, rows = seeded
    attempted = []
    for table in sorted(RLS_TABLES):
        columns = _columns(roles, table)
        for kind in ROLES:
            if "INSERT" not in expected_privileges(kind, table):
                continue
            # Under tenant A's settings, a fresh row tagged for tenant B (distinct keys) is refused.
            foreign = {column: value for column, value in rows[(table, "tenant-b")].items()}
            for column, value in foreign.items():
                if isinstance(value, str) and len(value) == 64 and column not in TENANT_COLUMNS:
                    foreign[column] = hashlib.sha256(f"insert/{kind}/{table}/{column}".encode()).hexdigest()
            if "alert_id" in foreign:
                foreign["alert_id"] = f"insert-{kind}"
            before = _xmin(roles, table, "tenant-b")
            with getattr(roles, kind).connection() as conn:
                with pytest.raises(psycopg.Error) as refused:
                    with conn.transaction():
                        _apply(conn, "tenant-a")
                        conn.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                            sql.Identifier(table), sql.SQL(", ").join(map(sql.Identifier, foreign)),
                            sql.SQL(", ").join(sql.Placeholder() * len(foreign))), list(foreign.values()))
            assert _xmin(roles, table, "tenant-b") == before, (kind, table)
            expected = TENANT_TRIGGERS.get(table, ROW_POLICY)
            assert expected in str(refused.value), (kind, table, str(refused.value))
            attempted.append((kind, table, "tenant trigger" if table in TENANT_TRIGGERS else "row policy"))
    assert len(attempted) == 26, attempted
    assert {table for _, table, how in attempted if how == "tenant trigger"} == set(TENANT_TRIGGERS)


def test_no_column_update_reaches_another_tenants_row(seeded):
    roles, rows = seeded
    attempted, outcomes = [], []
    for table in sorted(RLS_TABLES):
        columns = _columns(roles, table)
        for kind in ROLES:
            for column in columns:
                if "UPDATE" not in expected_privileges(kind, table, column):
                    continue
                own_before, before = _xmin(roles, table, "tenant-a"), _xmin(roles, table, "tenant-b")
                with getattr(roles, kind).connection() as conn:
                    try:
                        with conn.transaction():
                            _apply(conn, "tenant-a")
                            conn.execute(sql.SQL("UPDATE {} SET {} = {}").format(
                                sql.Identifier(table), sql.Identifier(column), sql.Identifier(column)))
                        outcome = "own row updated" if _xmin(roles, table, "tenant-a") != own_before else "no row"
                    except psycopg.Error as error:
                        outcome = "refused: " + str(error).splitlines()[0]
                assert _xmin(roles, table, "tenant-b") == before, (kind, table, column)
                attempted.append((kind, table, column))
                outcomes.append((kind, table, column, outcome))
    assert sorted(attempted) == sorted(EXPECTED_UPDATES), attempted
    # Not vacuous: each granted update reaches the requesting tenant's own row.
    assert all(outcome == "own row updated" for *_, outcome in outcomes), outcomes
