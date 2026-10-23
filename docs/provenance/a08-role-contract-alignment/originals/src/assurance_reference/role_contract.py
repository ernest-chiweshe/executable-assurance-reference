"""Read-only inventory against an explicit local runtime privilege contract.

Matching this contract detects grant drift; it does not certify tenant isolation.
The shared authority tables below remain explicit D4 scope-review work. Nothing
here changes grants, policies, records, or the obligation register.
"""

from __future__ import annotations

import psycopg
from psycopg import sql


ROLES = (
    "receiver", "allocator", "recorder", "governor", "clock", "alerts",
    "session_reader", "session_issuer", "project_state", "education_reader",
    "education_governor", "monitor_ingress",
)
CORE_TABLES = frozenset({
    "regulated_decision_evidence_v1", "regulated_permit_uses_v1",
    "regulated_reviews_v1", "regulated_mission_budget_events_v1",
    "regulated_preparations_v1", "regulated_preparation_writers_v1",
    "regulated_budget_writer_roles_v1", "regulated_revocation_events_v1",
    "regulated_delegation_grants_v1", "regulated_delegation_revocations_v1",
    "regulated_monitor_clearances_v1", "regulated_governance_events_v1",
    "regulated_governance_fences_v1", "regulated_egress_scope_v1",
    "regulated_monitor_heartbeats_v2", "regulated_governance_rosters_v1",
    "regulated_evidence_checkpoints_v1", "regulated_decision_uses_v1",
    "regulated_decision_inputs_v1", "regulated_root_admissions_v1",
    "regulated_database_attempts_v1", "regulated_database_receipts_v1",
    "pack_lifecycle_schema_migrations", "pack_lifecycle", "reference_alerts_v1",
    "reference_clock_floor_v1",
})
PRIVATE_TABLES = frozenset({
    "reference_identities_v1", "reference_sessions_v1", "projectos_states",
    "reference_clinical_state_v1", "reference_clinical_removals_v1",
    "pack_documents", "pack_collections_schema_migrations",
})
TABLES = CORE_TABLES | PRIVATE_TABLES

# Separate fixed audit profile for the explicitly selected reference migration.
# These expectations are not imported from migration SQL or observed ACLs.
PARTITIONED_TABLES = frozenset({
    "reference_pack_shared_v1", "reference_pack_tenants_v1",
    "reference_pack_installation_retries_v1", "reference_pack_retry_index_v1",
    "reference_pack_migrations_v1",
})
PARTITIONED_DUTIES = {
    "reference_pack_shared_v1": {"receiver": {"SELECT"}, "governor": {"SELECT", "INSERT", "UPDATE"}},
    "reference_pack_tenants_v1": {"receiver": {"SELECT"}, "governor": {"SELECT", "INSERT", "UPDATE"}},
    "reference_pack_installation_retries_v1": {"governor": {"SELECT", "INSERT", "UPDATE"}},
    "reference_pack_retry_index_v1": {"governor": {"SELECT", "INSERT"}},
    "reference_pack_migrations_v1": {},
}

# These are observed shared stores needing review, NOT accepted exclusions.
SCOPE_REVIEW = {
    "pack_lifecycle": "Shared pack payload includes tenant pins and request receipts.",
    "reference_alerts_v1": "Signed envelope includes tenant and decision/permit references.",
    "regulated_governance_rosters_v1": "Installation record also contains tenant authority fields.",
    "regulated_governance_fences_v1": "Shared scope/attempt coordination requires boundary review.",
    "regulated_monitor_heartbeats_v2": "Installation/monitor scope requires boundary review.",
}
HOST_METADATA = frozenset({
    "regulated_preparation_writers_v1", "regulated_budget_writer_roles_v1",
    "pack_lifecycle_schema_migrations", "pack_collections_schema_migrations",
    "reference_clock_floor_v1",
})
RLS_TABLES = (TABLES - HOST_METADATA - SCOPE_REVIEW.keys()) | {"reference_alerts_v1"}

# Fixed audit expectations kept separate from the provisioning implementation.
CORE_READS = {
    "receiver": {
        "pack_lifecycle", "regulated_permit_uses_v1", "regulated_reviews_v1",
        "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
        "regulated_preparations_v1", "regulated_database_attempts_v1",
        "regulated_database_receipts_v1", "regulated_revocation_events_v1",
        "regulated_delegation_grants_v1", "regulated_delegation_revocations_v1",
        "regulated_monitor_clearances_v1", "regulated_governance_events_v1",
        "regulated_governance_fences_v1", "regulated_monitor_heartbeats_v2",
    },
    "allocator": {
        "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
        "regulated_preparations_v1", "regulated_database_attempts_v1", "regulated_database_receipts_v1",
    },
    "recorder": {
        "regulated_decision_evidence_v1", "regulated_preparations_v1",
        "regulated_preparation_writers_v1", "regulated_mission_budget_events_v1",
    },
    "governor": {
        "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
        "pack_lifecycle", "regulated_governance_events_v1", "regulated_governance_fences_v1",
        "regulated_revocation_events_v1", "regulated_governance_rosters_v1",
    },
    "clock": {"reference_clock_floor_v1"},
    "alerts": {"reference_alerts_v1"},
}

INSERTS = {
    "allocator": {"regulated_mission_budget_events_v1"},
    "receiver": {"regulated_mission_budget_events_v1", "regulated_permit_uses_v1",
                 "regulated_reviews_v1"},
    "recorder": {"regulated_decision_evidence_v1", "regulated_preparations_v1"},
    "governor": {"regulated_mission_budget_events_v1", "regulated_governance_events_v1", "regulated_revocation_events_v1",
                         "regulated_governance_rosters_v1",
                 "pack_lifecycle", "regulated_governance_fences_v1"},
    "alerts": {"reference_alerts_v1"},
    "session_issuer": {"reference_identities_v1", "reference_sessions_v1"},
    "project_state": {"projectos_states", "reference_clinical_state_v1",
                      "reference_clinical_removals_v1"},
    "education_governor": {"pack_documents"},
    "monitor_ingress": {"regulated_monitor_heartbeats_v2"},
}
PRIVATE_READS = {
    "session_issuer": {"reference_identities_v1", "reference_sessions_v1"},
    "session_reader": {"reference_sessions_v1"},
    "project_state": {"projectos_states", "reference_clinical_state_v1",
                      "reference_clinical_removals_v1"},
    "education_reader": {"pack_documents"},
    "education_governor": {"pack_documents"},
}
COLUMN_UPDATES = {
    ("clock", "reference_clock_floor_v1"): {"highwater_us"},
    ("session_issuer", "reference_identities_v1"): {"active", "lock_anchor"},
    ("session_issuer", "reference_sessions_v1"): {"revoked", "lock_anchor"},
    ("session_reader", "reference_identities_v1"): {"lock_anchor"},
    ("session_reader", "reference_sessions_v1"): {"lock_anchor"},
    ("project_state", "projectos_states"): {"state", "revision", "updated_at"},
    ("project_state", "reference_clinical_state_v1"):
        {"payload", "record_digest", "revision", "tombstoned"},
    ("education_governor", "pack_documents"):
        {"version", "payload", "record_digest", "updated_at", "schema_version"},
}
IDENTITY_READER_COLUMNS = frozenset({"tenant", "principal", "username", "active", "lock_anchor"})
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN")
COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")


def expected_privileges(role, table, column=None, *, partitioned_lifecycle=False):
    """Independent fixed contract; never inferred from observed ACLs."""
    if type(partitioned_lifecycle) is not bool:
        raise TypeError("partitioned_lifecycle must be an explicit boolean")
    tables = TABLES | PARTITIONED_TABLES if partitioned_lifecycle else TABLES
    if role not in ROLES or table not in tables:
        raise ValueError("unregistered role or table")
    if partitioned_lifecycle and table == "pack_lifecycle":
        return set()  # Preserved migration evidence, inaccessible to runtime.
    if partitioned_lifecycle and table in PARTITIONED_TABLES:
        result = set(PARTITIONED_DUTIES[table].get(role, ()))
        return result if column is None else result & set(COLUMN_PRIVILEGES)
    result = set()
    if table in CORE_READS.get(role, ()) or table in PRIVATE_READS.get(role, ()):
        result.add("SELECT")
    if table in INSERTS.get(role, ()):
        result.add("INSERT")
    if role == "governor" and table in {"pack_lifecycle", "regulated_governance_fences_v1"}:
        result.add("UPDATE")
    if column is not None:
        if column in COLUMN_UPDATES.get((role, table), ()):
            result.add("UPDATE")
        if (role == "session_reader" and table == "reference_identities_v1"
                and column in IDENTITY_READER_COLUMNS):
            result.add("SELECT")
        if (role == "monitor_ingress" and table == "regulated_monitor_heartbeats_v2"
                and column in {"installation", "monitor_id", "sequence"}):
            result.add("SELECT")
        result.intersection_update(COLUMN_PRIVILEGES)
    return result


def collect_access_matrix(roles, *, partitioned_lifecycle=False):
    """Inspect with each actual login; read probes use LIMIT 0 and no row data.

    No admin DSN, SET ROLE, altered grants, or altered RLS are used. A successful
    read probe proves SQL access only, never visibility of seeded tenant records.
    PostgreSQL 17+ is required (including its MAINTAIN privilege).
    """
    if type(partitioned_lifecycle) is not bool:
        raise TypeError("partitioned_lifecycle must be an explicit boolean")
    tables = TABLES | PARTITIONED_TABLES if partitioned_lifecycle else TABLES
    rls_tables = RLS_TABLES | {"reference_pack_tenants_v1"} if partitioned_lifecycle else RLS_TABLES
    scope_review = SCOPE_REVIEW.copy()
    if partitioned_lifecycle:
        scope_review.update({
            "pack_lifecycle": "Retained legacy evidence; runtime access must be absent. Overall D4 review remains OPEN.",
            "reference_pack_shared_v1": "Installation activation/history/revocation remains shared; authority review OPEN.",
            "reference_pack_tenants_v1": "Tenant RLS/attribution requires seeded-row, guarded-write and restore evidence.",
            "reference_pack_installation_retries_v1": "Unscoped installation retry payloads restricted to governor; review OPEN.",
            "reference_pack_retry_index_v1": "Pack-wide digest index retains original retry uniqueness; review OPEN.",
        })
    report = {"schema": "reference/role-access-matrix/v1", "roles": {},
              "lifecycle_profile": "partitioned-v1" if partitioned_lifecycle else "original",
              "errors": [], "scope_review_open": scope_review,
              "tenant_row_isolation_demonstrated": False, "claims_promoted": 0}
    for kind in ROLES:
        pool = getattr(roles, kind)
        with pool.connection() as conn:
            if conn.info.server_version < 170000:
                raise ValueError("PostgreSQL 17 or newer required for complete privilege inventory")
            identity = conn.execute(
                "SELECT session_user,current_user,current_schema()"
            ).fetchone()
            if identity != (pool.role, pool.role, roles.schema):
                raise ValueError("runtime login or schema differs from explicit role binding")
            catalog = conn.execute(
                "SELECT c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND c.relkind IN ('r','p') ORDER BY c.relname"
            ).fetchall()
            observed = {r[1] for r in catalog}
            if observed != tables:
                report["errors"].append({"role": kind, "table_inventory": {
                    "missing": sorted(tables - observed), "extra": sorted(observed - tables)}})
            table_rows = conn.execute(
                "SELECT c.relname,p,has_table_privilege(session_user,c.oid,p), "
                "has_table_privilege(session_user,c.oid,p || ' WITH GRANT OPTION') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "CROSS JOIN unnest(%s::text[]) p WHERE n.nspname=current_schema() "
                "AND c.relkind IN ('r','p') ORDER BY c.relname,p", (list(TABLE_PRIVILEGES),)
            ).fetchall()
            column_rows = conn.execute(
                "SELECT c.relname,a.attname,p,has_column_privilege(session_user,c.oid,a.attnum,p), "
                "has_column_privilege(session_user,c.oid,a.attnum,p || ' WITH GRANT OPTION') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped "
                "CROSS JOIN unnest(%s::text[]) p WHERE n.nspname=current_schema() "
                "AND c.relkind IN ('r','p') ORDER BY c.relname,a.attnum,p",
                (list(COLUMN_PRIVILEGES),)
            ).fetchall()
            entries = {}
            for _, table, enabled, forced in catalog:
                entries[table] = {"rls_enabled": enabled, "rls_forced": forced,
                                  "table_privileges": [], "columns": {}, "grant_options": []}
                if table in rls_tables and not (enabled and forced):
                    report["errors"].append({"role": kind, "table": table, "forced_rls_missing": True})
            for table, privilege, allowed, grantable in table_rows:
                if allowed:
                    entries[table]["table_privileges"].append(privilege)
                if grantable:
                    entries[table]["grant_options"].append(privilege)
                if table in tables and (allowed != (privilege in expected_privileges(
                        kind, table, partitioned_lifecycle=partitioned_lifecycle)) or grantable):
                    report["errors"].append({"role": kind, "table": table, "privilege": privilege,
                                             "allowed": allowed, "grantable": grantable})
            for table, column, privilege, allowed, grantable in column_rows:
                cell = entries[table]["columns"].setdefault(column, {"privileges": [], "grant_options": []})
                if allowed:
                    cell["privileges"].append(privilege)
                if grantable:
                    cell["grant_options"].append(privilege)
                if table in tables and (allowed != (privilege in expected_privileges(
                        kind, table, column, partitioned_lifecycle=partitioned_lifecycle)) or grantable):
                    report["errors"].append({"role": kind, "table": table, "column": column,
                                             "privilege": privilege, "allowed": allowed, "grantable": grantable})
            for table, entry in entries.items():
                columns = [name for name, cell in entry["columns"].items() if "SELECT" in cell["privileges"]]
                # Probe all readable columns, or one denied column if none is readable.
                projection = columns or list(entry["columns"])[:1]
                query = sql.SQL("SELECT {} FROM {} LIMIT 0").format(
                    sql.SQL(",").join(map(sql.Identifier, projection)), sql.Identifier(table))
                try:
                    with conn.transaction():
                        conn.execute("SET TRANSACTION READ ONLY")
                        conn.execute(query).fetchall()
                    allowed = True
                except psycopg.errors.InsufficientPrivilege:
                    allowed = False
                entry["read_probe"] = {"allowed": allowed, "columns": projection, "rows_requested": 0}
                if allowed != bool(columns):
                    report["errors"].append({"role": kind, "table": table, "read_probe_mismatch": True})
            report["roles"][kind] = {"tables": entries}
    report["privilege_contract_matches"] = not report["errors"]
    return report
