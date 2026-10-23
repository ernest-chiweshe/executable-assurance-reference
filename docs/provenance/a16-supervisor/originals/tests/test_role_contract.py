"""Fixed privilege boundaries, plus actual-login inventory on an owned cluster."""

import json
import os
from dataclasses import fields

import psycopg
from psycopg import sql

from assurance_reference.local_roles import LocalAuthorityRoles, provision_local_roles
from assurance_reference.role_contract import (
    CORE_TABLES, HOST_METADATA, PRIVATE_TABLES, RLS_TABLES, ROLES, SCOPE_REVIEW,
    TABLES, collect_access_matrix, expected_privileges,
)


def test_contract_covers_every_known_table_without_hiding_scope_gaps():
    assert len(ROLES) == 13
    assert set(ROLES) == {field.name for field in fields(LocalAuthorityRoles)} - {"schema", "domain"}
    assert len(TABLES) == 33
    assert not CORE_TABLES & PRIVATE_TABLES
    assert len(RLS_TABLES) == 24
    assert len(HOST_METADATA) == 5
    assert len(SCOPE_REVIEW) == 5
    assert RLS_TABLES | HOST_METADATA | SCOPE_REVIEW.keys() == TABLES


def test_sensitive_columns_and_authority_maps_have_no_extra_duties():
    for role in ROLES:
        for table in TABLES:
            assert not expected_privileges(role, table) & {"DELETE", "TRUNCATE", "TRIGGER", "REFERENCES", "MAINTAIN"}
        for table in ("regulated_budget_writer_roles_v1", "regulated_preparation_writers_v1"):
            assert expected_privileges(role, table) <= {"SELECT"}
        for column in ("salt", "password_hash"):
            actual = expected_privileges(role, "reference_identities_v1", column)
            assert actual == ({"SELECT", "INSERT"} if role == "session_issuer" else set())
    assert expected_privileges("session_reader", "reference_identities_v1") == set()
    assert expected_privileges("session_reader", "reference_identities_v1", "principal") == {"SELECT"}
    assert expected_privileges("session_reader", "reference_identities_v1", "lock_anchor") == {"SELECT", "UPDATE"}
    assert expected_privileges("session_reader", "reference_identities_v1", "active") == {"SELECT"}
    assert expected_privileges("clock", "reference_clock_floor_v1") == {"SELECT"}
    assert expected_privileges("clock", "reference_clock_floor_v1", "highwater_us") == {"SELECT", "UPDATE"}
    for role in ROLES:
        assert expected_privileges(role, "pack_collections_schema_migrations") == set()
        assert expected_privileges(role, "pack_lifecycle_schema_migrations") == set()
        assert ("SELECT" in expected_privileges(role, "reference_alerts_v1")) == (role == "alerts")
        assert ("SELECT" in expected_privileges(role, "pack_lifecycle")) == (role in {"receiver", "governor"})


def test_monitor_ingress_contract_has_only_append_and_conflict_key_read_duties():
    table = "regulated_monitor_heartbeats_v2"
    assert expected_privileges("monitor_ingress", table) == {"INSERT"}
    for column in ("installation", "monitor_id", "sequence"):
        assert expected_privileges("monitor_ingress", table, column) == {"INSERT", "SELECT"}
    for column in ("beat_at_us", "signature"):
        assert expected_privileges("monitor_ingress", table, column) == {"INSERT"}
    for other in TABLES - {table}:
        assert expected_privileges("monitor_ingress", other) == set()


def test_delegation_issuer_contract_is_exact_and_receiver_remains_read_only():
    grants = "regulated_delegation_grants_v1"
    revocations = "regulated_delegation_revocations_v1"
    for partitioned in (False, True):
        for role, table, duties in (
            ("delegation_issuer", grants, {"SELECT", "INSERT"}),
            ("delegation_issuer", revocations, {"SELECT"}),
            ("receiver", grants, {"SELECT"}),
            ("receiver", revocations, {"SELECT"}),
        ):
            assert expected_privileges(role, table, partitioned_lifecycle=partitioned) == duties
        for table in TABLES - {grants, revocations}:
            assert expected_privileges("delegation_issuer", table, partitioned_lifecycle=partitioned) == set()


def test_every_runtime_login_matches_explicit_privilege_contract(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test required; no skipped qualification"
    roles = provision_local_roles(dsn)
    report = collect_access_matrix(roles)
    (tmp_path / "role-access-matrix.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    assert len(report["roles"]) == 13
    assert all(len(value["tables"]) == 33 for value in report["roles"].values())
    assert not report["tenant_row_isolation_demonstrated"]
    assert report["claims_promoted"] == 0
    assert report["scope_review_open"] == SCOPE_REVIEW
    assert report["privilege_contract_matches"], report["errors"]
    # Actual guarded SQL refusal under every out-of-duty login, even if the
    # table is empty. No foreign records or vulnerability payloads are needed.
    duties = {
        "pack_lifecycle": {"receiver", "governor"},
        "reference_alerts_v1": {"alerts"},
        "regulated_governance_rosters_v1": {"governor"},
        "regulated_governance_fences_v1": {"receiver", "governor"},
        "regulated_monitor_heartbeats_v2": {"receiver"},
    }
    refused = 0
    for kind in ROLES:
        with getattr(roles, kind).connection() as conn:
            for table, allowed in duties.items():
                if kind not in allowed:
                    try:
                        conn.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(table)))
                    except psycopg.errors.InsufficientPrivilege:
                        refused += 1
                    else:
                        raise AssertionError(f"{kind} read outside its duty: {table}")
    assert refused == 58
