"""Independent fixed duty inventory for the staged partitioned lifecycle."""
import json
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.role_contract import PARTITIONED_TABLES, ROLES, TABLES, collect_access_matrix, expected_privileges


def test_partitioned_profile_preserves_unaffected_duties_and_retires_old_payload():
    assert len(TABLES | PARTITIONED_TABLES) == 38
    for role in ROLES:
        assert expected_privileges(role, "pack_lifecycle", partitioned_lifecycle=True) == set()
        assert expected_privileges(role, "pack_lifecycle", "payload", partitioned_lifecycle=True) == set()
        for table in TABLES - {"pack_lifecycle"}:
            assert expected_privileges(role, table, partitioned_lifecycle=True) == expected_privileges(role, table)
        for table in PARTITIONED_TABLES:
            assert not expected_privileges(role, table, partitioned_lifecycle=True) & {
                "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES", "MAINTAIN"}
        assert expected_privileges(role, "reference_pack_migrations_v1", partitioned_lifecycle=True) == set()
        for table in ("reference_pack_retry_index_v1", "reference_pack_installation_retries_v1"):
            assert ("SELECT" in expected_privileges(role, table, partitioned_lifecycle=True)) == (role == "governor")


def test_all_actual_partitioned_logins_match_full_table_and_column_contract(tmp_path):
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    report = collect_access_matrix(roles, partitioned_lifecycle=True)
    (tmp_path / "partitioned-role-access-matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    assert report["lifecycle_profile"] == "partitioned-v1"
    assert len(report["roles"]) == 12
    assert all(len(value["tables"]) == 38 for value in report["roles"].values())
    assert report["privilege_contract_matches"], report["errors"]
    assert not report["tenant_row_isolation_demonstrated"] and report["claims_promoted"] == 0
    refused = 0
    for kind in ROLES:
        tables = report["roles"][kind]["tables"]
        assert tables["reference_pack_tenants_v1"]["rls_enabled"]
        assert tables["reference_pack_tenants_v1"]["rls_forced"]
        with getattr(roles, kind).connection() as conn:
            for table in PARTITIONED_TABLES | {"pack_lifecycle"}:
                if "SELECT" not in expected_privileges(kind, table, partitioned_lifecycle=True):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        conn.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(table)))
                    refused += 1
    assert refused == 66  # 72 role/table pairs minus six allowed reads.
