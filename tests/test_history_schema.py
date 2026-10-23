"""The installed reference schema must not outgrow the scan guard's table list."""
from dataclasses import fields
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_history_scans import TABLE
from history_schema import immutable_tables
from assurance_reference.local_roles import provision_local_roles


def test_installed_immutable_tables_match_reviewed_inventory_and_scan_pattern():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test is required; no skipped qualification"
    catalog = json.loads((Path(__file__).resolve().parents[1] /
                          "docs/provenance/history-read-classifications.json").read_bytes())
    profile = catalog["schema_profiles"]["local_reference"]
    roles = provision_local_roles(dsn)
    try:
        with roles.receiver.connection() as connection:
            assert immutable_tables(connection) == profile["immutable_tables"]
        for name in profile["immutable_tables"] + profile["append_only_by_design"]:
            assert TABLE.fullmatch(name), f"uncovered history table: {name}"
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if callable(getattr(pool, "close", None)):
                pool.close()
