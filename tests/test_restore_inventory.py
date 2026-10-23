"""Effective ACL comparison must still detect an actual loss of a runtime grant."""
import importlib.util
import os
from pathlib import Path

from psycopg import sql

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_roles import LocalPool

spec = importlib.util.spec_from_file_location("restore_inventory_support",
    Path(__file__).resolve().parents[1] / "scripts/d1_restore_support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def test_effective_acl_inventory_detects_stricter_actual_grants():
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_partitioned_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "fixture-inventory-owner")
    raw_before = {}
    before = support.inventory(owner, roles, representations=raw_before)
    # Tighten one grant only within this fresh fixture; no guard is disabled.
    with owner.connection() as conn, conn.transaction():
        conn.execute(sql.SQL("REVOKE SELECT ON reference_pack_shared_v1 FROM {}")
                     .format(sql.Identifier(roles.governor.role)))
    raw_after = {}
    after = support.inventory(owner, roles, representations=raw_after)
    assert raw_before != raw_after and raw_before["relation_acls"]
    assert before["tables"] == after["tables"]
    assert before["catalog"] != after["catalog"]
    initial = {row[0]: row for row in before["catalog"]["relations"]}
    final = {row[0]: row for row in after["catalog"]["relations"]}
    changed = [name for name in initial if initial[name] != final[name]]
    assert changed == ["reference_pack_shared_v1"]
    first, last = initial[changed[0]], final[changed[0]]
    assert first[:5] == last[:5]  # identity, owner and RLS comparison stays exact
    removed = [grant for grant in first[5] if grant not in last[5]]
    assert removed == [[first[4], roles.governor.role, "SELECT", False]]
    assert all(grant in first[5] for grant in last[5])
