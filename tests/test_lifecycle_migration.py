"""Queued contracts for an owned reference migration; no application effects."""
from dataclasses import fields
import json
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.lifecycle_migration import TABLES, migrate_reference_lifecycle
from assurance_reference.local_roles import LocalPool, provision_local_roles
from factory.packs.lifecycle import LifecycleError
from factory.packs.lifecycle_pg import _canonical, _digest
from test_lifecycle_partition import legacy_snapshot


@pytest.fixture
def legacy():
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn, legacy_lifecycle=True)  # migration evidence starts from the legacy profile
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    names = {field.name: getattr(roles, field.name).role for field in fields(roles)
             if field.name not in {"schema", "domain"}}
    payload = json.loads(_canonical(legacy_snapshot()))
    digest = _digest("education", 6, payload)
    with owner.connection() as conn:
        conn.execute("INSERT INTO pack_lifecycle VALUES (%s,%s,%s::jsonb,%s)",
                     ("education", 6, _canonical(payload), digest))
    return owner, roles, names, payload, digest


def test_transactional_partition_preserves_source_and_installation_listing(legacy):
    owner, roles, names, payload, digest = legacy
    first = migrate_reference_lifecycle(owner, runtime_roles=names)
    assert first["source_rows"] == 1 and first["legacy_rows_retained"]
    second = migrate_reference_lifecycle(owner, runtime_roles=names)
    assert second["already_migrated"]
    assert second["source_inventory_digest"] == first["source_inventory_digest"]
    with owner.connection() as conn:
        assert conn.execute("SELECT revision,payload,state_digest FROM pack_lifecycle").fetchone() == (
            6, payload, digest)
        assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone() == (2,)
        assert conn.execute("SELECT count(*) FROM reference_pack_retry_index_v1").fetchone() == (6,)
        assert conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                            "WHERE oid='reference_pack_tenants_v1'::regclass").fetchone() == (True, True)
    with roles.receiver.connection() as conn:
        assert conn.execute("SELECT pack_id FROM reference_pack_shared_v1 ORDER BY pack_id").fetchall() == [
            ("education",)]
        shared = conn.execute("SELECT payload FROM reference_pack_shared_v1").fetchone()[0]
        assert shared["records"] == payload["records"]
        assert shared["active"] == payload["active"] and shared["revoked"] == payload["revoked"]
        assert shared["pins"] == shared["requests"] == {}
        assert shared["governance_receipts"] == []


@pytest.mark.parametrize("kind", ["receiver", "governor"])
def test_seeded_private_records_are_hidden_outside_selected_tenant(legacy, kind):
    owner, roles, names, _, _ = legacy
    migrate_reference_lifecycle(owner, runtime_roles=names)
    with getattr(roles, kind).connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone() == (0,)
        for tenant, private_key, foreign in (("school-a", "private-a", "school-b"),
                                             ("school-b", "private-b", "school-a")):
            with conn.transaction():
                conn.execute("SELECT set_config('app.pack_tenant',%s,true)", (tenant,))
                rows = conn.execute("SELECT tenant_id,payload FROM reference_pack_tenants_v1").fetchall()
                assert len(rows) == 1 and rows[0][0] == tenant
                assert private_key in rows[0][1]["requests"]
                assert foreign not in _canonical(rows[0][1])
                assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1 WHERE tenant_id=%s",
                                    (foreign,)).fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM pack_lifecycle")


def test_guarded_private_writes_cannot_cross_scope_and_have_no_delete_grant(legacy):
    owner, roles, names, _, _ = legacy
    migrate_reference_lifecycle(owner, runtime_roles=names)
    with roles.governor.connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.pack_tenant','school-a',true)")
            assert conn.execute("UPDATE reference_pack_tenants_v1 SET revision=revision "
                                "WHERE tenant_id='school-b'").rowcount == 0
        # Legal row shape with an absent/wrong tenant context must fail RLS.
        for selected in ("", "school-a"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
                conn.execute("SELECT set_config('app.pack_tenant',%s,true)", (selected,))
                conn.execute("INSERT INTO reference_pack_tenants_v1 VALUES "
                    "('education','school-c',1,%s::jsonb,%s)",
                    (_canonical({"pin": None, "requests": {}, "governance_receipts": []}), "a" * 64))
    for name in names:
        with getattr(roles, name).connection() as conn:
            for table in TABLES:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute(sql.SQL("DELETE FROM {} WHERE false").format(sql.Identifier(table)))
            if name not in {"receiver", "governor"}:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute("SELECT * FROM reference_pack_tenants_v1")


@pytest.mark.parametrize("problem", ["checksum", "ambiguous"])
def test_bad_source_rolls_back_schema_and_grants_without_changing_legacy_evidence(legacy, problem):
    owner, roles, names, payload, _ = legacy
    if problem == "checksum":
        digest = "0" * 64
    else:
        payload["requests"]["private-a"]["request"] = _canonical([
            "pin", ["school-a", "education", "1"],
            {"receipt": ["", "pin", "ambiguous", "c" * 64]}])
        digest = _digest("education", 6, payload)
    with owner.connection() as conn:
        conn.execute("UPDATE pack_lifecycle SET payload=%s::jsonb,state_digest=%s",
                     (_canonical(payload), digest))
    with pytest.raises(LifecycleError):
        migrate_reference_lifecycle(owner, runtime_roles=names)
    with owner.connection() as conn:
        for table in TABLES:
            assert conn.execute("SELECT to_regclass(%s)", (table,)).fetchone() == (None,)
        assert conn.execute("SELECT payload,state_digest FROM pack_lifecycle").fetchone() == (payload, digest)
    with roles.receiver.connection() as conn:
        assert conn.execute("SELECT count(*) FROM pack_lifecycle").fetchone() == (1,)


def test_migration_requires_explicit_complete_runtime_role_map_before_any_connection():
    class NoConnection:
        def connection(self):
            raise AssertionError("invalid configuration must not open a database")
    with pytest.raises(ValueError, match="exact distinct"):
        migrate_reference_lifecycle(NoConnection(), runtime_roles={"receiver": "only-one"})


def test_migration_keeps_governance_receipt_separate_from_its_pin_target(legacy):
    owner, roles, names, payload, _ = legacy
    original_receipt = ["school-a", "pin", "nonce-a", "c" * 64]
    receipt = ["governance-office", "pin", "nonce-a", "c" * 64]
    payload["governance_receipts"].remove(original_receipt)
    payload["governance_receipts"].append(receipt)
    payload["requests"]["private-a"]["request"] = _canonical([
        "pin", ["school-a", "education", "1"], {"receipt": receipt}])
    with owner.connection() as conn:
        conn.execute("UPDATE pack_lifecycle SET payload=%s::jsonb,state_digest=%s",
                     (_canonical(payload), _digest("education", 6, payload)))
    migrate_reference_lifecycle(owner, runtime_roles=names)
    with roles.receiver.connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.pack_tenant','school-a',true)")
            target = conn.execute("SELECT payload FROM reference_pack_tenants_v1").fetchone()[0]
            assert target["pin"] == "1" and "private-a" not in target["requests"]
            assert receipt not in target["governance_receipts"]
        with conn.transaction():
            conn.execute("SELECT set_config('app.pack_tenant','governance-office',true)")
            governance = conn.execute("SELECT payload FROM reference_pack_tenants_v1").fetchone()[0]
            assert governance["pin"] is None
            assert governance["requests"]["private-a"] == payload["requests"]["private-a"]
            assert governance["governance_receipts"] == [receipt]
