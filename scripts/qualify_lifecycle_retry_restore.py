"""Populated lifecycle retry restore in two newly owned loopback clusters.

Two distinct evidence classes are retained: a labelled synthetic legacy row
with installation/private retries, and a current signed tier-4 pin with an
exact retry through the unchanged governance checks. After restore only
historical observations run; the old authority clock must refuse. No resume,
physical durability or integrated three-application completion is claimed.
"""

import argparse
from dataclasses import fields
import hashlib
import os
from pathlib import Path
import sys

from d1_restore_support import (OwnedCluster, inventory, public_inventory, reconnect_runtime_pools,
    restore_runtime_logins, save)
from assurance_reference.lifecycle_migration import migrate_reference_lifecycle
from assurance_reference.lifecycle_partition import _empty_scope, restore_partition
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.packs import verify_bundles
from assurance_reference.role_contract import collect_access_matrix
from factory.packs.lifecycle_pg import _canonical, _digest
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError
from regulated_core.target import Outcome


def retry_observation(tables, legacy_payload, *, current_pack, governance_tenant):
    """Read-only evidence assertions; empty retry tables cannot satisfy this drill."""
    shared = {row["pack_id"]: row for row in tables["reference_pack_shared_v1"]}
    tenants = tables["reference_pack_tenants_v1"]
    installation = tables["reference_pack_installation_retries_v1"]
    index = tables["reference_pack_retry_index_v1"]
    assert len([row for row in installation if row["pack_id"] == "education"]) == 1
    scopes = {row["tenant_id"]: row["payload"] for row in tenants if row["pack_id"] == "education"}
    scope = next(row for row in installation if row["pack_id"] == "education")
    scopes[None] = {**_empty_scope(), "requests": scope["requests"]}
    restored = restore_partition("education", {"shared": shared["education"]["payload"],
        "scopes": scopes, "retry_index": {row["key_digest"]: row["request_digest"]
            for row in index if row["pack_id"] == "education"}})
    assert _canonical(restored) == _canonical(legacy_payload)
    assert set(scopes[None]["requests"]) == {"install-one", "install-two", "global-rollback"}
    assert set(scopes["school-a"]["requests"]) == {"private-a", "private-revoke"}
    assert set(scopes["school-b"]["requests"]) == {"private-b"}
    current = next(row["payload"] for row in tenants
                   if row["pack_id"] == current_pack and row["tenant_id"] == governance_tenant)
    assert set(current["requests"]) == {"restore-guarded-retry"}
    assert current["governance_receipts"]
    assert len([row for row in index if row["pack_id"] == current_pack]) == 1
    restore_partition(current_pack, {"shared": shared[current_pack]["payload"],
        "scopes": {row["tenant_id"]: row["payload"] for row in tenants if row["pack_id"] == current_pack},
        "retry_index": {row["key_digest"]: row["request_digest"]
                        for row in index if row["pack_id"] == current_pack}})
    return {"synthetic_legacy_installation_retries": 3, "synthetic_legacy_private_retries": 3,
            "current_guarded_private_retries": 1, "total_retry_index_rows": len(index),
            "legacy_roundtrip": "EXACT", "effect_resumption": "NOT_ATTEMPTED"}


def scope_observation(roles, governance_tenant):
    """Actual restricted reads; host-selected settings do not grant a session."""
    observed = {}
    for kind in ("receiver", "governor"):
        with getattr(roles, kind).connection() as conn, conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            for tenant in ("", "school-a", "school-b", governance_tenant, "school-current", "foreign"):
                conn.execute("SELECT set_config('app.pack_tenant',%s,true)", (tenant,))
                rows = conn.execute("SELECT tenant_id,payload FROM reference_pack_tenants_v1 "
                                    "ORDER BY pack_id,tenant_id").fetchall()
                assert all(row[0] == tenant for row in rows)
                if tenant in {"", "foreign"}:
                    assert rows == []
                else:
                    assert len(rows) == 1
                observed[kind + ":" + tenant] = {"rows": len(rows),
                    "payload_sha256": hashlib.sha256(_canonical(rows).encode()).hexdigest()}
    return observed


def qualify(root, bins):
    # These are explicit fictional qualification fixtures, not runtime imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from partitioned_governance_fixture import GovernedFixture
    from test_lifecycle_partition import legacy_snapshot

    a, b = [OwnedCluster(root, name, bins) for name in ("source-a", "restored-b")]
    result = None
    try:
        domain = a.start()
        roles = provision_local_roles(a.dsn)
        owner_a = LocalPool(a.dsn, roles.schema, "fixture-migration-owner")
        names = {field.name: getattr(roles, field.name).role for field in fields(roles)
                 if field.name not in {"schema", "domain"}}
        legacy = legacy_snapshot()
        # A synthetic backup fixture inserted into a fresh owned schema. It is
        # never described as a historical deployment or guarded execution.
        with owner_a.connection() as conn:
            conn.execute("INSERT INTO pack_lifecycle VALUES (%s,%s,%s::jsonb,%s)",
                ("education", 6, _canonical(legacy), _digest("education", 6, legacy)))
        migration = migrate_reference_lifecycle(owner_a, runtime_roles=names)
        assert migration["source_rows"] == 1
        app = GovernedFixture(roles)
        first, second = (item["reference"] for item in verify_bundles()["bundles"])
        pack = first.partition("#")[0]
        assert pack != "education", "synthetic legacy and current guarded evidence must stay distinct"
        tenant = "retry-restore-governance"
        for reference in (first, second):
            committed, _, _, _ = app.enact(tenant, {"activate": reference, "at": "fictional restore"})
            assert committed.outcome is Outcome.COMMITTED, committed.detail
        original_pin = app.packs.ledger.pin
        callbacks = []

        def exact_retry(*args, **kwargs):
            receiving = kwargs["before_commit"]

            def checked():
                receiving()
                callbacks.append("original receiving check")

            kwargs.update(idempotency_key="restore-guarded-retry", before_commit=checked)
            answer = original_pin(*args, **kwargs)
            assert original_pin(*args, **kwargs) == answer
            return answer

        app.packs.ledger.pin = exact_retry
        try:
            committed, target, authorization, output = app.enact(
                tenant, {"pin": first, "tenant": "school-current"})
        finally:
            app.packs.ledger.pin = original_pin
        assert committed.outcome is Outcome.COMMITTED, committed.detail
        assert callbacks == ["original receiving check"]
        receipt_key = (tenant, target.operation, authorization.permit.permit.nonce,
                       hashlib.sha256(output).hexdigest())
        assert app.packs.governance_receipt(*receipt_key) is Outcome.COMMITTED
        assert app.recorder.verify_chain(tenant)
        chain = canonical_bytes(app.recorder.entries(tenant))
        scopes = scope_observation(roles, tenant)
        raw_before = {}
        before = inventory(owner_a, roles, representations=raw_before)
        observation = retry_observation(before["tables"], legacy, current_pack=pack, governance_tenant=tenant)
        assert observation["total_retry_index_rows"] == 7
        duties = collect_access_matrix(roles, partitioned_lifecycle=True)
        assert duties["privilege_contract_matches"], duties["errors"]
        save(root / "source-role-access-matrix.json", duties)
        save(root / "source-raw-acl.json", raw_before)
        save(root / "backup-inventory.json", public_inventory(before))
        save(root / "retry-evidence.json", observation)
        dump = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--schema", roles.schema, "--file", dump, "factory_test"], "dump")
        a.stop()
        restored_domain = b.start()
        assert restored_domain != domain
        restore_runtime_logins(b, roles)
        b.command("pg_restore", ["--exit-on-error", "-d", "factory_test", dump], "restore")
        owner_b = LocalPool(b.dsn, roles.schema, "fixture-restore-owner")
        raw_after = {}
        restored = inventory(owner_b, roles, representations=raw_after)
        save(root / "restored-raw-acl.json", raw_after)
        save(root / "restored-inventory.json", public_inventory(restored))
        assert restored == before, "Exact data/effective ACL/ownership/RLS/guards changed"
        assert retry_observation(restored["tables"], legacy, current_pack=pack,
                                 governance_tenant=tenant) == observation
        reconnect_runtime_pools(b, roles)
        assert scope_observation(roles, tenant) == scopes
        restored_duties = collect_access_matrix(roles, partitioned_lifecycle=True)
        save(root / "restored-role-access-matrix.json", restored_duties)
        assert restored_duties == duties
        assert app.recorder.verify_chain(tenant)
        assert canonical_bytes(app.recorder.entries(tenant)) == chain
        assert app.packs.governance_receipt(*receipt_key) is Outcome.COMMITTED
        try:
            app.clock.now_us()
        except ClockError:
            pass
        else:
            raise AssertionError("Restored authority resumed its old clock domain")
        assert inventory(owner_b, roles) == before
        result = {"status": "PASS_POPULATED_LIFECYCLE_RESTORE_HOLD", "claims_promoted": 0,
            "source_domain": domain, "restored_domain": restored_domain,
            "retry_evidence": observation, "historical_guarded_receipt": "IDENTICAL_COMMITTED",
            "restricted_tenant_observations": scopes,
            "evidence_chain": "VERIFIED_IDENTICAL", "restored_authority": "HOLD",
            "raw_acl_representations_equal": raw_before == raw_after, "effective_catalog_equal": True,
            "backup_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "limits": ["Synthetic legacy history is fixture data, not proof of historical execution.",
                "Current guarded pin uses synthetic tier-4 identities and in-memory clearance custody.",
                "No post-restore transition or replay was executed; safe resumption remains OPEN.",
                "Host-selected RLS contexts do not isolate a holder of the raw database login.",
                "Surviving process keys/passwords; no cold start, physical G4 or integrated three-app restore."]}
        return result
    finally:
        failures = []
        for cluster in (b, a):
            try:
                cluster.stop()
            except Exception as error:
                failures.append(type(error).__name__)
        save(root / "CLUSTERS.json", {"clusters": [{"name": c.path.name, "port": c.port,
            "started": c.started, "stopped": c.stopped} for c in (a, b)], "shutdown_failures": failures})
        if failures:
            raise RuntimeError("Owned cluster shutdown needs attention")
        if result is not None:
            save(root / "RESULT.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--fictional-fixture", action="store_true", required=True)
    args = parser.parse_args()
    if sys.flags.optimize or (os.name != "nt" and os.geteuid() == 0):
        raise SystemExit("Assertions must be enabled; use an ordinary local user")
    root = args.run_root.absolute()
    if root.resolve() != root or any(p.is_symlink() for p in (root, *root.parents)):
        raise SystemExit("Run root must be normalized with no symlinks")
    bins = args.pg_bin.resolve(strict=True)
    root.mkdir(parents=True, exist_ok=False)
    save(root / "OWNER.json", {"purpose": "Fictional populated lifecycle retry restore", "pid": os.getpid()})
    try:
        result = qualify(root, bins)
    except Exception as error:
        save(root / "FAILURE.json", {"error_type": type(error).__name__, "message": str(error)})
        raise
    print(result["status"])


if __name__ == "__main__":
    main()
