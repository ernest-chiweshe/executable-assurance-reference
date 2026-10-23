"""One logical snapshot containing Education, Health and neutral product_spec.

Restricted runtime roles create all three fictional releases in one fresh
schema. Ownership, grants, forced RLS and exact rows survive the restore.
Historical receipts remain observations; old-domain sessions stay on HOLD.
No public delivery, provider, production database or live cloud is involved.
"""

import argparse
import hashlib
import os
from pathlib import Path
import sys

from d1_restore_support import (OwnedCluster, inventory, public_inventory, reconnect_runtime_pools,
    restore_runtime_logins, save)
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_roles import LocalPool
from assurance_reference.role_contract import collect_access_matrix
from assurance_reference.session_credentials import SessionUnavailable
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError


def applications(matrix):
    return (("education", matrix.education, matrix.education.identities["requester"]),
            ("health", matrix.health, matrix.health.authenticated),
            ("product_spec", matrix.product_spec, matrix.product_spec.identities["requester"]))


def receipt(app, name):
    if name == "health":
        gate, nonce = app.gate, app.release_outcome.nonce
        tenant = app.authenticated.tenant
        record_hash = app.lineage_snapshot["evidence"]["authorization_decision"]["record_hash"]
    else:
        gate, nonce = app.gates["requester"], app.release_context.nonce
        tenant = app.identities["requester"].tenant
        record_hash = app.release_observation.receipt["decision_record_hash"]
    found = gate.release_receipt(spec=app.spec, out_path=str(app.path), tenant=tenant, nonce=nonce,
        artifact_sha256=hashlib.sha256(app.path.read_bytes()).hexdigest(), decision_record_hash=record_hash)
    assert found is not None
    return canonical_bytes(found)


def qualify(root, bins):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from three_application_fixture import compose_and_release, project_scope_observation

    a, b = [OwnedCluster(root, name, bins) for name in ("source-a", "restored-b")]
    result = None
    try:
        domain = a.start()
        roles = provision_partitioned_local_roles(a.dsn)
        fixture = root / "fictional-three-applications"
        fixture.mkdir()
        matrix = compose_and_release(roles, fixture)
        observations = project_scope_observation(matrix)
        chains, receipts, artifacts = {}, {}, {}
        for name, app, identity in applications(matrix):
            assert app.clock.domain == domain
            assert app.stores.recorder.verify_chain(identity.tenant)
            chains[name] = canonical_bytes(app.stores.recorder.entries(identity.tenant))
            receipts[name] = receipt(app, name)
            artifacts[name] = (app.path.stat().st_mtime_ns, hashlib.sha256(app.path.read_bytes()).hexdigest())
        owner_a = LocalPool(a.dsn, roles.schema, "fixture-backup-owner")
        raw_before = {}
        before = inventory(owner_a, roles, representations=raw_before)
        assert len(before["tables"]) == 38
        assert len(before["tables"]["projectos_states"]) == 3
        assert len(before["tables"]["reference_clinical_state_v1"]) == 1
        assert matrix.product_spec.domain_packs == ()
        duties = collect_access_matrix(roles, partitioned_lifecycle=True)
        assert duties["privilege_contract_matches"], duties["errors"]
        save(root / "source-role-access-matrix.json", duties)
        save(root / "source-raw-acl.json", raw_before)
        save(root / "backup-inventory.json", public_inventory(before))
        save(root / "project-scope-matrix.json", observations)
        # Fixture key labels overlap across independent application trust scopes.
        # Keep public key sets with their respective evidence, never merge them.
        save(root / "application-trust-scopes.json", {name: {"tenant": identity.tenant,
            "public_keys": app.public_keys} for name, app, identity in applications(matrix)})
        dump = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--schema", roles.schema, "--file", dump, "factory_test"], "dump")
        for _, app, identity in applications(matrix):
            app.sessions.revoke(identity)
        tail = inventory(owner_a, roles)
        assert tail["tables"]["reference_sessions_v1"] != before["tables"]["reference_sessions_v1"]
        save(root / "known-lost-tail.json", {"event": "three-requester-session-revocations-after-backup",
            "before": public_inventory(before)["tables"]["reference_sessions_v1"],
            "after": public_inventory(tail)["tables"]["reference_sessions_v1"], "restore_must_remain": "HOLD"})
        a.stop()
        restored_domain = b.start()
        assert domain != restored_domain
        restore_runtime_logins(b, roles)
        b.command("pg_restore", ["--exit-on-error", "-d", "factory_test", dump], "restore")
        owner_b = LocalPool(b.dsn, roles.schema, "fixture-restore-owner")
        raw_after = {}
        restored = inventory(owner_b, roles, representations=raw_after)
        save(root / "restored-raw-acl.json", raw_after)
        save(root / "restored-inventory.json", public_inventory(restored))
        assert restored == before, "Shared snapshot data/effective ACL/ownership/RLS/guards differ"
        reconnect_runtime_pools(b, roles)
        assert project_scope_observation(matrix) == observations
        restored_duties = collect_access_matrix(roles, partitioned_lifecycle=True)
        save(root / "restored-role-access-matrix.json", restored_duties)
        assert restored_duties == duties
        for name, app, identity in applications(matrix):
            assert app.stores.recorder.verify_chain(identity.tenant)
            assert canonical_bytes(app.stores.recorder.entries(identity.tenant)) == chains[name]
            assert receipt(app, name) == receipts[name]
            assert (app.path.stat().st_mtime_ns, hashlib.sha256(app.path.read_bytes()).hexdigest()) == artifacts[name]
            try:
                app.clock.now_us()
            except ClockError:
                pass
            else:
                raise AssertionError(name + " resumed old-domain time")
        readers = {
            "education": lambda: matrix.education.workflow_state.load("geometry"),
            "health": lambda: matrix.health.lineage.get(matrix.health.release_outcome.nonce),
            "product_spec": lambda: matrix.product_spec.state.load("geometry"),
        }
        for name, read in readers.items():
            try:
                read()
            except SessionUnavailable as error:
                assert isinstance(error.__cause__, ClockError)
            else:
                raise AssertionError(name + " resumed the restored pre-revocation session")
        assert inventory(owner_b, roles) == before
        result = {"status": "PASS_THREE_APPLICATION_LOGICAL_RESTORE_HOLD", "claims_promoted": 0,
            "source_domain": domain, "restored_domain": restored_domain, "schema_count": 1,
            "snapshot_count": 1, "tables": 38, "runtime_roles": 11,
            "applications": [name for name, _, _ in applications(matrix)],
            "historical_chains_and_receipts": "IDENTICAL", "project_scope_matrix": observations,
            "restored_sessions": "REFUSED_OLD_CLOCK_DOMAIN", "resume_authority": "HOLD",
            "raw_acl_representations_equal": raw_before == raw_after, "effective_catalog_equal": True,
            "backup_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "limits": ["Surviving process keys/passwords, file membership and artifacts; not a cold start.",
                "Application fixture trust scopes remain separate; no deployed common key directory claim.",
                "No physical G4, PITR, zero RPO or safe authority resumption.",
                "Known post-backup revocations are lost and all restored sessions stay on HOLD.",
                "No post-restore pending effect was attempted in this drill.",
                "Host-selected RLS settings do not isolate holders of the raw database login."]}
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
    save(root / "OWNER.json", {"purpose": "Fictional three-application logical restore", "pid": os.getpid()})
    try:
        result = qualify(root, bins)
    except Exception as error:
        save(root / "FAILURE.json", {"error_type": type(error).__name__, "message": str(error)})
        raise
    print(result["status"])


if __name__ == "__main__":
    main()
