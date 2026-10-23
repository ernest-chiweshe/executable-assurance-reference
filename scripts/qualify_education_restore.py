"""D1 scoped Education logical restore into a second new local cluster.

Restore data, ownership, grants, forced RLS, sessions and retained decisions.
Observe a historical receipt and refuse old-domain authority for a pending
effect. Both clusters stop and remain on disk; safe resumption remains OPEN.
"""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys

from d1_restore_support import (OwnedCluster, digest, inventory, public_inventory,
                                reconnect_runtime_pools, restore_runtime_logins,
                                runtime_pools, save)
from assurance_reference.education_workflow import compose_education_workflow
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.session_credentials import SessionUnavailable
from factory.projectos.governed_release import TARGET_FIELD
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError, ClockReading
from regulated_core.qualification import QualificationError
from regulated_core.permit import EmissionError


def review(app, contract, context):
    teacher = replace(context, actor_id="teacher", now_us=app.clock.now_us())
    view = app.gates["teacher"].get_source_review(spec=app.spec, contract=contract, context=teacher)
    confirmed = app.gates["teacher"].confirm_source_review(spec=app.spec, contract=contract,
        context=teacher, expected_material_digest=view["material_digest"], confirmed=True,
        request_id="SCRIPTED-RESTORE-SOURCE-" + context.nonce)
    assert confirmed["confirmed"]
    opened = app.gates["requester"].open_review(spec=app.spec, contract=contract, context=context)
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        result = app.gates[principal].grant_review(spec=app.spec, contract=contract,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
    assert result["status"] == "approved"
    return replace(context, approval=opened["review_id"])


def access_probe(roles, *, partitioned_lifecycle=False):
    """Read-only checks under real restricted logins, with explicit host contexts."""
    result = {}
    for kind, table, setting, extra in (
        ("project_state", "projectos_states", "app.tenant", ("app.project_namespace", "education")),
        ("education_reader", "pack_documents", "app.education_tenant", None),
    ):
        pool = getattr(roles, kind)
        with pool.connection() as conn, conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            if extra:
                conn.execute("SELECT set_config(%s,%s,true)", extra)
            counts = []
            for tenant in ("school-a", "other-school"):
                conn.execute("SELECT set_config(%s,%s,true)", (setting, tenant))
                # Table names are the fixed fixture tables above, never request data.
                counts.append(conn.execute("SELECT count(*) FROM " + table).fetchone()[0])
            assert counts[0] > 0 and counts[1] == 0, (kind, counts)
            result[kind] = {"same_tenant_rows": counts[0], "other_tenant_rows": counts[1]}
    with roles.session_reader.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant','school-a',true)")
        assert conn.execute("SELECT count(*) FROM reference_sessions_v1").fetchone()[0] == 3
        assert not conn.execute("SELECT has_column_privilege(current_user,"
                                "'reference_identities_v1','password_hash','SELECT')").fetchone()[0]
    with roles.receiver.connection() as conn:
        assert not conn.execute("SELECT has_table_privilege(current_user,'pack_documents','SELECT')").fetchone()[0]
    for pool in runtime_pools(roles):
        with pool.connection() as conn:
            row = conn.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit "
                               "FROM pg_roles WHERE rolname=current_user").fetchone()
            assert row == (False,) * 6
    if partitioned_lifecycle:
        with roles.receiver.connection() as conn, conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            assert not conn.execute("SELECT has_table_privilege(current_user,'pack_lifecycle','SELECT')").fetchone()[0]
            counts = []
            for tenant in ("school-a", "other-school"):
                conn.execute("SELECT set_config('app.pack_tenant',%s,true)", (tenant,))
                counts.append(conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone()[0])
            assert counts[0] > 0 and counts[1] == 0
            result["partitioned_lifecycle"] = {"same_tenant_rows": counts[0],
                "other_tenant_rows": counts[1], "retired_legacy_access": False}
    return {**result, "restricted_logins": len(runtime_pools(roles)),
            "session_rows": 3, "session_reader_password_access": False,
            "receiver_education_collection_access": False}


def qualify(root, bins, *, partitioned_lifecycle=False):
    if type(partitioned_lifecycle) is not bool:
        raise TypeError("partitioned_lifecycle must be an explicit boolean")
    a, b = [OwnedCluster(root, name, bins) for name in ("source-a", "restored-b")]
    outcome = None
    try:
        domain = a.start()
        if partitioned_lifecycle:
            from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
            roles = provision_partitioned_local_roles(a.dsn)
        else:
            roles = provision_local_roles(a.dsn)
        assert roles.domain == domain
        fixture = root / "fictional-school"
        fixture.mkdir()
        app = build_education_fixture(roles, fixture, scoped_authority=True,
            partitioned_lifecycle=partitioned_lifecycle,
            # The expanded real-SQL restore setup can exceed the ordinary
            # two-minute fixture lifetime. Issue fresh signed, bounded evidence
            # at creation; never edit an issued report or disable expiry checks.
            fixture_validity_us=600_000_000 if partitioned_lifecycle else 120_000_000)
        assert app.report.expires_at_us - app.report.qualified_at_us == (
            600_000_000 if partitioned_lifecycle else 120_000_000)
        if partitioned_lifecycle:
            # Read-only boundary observations of the actual signed drill report.
            # The live authority clock is never changed, paused or replaced.
            qualifications = app.gates["requester"]._engine._qualifications
            assert qualifications.check(ClockReading(domain, app.report.expires_at_us - 1))[0] == (
                app.report.digest(),)
            for observed in (app.report.expires_at_us, app.report.expires_at_us + 1):
                try:
                    qualifications.check(ClockReading(domain, observed))
                except QualificationError as error:
                    assert str(error) == "qualification report is not current"
                else:
                    raise AssertionError("expired drill evidence was accepted")
            save(root / "qualification-expiry-observation.json", {
                "report_sha256": app.report.digest(), "validity_us": 600_000_000,
                "before_expiry": "VALID", "at_and_after_expiry": "REFUSED",
                "basis": "Synthetic readings checked against the actual signed report; no live-clock mutation"})
        state, release = compose_education_workflow(app)
        state.create("geometry", {"contract": app.contract, "source_material": app.scoped.retained})
        context = replace(app.context, release_target=str(app.path),
                          retained_state=state.load("geometry")["source_material"])
        prepared = release.contract("geometry", tenant="school-a", context=context)
        contract = prepared.for_approval()
        context = review(app, contract, context)
        release.release("geometry", str(app.path), context)
        observation = release.observe("geometry", str(app.path), context)
        assert (observation.outcome.state == "committed" and observation.receipt is not None
                and observation.receiving_record is not None)
        assert app.path.read_bytes() == prepared.prepared.content
        artifact_stat = (app.path.stat().st_mtime_ns, hashlib.sha256(app.path.read_bytes()).hexdigest())
        # A different nonce and target yield a genuinely pending, approved permit.
        pending_path = fixture / "pending-feedback.txt"
        pending_context = replace(app.context, nonce="restore-pending", now_us=app.clock.now_us(),
                                  release_target=str(pending_path))
        pending_contract = {**app.contract, TARGET_FIELD: app.gates["requester"].describe_target(
            spec=app.spec, out_path=str(pending_path), context=pending_context)}
        pending_context = review(app, pending_contract, pending_context)
        pending = app.gates["requester"].authorize_release(spec=app.spec, contract=pending_contract,
            out_path=str(pending_path), context=pending_context, artifact=app.body)
        assert pending.allowed, pending.reason
        assert not pending_path.exists()
        assert app.stores.recorder.verify_chain("school-a")
        chain = canonical_bytes(app.stores.recorder.entries("school-a"))
        source_access = access_probe(roles, partitioned_lifecycle=partitioned_lifecycle)
        owner_a = LocalPool(a.dsn, roles.schema, "fixture-backup-owner")
        before_representation = {}
        before = inventory(owner_a, roles, representations=before_representation)
        save(root / "source-raw-acl-representations.json", before_representation)
        if partitioned_lifecycle:
            from assurance_reference.role_contract import PARTITIONED_TABLES, collect_access_matrix
            assert len(before["tables"]) == 38 and PARTITIONED_TABLES <= before["tables"].keys()
            source_duties = collect_access_matrix(roles, partitioned_lifecycle=True)
            assert source_duties["privilege_contract_matches"], source_duties["errors"]
            save(root / "source-role-access-matrix.json", source_duties)
        # Store only row counts and digests in the public report. The local dump
        # contains explicitly fictional session hashes and must remain local.
        save(root / "backup-inventory.json", public_inventory(before))
        (root / "public-evidence.json").write_bytes(canonical_bytes({
            "public_keys": app.public_keys, "chain": app.stores.recorder.entries("school-a"),
            "receipt": observation.receipt, "pending_permit": pending.permit.permit,
            "fixture": "Scripted fictional identities, appointments and source confirmation"}))
        dump = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--schema", roles.schema, "--file", dump, "factory_test"], "dump")
        # Explicit known lost tail: revocation after backup. A restored active
        # session is not current authority and MUST NOT be resumed on that basis.
        app.sessions.revoke(app.identities["requester"])
        tail = inventory(owner_a, roles)
        assert tail["tables"]["reference_sessions_v1"] != before["tables"]["reference_sessions_v1"]
        save(root / "known-lost-tail.json", {"event": "requester-session-revocation-after-backup",
             "session_tables_before_sha256": digest(before["tables"]["reference_sessions_v1"]),
             "session_tables_after_sha256": digest(tail["tables"]["reference_sessions_v1"]),
             "restore_must_remain": "HOLD"})
        a.stop()
        restored_domain = b.start()
        assert domain != restored_domain
        restore_runtime_logins(b, roles)
        # Ownership and ACL restoration are mandatory: never --no-owner or --no-privileges.
        b.command("pg_restore", ["--exit-on-error", "-d", "factory_test", dump], "restore")
        owner_b = LocalPool(b.dsn, roles.schema, "fixture-restore-owner")
        restored_representation = {}
        restored = inventory(owner_b, roles, representations=restored_representation)
        save(root / "restored-raw-acl-representations.json", restored_representation)
        save(root / "acl-representation-comparison.json", {
            "raw_representations_equal": before_representation == restored_representation,
            "effective_catalog_equal": restored["catalog"] == before["catalog"],
            "classification": ("representation differs, effective identical"
                if before_representation != restored_representation and restored["catalog"] == before["catalog"]
                else "identical" if restored["catalog"] == before["catalog"] else "effective difference: review required")})
        save(root / "restored-inventory.json", public_inventory(restored))
        if restored["catalog"] != before["catalog"]:
            save(root / "catalog-differences.json", {
                key: {"before": before["catalog"][key], "after": restored["catalog"][key]}
                for key in before["catalog"] if before["catalog"][key] != restored["catalog"][key]})
        assert restored == before, "Restored data/ownership/grants/RLS/guards differ from backup"
        reconnect_runtime_pools(b, roles)
        assert roles.domain == domain and app.clock.domain == domain
        assert access_probe(roles, partitioned_lifecycle=partitioned_lifecycle) == source_access
        if partitioned_lifecycle:
            restored_duties = collect_access_matrix(roles, partitioned_lifecycle=True)
            save(root / "restored-role-access-matrix.json", restored_duties)
            assert restored_duties == source_duties
        assert app.stores.recorder.verify_chain("school-a")
        assert canonical_bytes(app.stores.recorder.entries("school-a")) == chain
        # Observe the historical receiver receipt directly; no fresh authority is
        # needed or implied by recovering a receipt. Do not bypass session gates
        # to operate the restored Project OS workflow.
        historical = app.gates["requester"].release_receipt(spec=app.spec, out_path=str(app.path),
            tenant="school-a", nonce=context.nonce, artifact_sha256=artifact_stat[1],
            decision_record_hash=observation.receipt["decision_record_hash"])
        assert historical is not None
        assert canonical_bytes(historical) == canonical_bytes(observation.receipt)
        receiving_record = app.gates["requester"].verified_release_outcome(
            spec=app.spec, tenant="school-a", decision=observation.decision)
        assert receiving_record is not None
        assert canonical_bytes(receiving_record) == canonical_bytes(observation.receiving_record)
        assert inventory(owner_b, roles) == before, "Read-only recovery changed backed-up state"
        try:
            app.clock.now_us()
        except ClockError:
            pass
        else:
            raise AssertionError("Restored cluster silently resumed old clock authority")
        try:
            state.load("geometry")
        except SessionUnavailable as error:
            assert isinstance(error.__cause__, ClockError), "Unexpected session failure"
        else:
            raise AssertionError("Restored pre-revocation session resumed the workflow")
        # The real receiver still owns the decision. No synthetic guard failure,
        # mock clock, re-signed permit, domain rebinding or switched-off check.
        try:
            app.gates["requester"].commit_release(spec=app.spec, contract=pending_contract,
                context=pending_context, decision=pending, artifact=app.body, out_path=str(pending_path))
        except EmissionError as error:
            assert str(error) == "authority clock unavailable"
            assert isinstance(error.__cause__, ClockError)
            assert str(error.__cause__) == "database authority clock requires the configured primary domain"
        else:
            raise AssertionError("Old-domain pending request was not refused before target handoff")
        assert not pending_path.exists()
        assert (app.path.stat().st_mtime_ns, hashlib.sha256(app.path.read_bytes()).hexdigest()) == artifact_stat
        after = inventory(owner_b, roles)
        for table in before["tables"]:
            if table == "reference_alerts_v1":
                continue  # a retained uncertainty/refusal alert is allowed
            assert after["tables"][table] == before["tables"][table], table
        assert after["catalog"] == before["catalog"]
        assert app.stores.recorder.verify_chain("school-a")
        outcome = {"status": "PASS_D1_LOGICAL_RESTORE_HOLD", "full_D1": "OPEN",
            "lifecycle_profile": "partitioned-v1" if partitioned_lifecycle else "original",
            "fixture_evidence_validity_us": 600_000_000 if partitioned_lifecycle else 120_000_000,
            "source_domain": domain, "restored_domain": restored_domain,
            "backup_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "inventory": public_inventory(before), "restricted_access": source_access,
            "historical_receipt": "IDENTICAL_RECEIVER_RECORD_NO_NEW_EFFECT", "evidence_chain": "VERIFIED_IDENTICAL",
            "old_domain": "REFUSED", "pending_effect": "REFUSED_BEFORE_TARGET_HANDOFF", "pending_file_exists": False,
            "restored_session_workflow": "REFUSED_SESSION_TIME_UNAVAILABLE",
            "known_post_backup_session_revocation": "LOST_IN_RESTORE", "resume_authority": "HOLD",
            "limits": ["One-host logical database restore; no physical loss, PITR or zero-RPO claim.",
                "Surviving fixture process retains keys/passwords and filesystem artifacts; not cold-start recovery.",
                "The receiver receipt is unsigned; its authenticated support is the unchanged verified evidence chain.",
                "Eleven restricted logins and exact ACL/RLS restoration; host passwords remain trusted.",
                "Scripted fictional Education appointments and source confirmation, not human qualification.",
                "No old-domain migration or safe authority resumption; physical G4 remains OPEN.",
                "No external effects, deployed HSM, compliance WORM or complete D4 qualification.",
                "Post-backup session revocation is deliberately absent from restored data; HOLD is required."]}
        return outcome
    finally:
        failures = []
        for cluster in (b, a):
            try:
                cluster.stop()
            except Exception as error:
                failures.append(type(error).__name__)
        save(root / "CLUSTERS.json", {"clusters": [{"name": c.path.name, "port": c.port,
            "started": c.started, "stopped": c.stopped, "retained": True} for c in (a, b)],
            "shutdown_failures": failures})
        if failures:
            raise RuntimeError("Owned cluster shutdown needs attention; see CLUSTERS.json")
        if outcome is not None:
            save(root / "RESULT.json", outcome)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--fictional-fixture", action="store_true", required=True)
    parser.add_argument("--partitioned-lifecycle", action="store_true",
                        help="Explicitly provision and restore the reference lifecycle partition schema")
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit("Assertions must remain enabled")
    if os.name != "nt" and os.geteuid() == 0:
        raise SystemExit("Run as an ordinary local user")
    root = args.run_root.absolute()
    if root.resolve() != root or any(p.is_symlink() for p in (root, *root.parents)):
        raise SystemExit("Run root must be normalized and contain no symlinks")
    root.mkdir(parents=True, exist_ok=False)
    save(root / "OWNER.json", {"purpose": "D1 fictional Education logical restore", "pid": os.getpid()})
    try:
        result = qualify(root, args.pg_bin.resolve(strict=True),
                         partitioned_lifecycle=args.partitioned_lifecycle)
    except Exception as error:
        save(root / "FAILURE.json", {"error_type": type(error).__name__, "message": str(error), "retained": True})
        raise
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
