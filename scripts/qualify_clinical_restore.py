"""Logical Health restore with retained finalisation and removal markers.

Two newly owned loopback clusters only. Restored authority remains on HOLD.
This supplements the Education drill; it does not close three-app recovery.
"""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys

from d1_restore_support import (OwnedCluster, inventory, public_inventory,
    reconnect_runtime_pools, restore_runtime_logins, runtime_pools, save)
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.session_credentials import SessionUnavailable
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_COMMITTED,
    Paragraph, Session, build_document)
from factory.health_ui.store import StoreDegraded
from factory.health_ui.templates import CONSULTATION
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError


def access_probe(roles, app):
    """Observe rows under a restricted login; these host settings grant no session."""
    observations = {}
    with roles.project_state.connection() as conn, conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        conn.execute("SELECT set_config('app.project_namespace','health',true)")
        for label, tenant, principal in (
            ("own", app.authenticated.tenant, app.authenticated.principal),
            ("other_clinician", app.authenticated.tenant, "other-clinician"),
            ("other_workspace", "other-workspace", app.authenticated.principal),
        ):
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            conn.execute("SELECT set_config('app.clinician',%s,true)", (principal,))
            visible = conn.execute("SELECT session_id FROM reference_clinical_state_v1 ORDER BY session_id").fetchall()
            removed = conn.execute("SELECT session_id,revision FROM reference_clinical_removals_v1 ORDER BY session_id").fetchall()
            assert (visible, removed) == (([("signed-case",)], [("removed-case", 2)])
                                         if label == "own" else ([], []))
            observations[label] = {"visible": visible, "removals": removed}
    for pool in runtime_pools(roles):
        with pool.connection() as conn:
            assert conn.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit "
                                "FROM pg_roles WHERE rolname=current_user").fetchone() == (False,) * 6
            for table in ("reference_clinical_state_v1", "reference_clinical_removals_v1"):
                assert not conn.execute("SELECT has_table_privilege(current_user,%s,'DELETE,TRUNCATE')", (table,)).fetchone()[0]
                if pool is not roles.project_state:
                    assert not conn.execute("SELECT has_table_privilege(current_user,%s,'SELECT')", (table,)).fetchone()[0]
    return observations


def qualify(root, bins):
    clusters = [OwnedCluster(root, name, bins) for name in ("source-a", "restored-b")]
    a, b = clusters
    result = None
    try:
        domain = a.start()
        roles = provision_local_roles(a.dsn)
        fixture = root / "fictional-health"
        fixture.mkdir()
        app = build_clinical_fixture(roles, fixture)
        document = build_document(CONSULTATION, "Fictional restore record", "signed-case", "Invented subject", [])
        for section in document.sections:
            section.paragraphs.append(Paragraph("Invented qualification text; no patient or clinical advice.",
                                               OBSERVATION, origin=CLINICIAN))
        session = Session("signed-case", "Fictional clinician", "Fixture", "Invented subject",
            "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
            workspace_id=app.clinician.workspace_id, documents=[document])
        app.store.save(session)
        removed = replace(session, session_id="removed-case", documents=[], revision=0)
        app.store.save(removed)
        assert app.store.delete(removed.session_id, removed.owner_id)
        outcome = app.finaliser.finalise(session, document, app.clinician)
        assert outcome.state == FINALISATION_COMMITTED, outcome.detail
        record = next(app.records.rglob("*.docx"))
        artifact = (record.stat().st_mtime_ns, hashlib.sha256(record.read_bytes()).hexdigest())
        assert artifact[1] == outcome.artifact_sha256
        stored = app.store.get(session.session_id, session.owner_id).document(document.doc_id)
        assert app.finaliser.committed_bytes(stored) == record.read_bytes()
        assert stored.frozen_export_digest_version == 3
        assert stored.frozen_export_digest == stored.export_digest(3)
        # Read the exact receipt, then check all its bindings through the public
        # gate. Receipt files survive locally; the DB evidence is restored below.
        raw = app.gate.target_for(str(record), app.clinician.workspace_id)._read_receipt(outcome.nonce, "committed")
        receipt_args = dict(spec=app.spec, out_path=str(record), tenant=app.clinician.workspace_id,
            nonce=outcome.nonce, artifact_sha256=artifact[1], decision_record_hash=raw["decision_record_hash"])
        receipt = app.gate.release_receipt(**receipt_args)
        assert receipt is not None
        assert app.stores.recorder.verify_chain(app.clinician.workspace_id)
        chain = canonical_bytes(app.stores.recorder.entries(app.clinician.workspace_id))
        lineage = app.lineage.get(outcome.nonce)
        assert lineage["evidence"]["authorization_decision"]["record_hash"] == raw["decision_record_hash"]
        assert lineage["evidence"]["qualification_lineage"]["reports"][0]["report_digest"] == app.report.digest()
        save(root / "retained-authorization-lineage.json", lineage)
        access = access_probe(roles, app)
        owner_a = LocalPool(a.dsn, roles.schema, "fixture-backup-owner")
        before = inventory(owner_a, roles)
        assert len(before["tables"]["reference_clinical_state_v1"]) == 2
        assert len(before["tables"]["reference_clinical_removals_v1"]) == 1
        lineage_rows = [row for row in before["tables"]["projectos_states"]
                        if row["namespace"] == app.lineage._pool.namespace]
        assert len(lineage_rows) == 1
        assert lineage_rows[0]["state"]["packet"] == lineage
        save(root / "backup-inventory.json", public_inventory(before))
        dump = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--schema", roles.schema, "--file", dump, "factory_test"], "dump")
        app.sessions.revoke(app.authenticated)
        tail = inventory(owner_a, roles)
        assert tail["tables"]["reference_sessions_v1"] != before["tables"]["reference_sessions_v1"]
        save(root / "known-lost-tail.json", {"event": "clinician-session-revocation-after-backup",
            "before": public_inventory(before)["tables"]["reference_sessions_v1"],
            "after": public_inventory(tail)["tables"]["reference_sessions_v1"], "required_state": "HOLD"})
        a.stop()
        restored_domain = b.start()
        assert restored_domain != domain
        restore_runtime_logins(b, roles)
        b.command("pg_restore", ["--exit-on-error", "-d", "factory_test", dump], "restore")
        owner_b = LocalPool(b.dsn, roles.schema, "fixture-restore-owner")
        restored = inventory(owner_b, roles)
        save(root / "restored-inventory.json", public_inventory(restored))
        assert restored == before, "Data, ownership, policies, grants, constraints or guards differ"
        reconnect_runtime_pools(b, roles)
        assert roles.domain == app.clock.domain == domain
        assert access_probe(roles, app) == access
        assert app.gate.release_receipt(**receipt_args) == receipt
        assert app.stores.recorder.verify_chain(app.clinician.workspace_id)
        assert canonical_bytes(app.stores.recorder.entries(app.clinician.workspace_id)) == chain
        try:
            app.clock.now_us()
        except ClockError:
            pass
        else:
            raise AssertionError("Old clock authority resumed after restore")
        try:
            app.store.get(session.session_id, session.owner_id)
        except StoreDegraded as error:
            assert isinstance(error.__cause__, SessionUnavailable)
            assert isinstance(error.__cause__.__cause__, ClockError)
        else:
            raise AssertionError("Restored session resumed a clinical read")
        try:
            app.lineage.get(outcome.nonce)
        except SessionUnavailable as error:
            assert isinstance(error.__cause__, ClockError)
        else:
            raise AssertionError("Restored session resumed a clinical lineage read")
        # The unchanged finaliser obtains its signing timestamp before its
        # session-bound store operation, so this path refuses directly.
        try:
            app.finaliser.finalise(session, document, app.clinician)
        except ClockError as error:
            assert str(error) == "database authority clock requires the configured primary domain"
        else:
            raise AssertionError("Restored clock resumed clinical finalisation")
        assert inventory(owner_b, roles) == before, "Recovery observation/refusal changed retained state"
        assert list(app.records.rglob("*.docx")) == [record]
        assert (record.stat().st_mtime_ns, hashlib.sha256(record.read_bytes()).hexdigest()) == artifact
        result = {"status": "PASS_HEALTH_LOGICAL_RESTORE_HOLD", "full_D2_D4": "OPEN",
            "source_domain": domain, "restored_domain": restored_domain,
            "backup_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "inventory": public_inventory(before), "restricted_access": access,
            "runtime_logins": len(runtime_pools(roles)), "historical_receipt": "IDENTICAL",
            "evidence_chain": "VERIFIED_IDENTICAL", "retained_removal": "HIDDEN_AFTER_RESTORE",
            "authorization_lineage": "EXACT_BACKUP_AND_RESTORED_BYTES_SESSION_ACCESS_ON_HOLD",
            "session_read_and_finalisation": "REFUSED_OLD_CLOCK_DOMAIN", "resume_authority": "HOLD",
            "limits": ["Logical one-host restore, surviving process keys/passwords and filesystem artifacts.",
                "No cold start, physical G4, PITR, zero RPO, or safe authority resumption.",
                "Post-backup clinician revocation is lost; the restored session must not authorize work.",
                "Historical receipt is unsigned; unchanged signed database evidence is checked separately.",
                "Original fictional file membership survives outside the database; it is not restored here.",
                "Host-selected RLS scope is not isolation from a holder of the raw database login.",
                "No neutral product_spec restore or complete all-table runtime-role qualification in this drill."]}
        return result
    finally:
        failures = []
        for cluster in reversed(clusters):
            try:
                cluster.stop()
            except Exception as error:
                failures.append(type(error).__name__)
        save(root / "CLUSTERS.json", {"clusters": [{"name": c.path.name, "port": c.port,
            "started": c.started, "stopped": c.stopped, "retained": True} for c in clusters],
            "shutdown_failures": failures})
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
        raise SystemExit("Assertions must be enabled; run as an ordinary local user")
    root = args.run_root.absolute()
    if root.resolve() != root or any(p.is_symlink() for p in (root, *root.parents)):
        raise SystemExit("Run root must be normalized with no symlinks")
    root.mkdir(parents=True, exist_ok=False)
    save(root / "OWNER.json", {"purpose": "Fictional Health logical restore", "pid": os.getpid()})
    try:
        result = qualify(root, args.pg_bin.resolve(strict=True))
    except Exception as error:
        save(root / "FAILURE.json", {"error_type": type(error).__name__, "message": str(error), "retained": True})
        raise
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
