"""Restore neutral product_spec state without resuming old authority.

Uses explicit offline stages, no domain packs or providers, and two new owned
loopback clusters. Existing Education and Health drills remain complementary.
"""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from d1_restore_support import (OwnedCluster, inventory, public_inventory,
    reconnect_runtime_pools, restore_runtime_logins, runtime_pools, save)
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.session_credentials import SessionUnavailable
from factory.projectos.regulated import EmissionContext
from factory.verticals.product_spec.export import render_product_spec_markdown
from regulated_core.canonical import canonical_bytes
from regulated_core.clock import ClockError
from regulated_core.permit import EmissionError


class ScriptedFactory:
    """An explicitly synthetic stage verdict, not model or product validation."""

    def run(self, prompt, profile, tenant, *, context):
        assert profile.gate_checks == frozenset({"input-guardrail", "grounded-critic"})
        return SimpleNamespace(output=("A fictional workshop needs a local inventory tool. "
            "Users record each item, its location and the date of the latest count. "
            "The proposed workflow keeps a readable history and requires a second person to review changes. "
            "A successful trial lets staff find a listed item and reconcile an incorrect count. "
            "The interface displays the current count, previous entries and the reason for each adjustment. "
            "Acceptance checks cover missing names, duplicated identifiers, stale updates and unavailable storage. "
            "This text is a scripted test fixture, with no generated model verdict or product validation claim."),
            accepted=True, gate_reason="Explicit scripted fixture verdict", run_id="offline-restore-fixture",
            cost_usd=0, harness_name="scripted-no-provider")


def prepare(app, project, path):
    app.engine.new(project, title="Fictional inventory", idea="A local workshop fixture")
    for stage in ("problem", "solution", "scope", "spec"):
        app.engine.run_stage(project, stage, tenant=app.tenant)
    now = app.clock.now_us()
    context = EmissionContext(tenant=app.tenant, actor_id="requester", project_id=project,
        vertical_name=app.spec.name, action_id="release", nonce="restore-" + project,
        now_us=now, not_after_us=now + 30_000_000, release_target=str(path))
    _, assembled = app.engine.assemble(project, tenant=app.tenant, context=context)
    assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
    prepared = app.engine._governed_release().contract(project, tenant=app.tenant, context=context)
    contract = prepared.for_approval()
    opened = app.engine.open_review(project, context=context)
    granted = app.gates["reviewer"].grant_review(spec=app.spec, contract=contract,
        context=replace(context, actor_id="reviewer", now_us=app.clock.now_us()),
        review_id=opened["review_id"], role="reviewer")
    assert granted["status"] == "approved"
    return replace(context, approval=opened["review_id"]), contract, prepared.prepared.content


def access_probe(roles, app):
    """Read-only host-scope observations under real restricted credentials."""
    with roles.project_state.connection() as conn, conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        observations = {}
        for label, tenant, namespace in (("own", app.tenant, "product-spec"),
            ("other_tenant", "other-tenant", "product-spec"), ("other_namespace", app.tenant, "education")):
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            conn.execute("SELECT set_config('app.project_namespace',%s,true)", (namespace,))
            count = conn.execute("SELECT count(*) FROM projectos_states").fetchone()[0]
            assert count == (2 if label == "own" else 0)
            observations[label] = count
    with roles.receiver.connection() as conn:
        assert conn.execute("SELECT count(*) FROM pack_lifecycle").fetchone() == (0,)
    for pool in runtime_pools(roles):
        with pool.connection() as conn:
            assert conn.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit "
                                "FROM pg_roles WHERE rolname=current_user").fetchone() == (False,) * 6
            assert not conn.execute("SELECT has_table_privilege(current_user,'projectos_states','DELETE,TRUNCATE')").fetchone()[0]
    return observations


def qualify(root, bins):
    clusters = [OwnedCluster(root, name, bins) for name in ("source-a", "restored-b")]
    a, b = clusters
    result = None
    try:
        domain = a.start()
        roles = provision_local_roles(a.dsn)
        fixture = root / "fictional-product-spec"
        fixture.mkdir()
        app = build_product_spec_fixture(roles, fixture, factory=ScriptedFactory())
        context, _, expected = prepare(app, "inventory", app.path)
        rendered = render_product_spec_markdown(app.engine.contract("inventory"))
        app.engine.release("inventory", str(app.path), context=context)
        observed = app.engine.observe_release("inventory", str(app.path), context=context)
        assert observed.outcome.state == "committed"
        assert observed.receipt is not None and observed.receiving_record is not None
        assert app.path.read_bytes() == expected
        assert app.path.read_text(encoding="utf-8") == rendered
        artifact = (app.path.stat().st_mtime_ns, hashlib.sha256(expected).hexdigest())
        pending_path = fixture / "pending-product-spec.md"
        pending_context, pending_contract, pending_bytes = prepare(app, "pending", pending_path)
        pending = app.gates["requester"].authorize_release(spec=app.spec, contract=pending_contract,
            out_path=str(pending_path), context=pending_context, artifact=pending_bytes)
        assert pending.allowed, pending.reason
        assert not pending_path.exists() and app.domain_packs == ()
        assert app.stores.recorder.verify_chain(app.tenant)
        chain = canonical_bytes(app.stores.recorder.entries(app.tenant))
        access = access_probe(roles, app)
        owner_a = LocalPool(a.dsn, roles.schema, "fixture-backup-owner")
        before = inventory(owner_a, roles)
        save(root / "backup-inventory.json", public_inventory(before))
        dump = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--schema", roles.schema, "--file", dump, "factory_test"], "dump")
        app.sessions.revoke(app.identities["requester"])
        tail = inventory(owner_a, roles)
        assert tail["tables"]["reference_sessions_v1"] != before["tables"]["reference_sessions_v1"]
        save(root / "known-lost-tail.json", {"event": "requester-session-revocation-after-backup",
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
        assert restored == before, "Restored data, ownership, access controls or guards differ"
        reconnect_runtime_pools(b, roles)
        assert roles.domain == app.clock.domain == domain
        assert access_probe(roles, app) == access
        receipt = app.gates["requester"].release_receipt(spec=app.spec, out_path=str(app.path),
            tenant=app.tenant, nonce=context.nonce, artifact_sha256=artifact[1],
            decision_record_hash=observed.receipt["decision_record_hash"])
        assert receipt == observed.receipt
        receiving = app.gates["requester"].verified_release_outcome(spec=app.spec,
            tenant=app.tenant, decision=observed.decision)
        assert canonical_bytes(receiving) == canonical_bytes(observed.receiving_record)
        assert app.stores.recorder.verify_chain(app.tenant)
        assert canonical_bytes(app.stores.recorder.entries(app.tenant)) == chain
        assert inventory(owner_b, roles) == before
        try:
            app.state.load("inventory")
        except SessionUnavailable as error:
            assert isinstance(error.__cause__, ClockError)
        else:
            raise AssertionError("Restored pre-revocation session resumed Project OS")
        try:
            app.gates["requester"].commit_release(spec=app.spec, contract=pending_contract,
                context=pending_context, decision=pending, artifact=pending_bytes, out_path=str(pending_path))
        except (ClockError, EmissionError) as error:
            # Document-policy admission may reject its trusted clock before
            # the original receiver wraps the same clock error.
            clock_error = error if isinstance(error, ClockError) else error.__cause__
            assert isinstance(clock_error, ClockError)
            assert str(clock_error) == "database authority clock requires the configured primary domain"
        else:
            raise AssertionError("Old-domain pending release reached its target")
        assert not pending_path.exists()
        assert (app.path.stat().st_mtime_ns, hashlib.sha256(app.path.read_bytes()).hexdigest()) == artifact
        after = inventory(owner_b, roles)
        for name in before["tables"]:
            if name != "reference_alerts_v1":
                assert after["tables"][name] == before["tables"][name], name
        assert after["catalog"] == before["catalog"]
        assert app.stores.recorder.verify_chain(app.tenant)
        result = {"status": "PASS_PRODUCT_SPEC_LOGICAL_RESTORE_HOLD", "full_D2_D4": "OPEN",
            "source_domain": domain, "restored_domain": restored_domain,
            "backup_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "inventory": public_inventory(before), "restricted_access": access,
            "runtime_logins": len(runtime_pools(roles)), "domain_pack_rows": 0,
            "historical_receipt_and_signed_outcome": "IDENTICAL", "evidence_chain": "VERIFIED_IDENTICAL",
            "pending_release": "REFUSED_OLD_CLOCK_DOMAIN_NO_FILE", "restored_session": "REFUSED",
            "known_post_backup_revocation": "LOST_IN_RESTORE", "resume_authority": "HOLD",
            "limits": ["One-host logical database restore with surviving process keys/passwords and filesystem artifacts.",
                "The policy, readiness check and stage verdicts are host-written fictional fixtures.",
                "No domain pack, provider call, cold start, physical G4, PITR, zero RPO or safe authority resumption.",
                "Historical receipt is unsigned; its signed receiving outcome and evidence chain are checked separately.",
                "Host-selected RLS scope is not isolation from a holder of a raw database login.",
                "Not an integrated three-app dual-OS run or full all-table runtime-role qualification."]}
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
    save(root / "OWNER.json", {"purpose": "Fictional product_spec logical restore", "pid": os.getpid()})
    try:
        result = qualify(root, args.pg_bin.resolve(strict=True))
    except Exception as error:
        save(root / "FAILURE.json", {"error_type": type(error).__name__, "message": str(error), "retained": True})
        raise
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
