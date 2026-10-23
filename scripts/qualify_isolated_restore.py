"""Linux-only logical restore qualification in two new, owned PostgreSQL clusters.

Never connects to an existing cluster, deletes a directory, resets a clock domain,
or disables a receiving guard. Source A is stopped and retained before B starts.
Use the reviewed wheel installed in a venv and the matching extracted sdist tests.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

PORT = 55433


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def save(path, value):
    path.write_bytes(canonical(value) + b"\n")


def run(args, log, *, env=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=90, env=env)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed; retained log {log.name}")
    return result.stdout.decode().strip()


def safe_new_root(path):
    raw = path.expanduser().absolute()
    if not raw.is_relative_to(Path.home()) or raw == Path.home() or raw.exists():
        raise ValueError("Run root must be a NEW directory beneath your home")
    for p in (raw, *raw.parents):
        if p.is_symlink():
            raise ValueError("Symlink in run-root path")
    if raw.resolve() != raw:
        raise ValueError("Run root must be normalized")
    raw.mkdir(parents=True)
    os.chmod(raw, 0o700)
    save(raw / "OWNER.json", {"purpose": "isolated-restore-qualification", "uid": os.getuid(), "pid": os.getpid(), "port": PORT, "preserve": True})
    return raw


class Cluster:
    def __init__(self, root, name, bins):
        self.path = root / name
        self.path.mkdir()
        self.data = self.path / "data"
        self.socket = self.path / "socket"
        self.socket.mkdir()
        self.bins, self.started = bins, False
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        self.env.update(PGHOST="127.0.0.1", PGPORT=str(PORT), PGUSER=os.environ["USER"], PGDATABASE="factory_test")

    def command(self, name, args, label):
        return run([self.bins / name, *args], self.path / (label + ".log"), env=self.env)

    def start(self):
        # Port ownership is exclusive; never stop an existing listener to make room.
        with socket.socket() as probe:
            # Exclude a live listener, but permit normal TCP TIME_WAIT after A stops.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", PORT))
        self.command("initdb", ["-D", self.data, "--auth-local=trust", "--auth-host=trust", "--no-instructions"], "initdb")
        self.command("pg_ctl", ["-D", self.data, "-l", self.path / "server.log", "-o", f"-h 127.0.0.1 -p {PORT} -k {self.socket}", "-w", "start"], "start")
        self.started = True
        self.command("createdb", ["factory_test"], "createdb")
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            actual, identity = conn.execute("SELECT current_setting('data_directory'), system_identifier::text FROM pg_control_system()").fetchone()
            if Path(actual).resolve() != self.data.resolve():
                raise RuntimeError("Connected server is not this owned cluster")
        return "pg:" + identity

    @property
    def dsn(self):
        from psycopg.conninfo import make_conninfo
        return make_conninfo(host="127.0.0.1", port=PORT, user=self.env["PGUSER"], dbname="factory_test")

    def stop(self):
        if self.started:
            self.command("pg_ctl", ["-D", self.data, "-m", "fast", "-w", "stop"], "stop")
            self.started = False


def snapshot(pool):
    from psycopg import sql
    with pool.connection() as conn, conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        tables = [r[0] for r in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename")]
        values = {}
        for name in tables:
            rows = conn.execute(sql.SQL("SELECT to_jsonb(t) FROM {} t").format(sql.Identifier(name))).fetchall()
            values[name] = sorted((row[0] for row in rows), key=canonical)
        guards = conn.execute("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,"
                              "t.tgname,t.tgenabled,pg_get_triggerdef(t.oid) "
                              "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                              "JOIN pg_trigger t ON t.tgrelid=c.oid "
                              "WHERE n.nspname=current_schema() AND NOT t.tgisinternal "
                              "ORDER BY c.relname,t.tgname").fetchall()
        values["__restored_guard_catalog__"] = [list(row) for row in guards]
    return values


def verify_evidence(pool, keys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    def signature(body, sig):
        assert sig["alg"] == "ed25519" and sig["key_id"] in keys
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[sig["key_id"]])).verify(bytes.fromhex(sig["value"]), canonical(body))
    with pool.connection() as conn:
        records = conn.execute("SELECT tenant,seq,entry_hash,envelope FROM regulated_decision_evidence_v1 ORDER BY tenant,seq").fetchall()
        alerts = [json.loads(bytes(r[0])) for r in conn.execute("SELECT envelope FROM reference_alerts_v1 ORDER BY alert_id")]
    heads, counts = {}, {}
    for tenant, seq, entry_hash, entry in records:
        assert entry["record"]["tenant_id"] == tenant and entry["record_hash"] == digest(entry["record"])
        assert seq == entry["seq"] == counts.get(tenant, 0)
        assert entry["prev_hash"] == heads.get(tenant, "0" * 64)
        link = {"seq": seq, "prev_hash": entry["prev_hash"], "record_hash": entry["record_hash"], "clock_domain": entry["domain"]}
        signature({"schema": "regulated/evidence/v2", **link}, entry["signature"])
        expected = digest({"schema": "regulated/evidence-chain/v2", **link})
        assert entry_hash == expected
        heads[tenant], counts[tenant] = expected, seq + 1
    for alert in alerts:
        signature(alert["payload"], alert["signature"])
    assert records and alerts
    return {"chains": counts, "heads": heads, "signed_alerts": len(alerts)}


def qualify(root, bins, tests):
    import psycopg
    from assurance_reference.demo import SchemaConnections
    from regulated_core.budget import BudgetError
    from regulated_core.clock import ClockError
    from regulated_core.target import Outcome
    sys.path.insert(0, str(tests))
    from test_delegated_draft import delegated_draft_fixture, assemble_delegated_fixture, DraftCurrentness
    from test_root_admission import assemble_root_fixture, TENANTS
    from assurance_reference.prepared_budget_demo import BODY

    clusters = [Cluster(root, name, bins) for name in ("source-a", "restored-b")]
    a, b = clusters
    try:
        domain_a = a.start()
        os.environ["FACTORY_TEST_DB_URL"] = a.dsn
        fixtures = root / "fixture"
        fixtures.mkdir()
        f, assemble, authorize = delegated_draft_fixture(fixtures)
        assert f["domain"] == domain_a
        winner, _ = authorize(TENANTS[0], "alpha")
        assert winner.status == "authorized"
        pool, clock, _, _, _, receiver, budget, alerts = assemble(TENANTS[0])
        assert receiver.commit(winner.permit, BODY).outcome is Outcome.COMMITTED
        refused, _ = authorize(TENANTS[0], "beta")
        assert refused.status == "refused" and refused.alert_id
        pending, _ = authorize(TENANTS[1], "alpha")
        assert pending.status == "authorized"
        clock.now_us()
        before = snapshot(pool)
        keys = {s.key_id: s.public_key_bytes.hex() for s in f["signers"].values()}
        verified_before = verify_evidence(pool, keys)
        save(root / "backup-inventory.json", {"domain": domain_a, "schema": f["schema"], "tables": before, "sha256": digest(before), "public_keys": keys, "verification": verified_before, "committed_permit": asdict(winner.permit), "pending_permit": asdict(pending.permit)})
        backup = root / "snapshot.dump"
        a.command("pg_dump", ["-Fc", "--file", backup, "factory_test"], "dump")
        # A known tail after the snapshot proves why restore alone cannot establish no loss.
        lost_id = alerts.append_refusal(tenant_id=TENANTS[0], request_hash=digest({"fixture": "after-backup"}), decision_hash=None, code="AUTHORIZATION_UNCERTAIN")
        tail_time = clock.now_us()
        tail_alert = alerts.read(lost_id, tenant_id=TENANTS[0])
        save(root / "external-tail.json", {"alert": tail_alert, "last_observed_clock_us": tail_time, "schema": f["schema"], "domain": domain_a})
        a.stop()
        # The original data directory remains sealed by convention and offline as evidence.
        domain_b = b.start()
        assert domain_a != domain_b
        b.command("pg_restore", ["--exit-on-error", "--no-owner", "--no-privileges", "-d", "factory_test", backup], "restore")
        restored = SchemaConnections(b.dsn, f["schema"])
        restored_before = snapshot(restored)
        assert restored_before == before, "Restored snapshot differs from backed-up inventory"
        verified_after = verify_evidence(restored, keys)
        assert verified_after == verified_before
        # Reconstruct objects with the original pinned domain. Never bootstrap or rebind it.
        fresh = {**f, "assemble": lambda tenant: assemble_root_fixture(tenant, dsn=b.dsn, schema=f["schema"], domain=domain_a, document=f["document"], trust=f["trust"], signers=f["signers"], currentness_factory=DraftCurrentness)}
        p, restored_clock, _, _, _, receiving, restored_budget, _ = assemble_delegated_fixture(fresh, TENANTS[0])
        assert receiving.observe(winner.permit).outcome is Outcome.COMMITTED
        # An exact committed replay resolves to its old receipt and emits no new effect.
        assert receiving.commit(winner.permit, BODY).outcome is Outcome.COMMITTED
        assert snapshot(p) == before, "Receipt replay changed restored state"
        assert restored_budget.committed(TENANTS[0], "one-draft") == 1
        try:
            restored_budget.reserve(TENANTS[0], "one-draft", reservation_id="after-restore", units=1, limit=1, subject_digest="a" * 64)
        except BudgetError:
            pass
        else:
            raise AssertionError("Restored consumed budget was re-spendable")
        try:
            restored_clock.now_us()
        except ClockError:
            pass
        else:
            raise AssertionError("Old cluster clock authority was silently rebound")
        _, _, _, _, _, pending_receiver, _, _ = assemble_delegated_fixture(fresh, TENANTS[1])
        refused_domain = False
        try:
            result = pending_receiver.commit(pending.permit, BODY)
            refused_domain = result.outcome in {Outcome.FAILED, Outcome.NOT_COMMITTED, Outcome.UNKNOWN}
        except ClockError:
            refused_domain = True
        assert refused_domain
        after = snapshot(p)
        with p.connection() as conn:
            new_alerts = [json.loads(bytes(row[0])) for row in conn.execute(
                "SELECT envelope FROM reference_alerts_v1 WHERE alert_id NOT IN "
                "(SELECT unnest(%s::text[]))", ([row["alert_id"] for row in before["reference_alerts_v1"]],))]
        assert any(alert["payload"].get("permit_hash") == digest(pending.permit.permit.signed_body())
                   or alert["payload"].get("request_hash") == digest(pending.permit.permit.signed_body())
                   for alert in new_alerts), "Pending delivery refusal did not retain a signed alert"
        verified_with_refusal = verify_evidence(p, keys)
        for table in ("reference_prepared_drafts_v1", "regulated_permit_uses_v1", "regulated_mission_budget_events_v1", "reference_clock_floor_v1"):
            assert after[table] == before[table], "Recovery changed effect/budget/clock state"
        assert not any(row["alert_id"] == lost_id for row in after["reference_alerts_v1"])
        floor = next(row["highwater_us"] for row in before["reference_clock_floor_v1"] if row["domain"] == domain_a)
        assert floor < tail_time
        result = {"status": "PASS_BOUNDED_RESTORE_RECOVERY_HOLD", "source_domain": domain_a, "restored_domain": domain_b, "schema": f["schema"], "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(), "snapshot_sha256": digest(before), "restored_snapshot_sha256": digest(restored_before), "tables": len(before), "signature_verification": verified_after, "exact_committed_replay": "historical_receipt_returned_no_new_effect", "budget_respend": "REFUSED", "old_clock_domain": "REFUSED", "pending_effect": "REFUSED_OR_UNCERTAIN_NO_EFFECT", "floor_preserved_at_backup": floor, "external_last_observed_floor": tail_time, "known_lost_alert_ids": [lost_id], "resume_authority": "HOLD", "limits": ["Logical snapshot restore with source cluster stopped, not physical destruction or a machine crash.", "Known post-backup tail is LOST relative to restored snapshot; no zero-RPO or total-loss-detection claim.", "New cluster domain refuses old authority. Clock-domain migration/requalification and safe resume remain open.", "Alerts are individually signed; they are not a hash-chained or independently delivered journal.", "One host, synthetic identities and in-memory fixture keys; no production custody, RLS, external-effect or physical G4 qualification.", "Source and restored clusters are stopped and retained, never deleted."]}
        result["restored_guard_catalog_matches"] = True
        result["verification_after_domain_refusal"] = verified_with_refusal
        result["retained_refusal_alerts"] = new_alerts
        save(root / "RESULT.json", result)
        return result
    finally:
        for cluster in reversed(clusters):
            cluster.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--tests-root", required=True, type=Path)
    parser.add_argument("--pg-bin", required=True, type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise SystemExit("Assertions must remain enabled for qualification")
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("Run as an ordinary Linux user; no sudo")
    tests = args.tests_root.resolve(strict=True)
    if not (tests / "test_delegated_draft.py").is_file():
        raise SystemExit("Matching source-distribution tests are required")
    bins = args.pg_bin.resolve(strict=True)
    for name in ("initdb", "pg_ctl", "createdb", "pg_dump", "pg_restore"):
        if not (bins / name).is_file():
            raise SystemExit("Missing PostgreSQL executable: " + name)
    root = safe_new_root(args.run_root)
    try:
        result = qualify(root, bins, tests)
    except Exception as exc:
        save(root / "FAILURE.json", {"error_type": type(exc).__name__, "message": str(exc), "retained": True})
        raise
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
