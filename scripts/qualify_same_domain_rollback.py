"""R-2b drill: a physical, same-identifier rollback is detected, held, and resumed only by the ceremony.

Two runs on new private clusters (loopback, synthetic data, ordinary user):
  running  a process that kept running across the restore detects the rollback through its own high-water;
  fresh    a process with no memory (the in-process high-water is cleared) detects it through the witnesses.
Each run: provision roles; read the clock; stop the cluster and copy its data directory (the backup); start; do
authority work after the backup (a revocation with its post-commit tick, a permit use, a witnessed head); stop;
put the backup's data directory back (same system identifier); start; check detection, the hold guard, that the
post-backup writes are really gone, the quarantine, and the ceremony.

Usage: python scripts/qualify_same_domain_rollback.py --run-root <new dir> --pg-bin <postgres bin> [--port 55434]
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

LIFETIME_US = 3_000_000


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


class Cluster:
    def __init__(self, bin_dir: Path, data: Path, port: int, log: Path):
        self.bin, self.data, self.port, self.log = bin_dir, data, port, log

    def init(self):
        run([str(self.bin / "initdb"), "-D", str(self.data), "-A", "trust", "-U", "postgres", "--no-instructions"])

    def start(self):
        run([str(self.bin / "pg_ctl"), "-D", str(self.data), "-l", str(self.log), "-w", "start",
             "-o", f"-p {self.port} -h 127.0.0.1 -c unix_socket_directories=''"])

    def stop(self):
        run([str(self.bin / "pg_ctl"), "-D", str(self.data), "-w", "-m", "fast", "stop"])

    @property
    def dsn(self):
        return f"host=127.0.0.1 port={self.port} dbname=factory_test user=postgres"


def drill(mode: str, root: Path, bin_dir: Path, port: int) -> dict:
    import psycopg
    from psycopg import sql
    import assurance_reference.clock_floor as clock_floor
    from assurance_reference.clock_floor import DurableClock
    from assurance_reference.local_roles import LocalPool, provision_local_roles
    from assurance_reference.recovery_ceremony import ResumptionAuthority, provision_recovery_login, sign_ceremony
    from regulated_core.clock import ClockError, SystemClock
    from regulated_core.clock_pg import DbClock
    from regulated_core.evidence import GENESIS
    from regulated_core.evidence_arming import WitnessArming
    from regulated_core.evidence_map import EMPTY
    from regulated_core.evidence_service import sign_head
    from regulated_core.evidence_witness import HeadPolicy, WitnessAck, WitnessRequest, WitnessScope, WitnessSet
    from regulated_core.evidence_witness_store import DurableWitness
    from regulated_core.merkle import EMPTY_ROOT
    from regulated_core.persistence_pg import PostgresRevocationLedger
    from regulated_core.signing import Ed25519Signer, TrustDirectory

    record: dict = {"mode": mode}
    cluster = Cluster(bin_dir, root / "data", port, root / "postgres.log")
    cluster.init()
    cluster.start()
    run([str(bin_dir / "createdb"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "factory_test"])
    roles = provision_local_roles(cluster.dsn)
    with psycopg.connect(cluster.dsn) as c:
        record["system_identifier_before"] = c.execute("SELECT system_identifier FROM pg_control_system()").fetchone()[0]

    def admin():
        connection = psycopg.connect(cluster.dsn, autocommit=True)
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
        return connection

    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         max_permit_lifetime_us=LIFETIME_US)
    with roles.receiver.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
        connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES ('tenant-a', 'before-backup')")
    record["floor_at_backup"] = clock.read().now_us

    # The backup: a physical copy of the stopped cluster's data directory.
    for pool in vars(roles).values():
        if isinstance(pool, LocalPool):
            pool.close()
    cluster.stop()
    shutil.copytree(root / "data", root / "backup")
    cluster.start()
    roles = type(roles)(**{k: (LocalPool(v._dsn, v.schema, v.role) if isinstance(v, LocalPool) else v)
                           for k, v in vars(roles).items()})
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         max_permit_lifetime_us=LIFETIME_US)

    # Authority work after the backup.
    clock.read()
    PostgresRevocationLedger(pool=roles.governor).revoke("tenant-a", actor="admin", reason="after backup",
                                                          now_us=clock.read().now_us)
    with roles.receiver.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
        connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES ('tenant-a', 'after-backup')")
    head_signer, trust = Ed25519Signer("drill-head"), TrustDirectory()
    trust.register_signer(head_signer)
    keys = frozenset({head_signer.key_id})
    scope = WitnessScope("tenant", "tenant-a", "evidence")
    policy = HeadPolicy(scope, roles.domain, keys, trust)
    head = sign_head(tenant="tenant-a", tree_size=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0], last_entry_hash=GENESIS,
                     previous=None, signer=head_signer, clock=clock, trust=trust, signing_keys=keys, historical_keys={})
    witness_signer, witness_trust = Ed25519Signer("drill-witness"), TrustDirectory()
    witness_trust.register_signer(witness_signer)
    witness = DurableWitness(root / "witness.db", create=True, witness_id="w", signer=witness_signer,
                             trust=witness_trust, clock=SystemClock(), policies={scope: policy})
    assert type(witness.request(WitnessRequest(secrets.token_hex(16), scope, None, head, ()))) is WitnessAck
    arming = WitnessArming(members=WitnessSet((("w", witness_signer.key_id),), 0, 0, 1), witness_trust=witness_trust,
                           endpoints={"w": witness}, policies=(policy,))
    record["witnessed_head_issued_at_us"] = head.issued_at_us
    record["floor_after_backup_work"] = clock.read().now_us

    # The restore: the backup's data directory back in place; same system identifier.
    for pool in vars(roles).values():
        if isinstance(pool, LocalPool):
            pool.close()
    cluster.stop()
    shutil.rmtree(root / "data")
    shutil.copytree(root / "backup", root / "data")
    cluster.start()
    roles = type(roles)(**{k: (LocalPool(v._dsn, v.schema, v.role) if isinstance(v, LocalPool) else v)
                           for k, v in vars(roles).items()})
    with psycopg.connect(cluster.dsn) as c:
        record["system_identifier_after"] = c.execute("SELECT system_identifier FROM pg_control_system()").fetchone()[0]
    assert record["system_identifier_after"] == record["system_identifier_before"], "not a same-identifier restore"
    with admin() as a:
        record["post_backup_permit_use_present"] = a.execute(
            "SELECT count(*) FROM regulated_permit_uses_v1 WHERE nonce = 'after-backup'").fetchone()[0] == 1
        record["post_backup_revocation_present"] = a.execute(
            "SELECT count(*) FROM regulated_revocation_events_v1 WHERE tenant = 'tenant-a'").fetchone()[0] > 0
    assert not record["post_backup_permit_use_present"] and not record["post_backup_revocation_present"]

    if mode == "fresh":
        with clock_floor._SENTINEL_LOCK:
            clock_floor._HIGHWATER.clear()  # a new process: no memory of the later floor
        detector = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                                max_permit_lifetime_us=LIFETIME_US, arming=arming)
    else:
        detector = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                                max_permit_lifetime_us=LIFETIME_US)  # shares this process's high-water
    try:
        detector.read()
        record["detected"] = False
    except ClockError as exc:
        record["detected"], record["detection"] = True, str(exc)
    with admin() as a:
        record["hold_reason"] = a.execute("SELECT hold_reason FROM reference_clock_floor_v1 WHERE domain = %s",
                                          (roles.domain,)).fetchone()[0]
    try:
        with roles.receiver.connection() as connection, connection.transaction():
            connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
            connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES ('tenant-a', 'replay')")
        record["write_during_hold"] = "accepted"
    except psycopg.DatabaseError as exc:
        record["write_during_hold"] = "refused " + (exc.sqlstate or "")

    owner = LocalPool(cluster.dsn, roles.schema, "drill-owner")
    recovery = provision_recovery_login(owner, cluster.dsn)
    ceremony_signer, ceremony_trust = Ed25519Signer("drill-ceremony"), TrustDirectory()
    ceremony_trust.register_signer(ceremony_signer)
    # The restored log is empty, as the witnessed head (size 0) records: nothing witnessed was lost.
    head_at = lambda s, size: head if (s, size) == ("tenant-a", 0) else None  # noqa: E731
    authority = ResumptionAuthority(recovery_pool=recovery, clock=detector, trust=ceremony_trust,
                                    ceremony_key_id=ceremony_signer.key_id, arming=arming, head_at=head_at)
    with admin() as a:
        hold_at = a.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                            (roles.domain,)).fetchone()[0]
    ceremony = sign_ceremony(ceremony_signer, domain=roles.domain, hold_at_us=hold_at,
                             witnessed=arming.require_local_matches(roles.domain, head_at), issued_at_us=hold_at)
    try:
        authority.resume(ceremony)
        record["resume_before_quarantine"] = "accepted"
    except ClockError as exc:
        record["resume_before_quarantine"] = "refused: " + str(exc)
    while detector._read_for_ceremony().now_us < hold_at + LIFETIME_US:
        time.sleep(0.2)
    record["ceremony"] = authority.resume(ceremony)
    record["read_after_resume_us"] = detector.read().now_us
    with admin() as a:
        record["tenant_a_epoch_after"] = a.execute(
            "SELECT MAX(epoch) FROM regulated_revocation_events_v1 WHERE tenant = 'tenant-a'").fetchone()[0]
    for pool in [*vars(roles).values(), owner, recovery]:
        if isinstance(pool, LocalPool):
            pool.close()
    cluster.stop()
    shutil.rmtree(root / "data")
    shutil.rmtree(root / "backup")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--pg-bin", required=True)
    parser.add_argument("--port", type=int, default=55434)
    args = parser.parse_args()
    root = Path(args.run_root)
    root.mkdir(parents=True, exist_ok=False)
    results = {}
    for mode in ("running", "fresh"):
        (root / mode).mkdir()
        results[mode] = drill(mode, root / mode, Path(args.pg_bin), args.port)
    ok = all(r["detected"] and r["write_during_hold"].startswith("refused")
             and r["resume_before_quarantine"].startswith("refused") and r["ceremony"]["epoch_jump"] == 2 ** 32
             for r in results.values())
    results["status"] = "PASS_SAME_IDENTIFIER_ROLLBACK_HELD_AND_RESUMED" if ok else "FAIL"
    (root / "RESULT.json").write_text(json.dumps(results, indent=1, default=str) + "\n", encoding="utf-8")
    print(results["status"])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
