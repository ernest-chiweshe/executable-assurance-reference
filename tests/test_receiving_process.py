"""Kill owned workers at two transaction boundaries; reconcile in new processes."""

from dataclasses import asdict
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
from queue import Queue, Empty
import subprocess
import sys
from threading import Thread

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.prepared_budget_demo import BODY
from regulated_core.canonical import canonical_bytes, digest_hex
from test_delegated_draft import delegated_draft_fixture
from test_root_admission import TENANTS, canonical
from isolated_worker_database import verify_isolated_worker_database


WORKER = Path(__file__).with_name("receiving_process_worker.py")


def kill_owned_tree(process):
    """Interrupt only this test's live Popen tree, including Windows venv redirectors."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"
        result = subprocess.run(
            [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # The owned launcher can exit after the initial poll and before
        # taskkill opens it. Accept that race only after Popen confirms exit;
        # killed_worker still waits on its held handle to the actual worker.
        assert result.returncode == 0 or process.poll() is not None, "owned process-tree termination failed"
    else:
        process.kill()


def watch_windows_worker(pid):
    """Hold a synchronize-only handle to the actual worker before interruption."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only; no kill right.
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return kernel, handle


def killed_worker(config, marker):
    # Keep synthetic private-key arguments out of pytest's expanded helper traceback.
    __tracebackhide__ = True
    process = subprocess.Popen(
        [sys.executable, "-B", str(WORKER)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = Queue()
    watched = None
    Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        process.stdin.write(json.dumps(config) + "\n")
        process.stdin.flush()
        try:
            line = lines.get(timeout=25)
        except Empty:
            raise AssertionError("owned worker did not reach the requested boundary") from None
        if not line:
            raise AssertionError("owned worker exited before its marker: " + process.stderr.read())
        signal = json.loads(line)
        assert signal["marker"] == marker
        direct = signal["pid"] == process.pid and signal["parent_pid"] == os.getpid()
        redirected = os.name == "nt" and signal["parent_pid"] == process.pid
        assert direct or redirected, "marker was not emitted by the owned worker tree"
        if os.name == "nt":
            watched = watch_windows_worker(signal["pid"])
            kernel, handle = watched
            assert kernel.WaitForSingleObject(handle, 0) == 258, "worker exited before interruption"
        kill_owned_tree(process)
        if watched:
            assert kernel.WaitForSingleObject(handle, 10_000) == 0, "actual worker survived interruption"
        _, stderr = process.communicate(timeout=10)
        assert process.returncode != 0 and not stderr, stderr
        return {**signal, "launcher_pid": process.pid, "exit_code": process.returncode,
                "worker_exit_confirmed": True}
    finally:
        try:
            if process.poll() is None:
                kill_owned_tree(process)
                process.communicate(timeout=10)
        finally:
            if watched:
                watched[0].CloseHandle(watched[1])


def reconcile(config):
    result = subprocess.run(
        [sys.executable, "-B", str(WORKER)],
        input=json.dumps({**config, "mode": "reconcile"}) + "\n",
        capture_output=True, text=True, timeout=25,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def counts(pool, tenant):
    with pool.connection() as conn:
        result = {name: conn.execute("SELECT count(*) FROM " + table + " WHERE tenant=%s", (tenant,)).fetchone()[0]
                  for name, table in {
                      "effects": "reference_prepared_drafts_v1",
                      "attempts": "regulated_database_attempts_v1",
                      "receipts": "regulated_database_receipts_v1",
                      "nonce_uses": "regulated_permit_uses_v1",
                  }.items()}
        result["budget_events"] = sorted(row[0] for row in conn.execute(
            "SELECT kind FROM regulated_mission_budget_events_v1 WHERE tenant=%s", (tenant,)).fetchall())
        return result


def test_process_termination_before_and_after_commit(tmp_path):
    verify_isolated_worker_database()  # Before any fixture provisioning.
    evidence = []
    all_effects = []
    for tenant, mode, marker in (
        (TENANTS[0], "before-commit", "effect-written-uncommitted"),
        (TENANTS[1], "after-commit", "committed-before-caller-ack"),
    ):
        # Each leg starts a complete freshly reviewed fixture. Its fixed TTL is
        # unchanged and is no longer consumed by the other worker lifecycle.
        case_path = tmp_path / mode
        case_path.mkdir()
        fixture, assemble, authorize = delegated_draft_fixture(case_path)
        # Only these freshly generated test keys cross the anonymous pipe. No keys
        # are persisted, printed, passed in argv, or selected by an effect request.
        keys = {name: signer._sk.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
                for name, signer in fixture["signers"].items()}
        host = {"schema": fixture["schema"], "domain": fixture["domain"],
                "document": asdict(fixture["document"]), "fixture_keys": keys}
        pool, _, _, _, _, _, _, _ = assemble(TENANTS[0])
        authorization, _ = authorize(tenant, "alpha")
        assert authorization.status == "authorized", authorization
        signed = authorization.permit
        Ed25519PublicKey.from_public_bytes(fixture["signers"]["permit"].public_key_bytes).verify(
            bytes.fromhex(signed.signature.value), canonical(signed.permit.signed_body()))
        config = {**host, "signed": asdict(signed), "mode": mode}
        killed = killed_worker(config, marker)
        assert killed["worker_exit_confirmed"]
        before = counts(pool, tenant)
        if mode == "before-commit":
            assert before == {"effects": 0, "attempts": 1, "receipts": 0,
                              "nonce_uses": 0, "budget_events": ["reserve"]}
            assert counts(pool, TENANTS[1]) == {"effects": 0, "attempts": 0, "receipts": 0,
                                              "nonce_uses": 0, "budget_events": []}
        else:
            assert before == {"effects": 1, "attempts": 1, "receipts": 1,
                              "nonce_uses": 1, "budget_events": ["consume", "reserve"]}
        recovered = reconcile(config)
        assert recovered["pid"] not in {os.getpid(), killed["pid"]}
        assert recovered["permit_digest"] == digest_hex(signed.permit.signed_body())
        expected = "not_committed" if mode == "before-commit" else "committed"
        assert recovered["observed"] == ("unknown" if mode == "before-commit" else expected)
        assert recovered["reconciled"] == recovered["replay"] == expected
        after = counts(pool, tenant)
        assert after == {**before, "receipts": 1}
        if mode == "after-commit":
            assert recovered["state"] == hashlib.sha256(BODY).hexdigest()
        with pool.connection() as conn:
            effects = conn.execute("SELECT tenant,body FROM reference_prepared_drafts_v1").fetchall()
            alerts = [json.loads(bytes(row[0])) for row in
                      conn.execute("SELECT envelope FROM reference_alerts_v1").fetchall()]
        assert effects == ([] if mode == "before-commit" else [(tenant, BODY)])
        all_effects.extend(effects)
        replay_alert = None
        if mode == "before-commit":
            replay_alert, = [a for a in alerts
                            if a["payload"].get("request_hash") == recovered["permit_digest"]]
            assert replay_alert["payload"]["code"] == "AUTHORIZATION_REFUSED"
            Ed25519PublicKey.from_public_bytes(fixture["signers"]["alert"].public_key_bytes).verify(
                bytes.fromhex(replay_alert["signature"]["value"]), canonical(replay_alert["payload"]))
        evidence.append({"tenant": tenant, "mode": mode, "killed": killed,
                         "signed": asdict(signed), "recovered": recovered,
                         "before_reconciliation": before, "after_reconciliation": after,
                         "schema": fixture["schema"], "document": asdict(fixture["document"]),
                         "public_keys": {signer.key_id: signer.public_key_bytes.hex()
                                         for signer in fixture["signers"].values()},
                         "replay_refusal_alert": replay_alert})
    assert len({case["schema"] for case in evidence}) == 2
    assert all_effects == [(TENANTS[1], BODY)]
    (tmp_path / "process-recovery.json").write_bytes(canonical_bytes({
        "parent_pid": os.getpid(), "cases": evidence,
        "fixture_scope": "A fresh reviewed fixture and unchanged TTL per tenant leg.",
        "limits": ["Two owned Python process terminations; not PostgreSQL or machine failure.",
                   "Synthetic identities and pipe-transferred local fixture keys; no custody or RLS claim.",
                   "Terminal reconciliation retains unused reservations; no automatic capacity recycling.",
                   "Post-replay alert only: process-death alert delivery and an atomic outbox remain OPEN.",
                   "Transactional database draft only; physical G4 and external effects remain OPEN."],
    }) + b"\n")
