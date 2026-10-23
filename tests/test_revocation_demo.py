"""Independent signatures and retained outcomes for normal revoke-before-delivery."""

import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.revocation_demo import run


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_durable_epoch_refuses_old_permit_after_receiver_reconstruction(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped qualification"
    output = tmp_path / "revocation"
    run(output, dsn)
    saved = json.loads((output / "revocation.json").read_text(encoding="utf-8"))
    assert saved["status"] == "PASS"
    assert saved["epochs"] == {"revocation-fixture-a": 1, "revocation-fixture-b": 0}
    assert saved["absent_after_refusal"] and saved["refused_nonce_unspent"]
    assert len(saved["retained_events"]) == 1
    event = saved["retained_events"][0]
    assert event[:3] == ["revocation-fixture-a", 1, "fixture-host-operator"]
    assert event[4] == saved["revocation"]["at_us"]
    assert [step["outcome"] for step in saved["steps"]] == ["failed", "committed", "committed"]
    assert [step["permit"]["revocation_epoch"] for step in saved["steps"]] == [0, 0, 1]
    assert "permit revoked" in saved["steps"][0]["detail"]
    for step in saved["steps"]:
        signature = step["signature"]
        assert signature["key_id"] == "revocation:emission" and signature["alg"] == "ed25519"
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(saved["public_keys"][signature["key_id"]]))
        key.verify(bytes.fromhex(signature["value"]), canonical(step["permit"]))
        assert step["permit"]["output_digest"] == saved["body_sha256"]
    for tenant, entries in saved["evidence"].items():
        previous = "0" * 64
        assert len(entries) == (4 if tenant.endswith("-a") else 2)
        for seq, entry in enumerate(entries):
            assert entry["seq"] == seq and entry["prev_hash"] == previous
            assert entry["record"]["tenant_id"] == tenant
            assert entry["record_hash"] == hashlib.sha256(canonical(entry["record"])).hexdigest()
            body = {"schema": "regulated/evidence/v2", "seq": seq,
                    "prev_hash": previous, "record_hash": entry["record_hash"],
                    "clock_domain": saved["clock_domain"]}
            signature = entry["signature"]
            assert signature["key_id"] == "revocation:evidence" and signature["alg"] == "ed25519"
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(saved["public_keys"][signature["key_id"]]))
            key.verify(bytes.fromhex(signature["value"]), canonical(body))
            body["schema"] = "regulated/evidence-chain/v2"
            previous = hashlib.sha256(canonical(body)).hexdigest()
    for tenant in saved["epochs"]:
        assert hashlib.sha256((output / (tenant + ".txt")).read_bytes()).hexdigest() == saved["body_sha256"]
