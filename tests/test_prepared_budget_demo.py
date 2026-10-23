"""Real retained authority, refusal before effect, exact receiving receipt and signatures."""

import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.prepared_budget_demo import run


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_prepared_budget_refusals_and_rebuilt_receiving_path(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL required; no skipped database qualification"
    output = tmp_path / "prepared"
    run(output, dsn)
    saved = json.loads((output / "prepared-budget.json").read_text(encoding="utf-8"))
    assert saved["status"] == "PASS"
    assert saved["stages"] == ["reserved", "recorded", "prepared", "issued", "committed"]
    assert saved["counts"] == {
        "regulated_database_receipts_v1": 1, "regulated_decision_uses_v1": 1,
        "regulated_permit_uses_v1": 1, "regulated_preparations_v1": 1,
        "regulated_decision_inputs_v1": 2,
    }
    assert [row[:3] for row in saved["events"]] == [["reserve", 1, 1], ["consume", 1, 1]]
    assert saved["events"][0][3] == saved["events"][1][3] == saved["proof"]["preparation"]["subject_digest"]
    assert saved["replay"] == saved["observed"] == "committed"
    assert saved["refusal"]["refusal"]["record"]["decision"]["reason_codes"] == ["BUDGET_EXCEEDED"]
    assert [a["payload"]["code"] for a in saved["alerts"]] == ["ADMISSION_REFUSED", "AUTHORIZATION_REFUSED"]

    def verify(body, signature, expected_key):
        assert signature["key_id"] == expected_key and signature["alg"] == "ed25519"
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(saved["public_keys"][expected_key]))
        key.verify(bytes.fromhex(signature["value"]), canonical(body))

    proof = saved["proof"]
    verify(saved["policy"], saved["policy_signature"], "prepared:policy")
    verify(proof["permit"], proof["permit_signature"], "prepared:permit")
    verify(proof["preparation"], proof["preparation_signature"], "prepared:evidence")
    assert proof["permit"]["output_digest"] == saved["body_sha256"]
    assert proof["preparation"]["budget_units"] == proof["preparation"]["budget_limit"] == 1
    assert proof["permit"]["preparation_digest"] == hashlib.sha256(canonical({
        "body": proof["preparation"], "signature": proof["preparation_signature"],
    })).hexdigest()
    for alert in saved["alerts"]:
        verify(alert["payload"], alert["signature"], "prepared:alert")
        assert alert["payload"]["permit_hash"] is None and alert["payload"]["authority_time_us"] is None
    previous = "0" * 64
    assert len(saved["chain"]) == 3
    for seq, entry in enumerate(saved["chain"]):
        assert entry["seq"] == seq and entry["prev_hash"] == previous
        assert entry["record_hash"] == hashlib.sha256(canonical(entry["record"])).hexdigest()
        body = {"schema": "regulated/evidence/v2", "seq": seq,
                "prev_hash": previous, "record_hash": entry["record_hash"], "clock_domain": entry["domain"]}
        verify(body, entry["signature"], "prepared:evidence")
        body["schema"] = "regulated/evidence-chain/v2"
        previous = hashlib.sha256(canonical(body)).hexdigest()
    assert saved["outcome_evidence"]["record"]["decision"]["reason_codes"] == ["OUTCOME_COMMITTED"]
