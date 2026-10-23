"""Observe the synthetic Health workflow and independently verify its evidence."""

import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.health import CHECKS, HANDOUT, run


def test_health_dual_approval_and_exact_delivery(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped qualification"
    output = tmp_path / "health"
    summary = run(output, dsn)
    assert summary["status"] == "PASS"
    assert summary["single_approver_refused"]
    assert summary["duplicate_person_refused"]
    assert summary["self_approval_refused"]
    assert summary["cross_tenant_approval_refused"]
    assert not (output / "tenant-b-must-not-exist.txt").exists()
    assert summary["low_confidence_refused"]
    assert summary["missing_payload_reference_refused"]
    assert (output / summary["artifact"]).read_bytes() == HANDOUT
    encrypted = (output / "synthetic-payload.aesgcm").read_bytes()
    assert HANDOUT not in encrypted
    bundle = json.loads((output / "evidence.json").read_bytes())
    assert b"SAMPLE-001" not in (output / "evidence.json").read_bytes()

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def verify(body, signature, expected_id):
        assert signature["alg"] == "ed25519"
        assert signature["key_id"] == expected_id
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(bundle["public_keys"][expected_id])
        ).verify(bytes.fromhex(signature["value"]), canonical(body))

    entries = bundle["entries"]
    assert [e["record"]["decision"]["reason_codes"] for e in entries] == [
        ["PRIVACY_CONTROL_MISSING"],
        ["CONFIDENCE_NOT_ESTABLISHED"],
        ["PLAINTEXT_IN_RECORD"],
        ["HUMAN_ACCOUNTABILITY_REQUIRED"],
        ["APPROVAL_MISSING"],
        ["HUMAN_ACCOUNTABILITY_REQUIRED"],
        ["OUTCOME_COMMITTED"],
        ["PERMIT_REPLAY"],
    ]
    other_entries = bundle["tenant_boundary_entries"]
    assert [e["record"]["decision"]["reason_codes"] for e in other_entries] == [
        ["HUMAN_ACCOUNTABILITY_REQUIRED"],
        ["APPROVAL_DECISION_CHANGED"],
    ]
    for tenant, chain in (("synthetic-clinic", entries), ("synthetic-clinic-b", other_entries)):
        previous = "0" * 64
        for seq, entry in enumerate(chain):
            assert entry["record"]["tenant_id"] == tenant
            assert entry["seq"] == seq and entry["prev_hash"] == previous
            assert entry["record_hash"] == hashlib.sha256(canonical(entry["record"])).hexdigest()
            link = {k: entry[k] for k in ("seq", "prev_hash", "record_hash")}
            verify(
                dict(link, schema="regulated/evidence/v2", clock_domain=entry["domain"]),
                entry["signature"],
                "health-demo:evidence",
            )
            previous = hashlib.sha256(
                canonical(
                    dict(
                        link,
                        schema="regulated/evidence-chain/v2",
                        clock_domain=entry["domain"],
                    )
                )
            ).hexdigest()
    assertion = bundle["assertion"]
    assert assertion["confidence"]["method_id"] == "synthetic-exact-template-fixture"
    assert assertion["confidence"]["score"] == "0.95"
    assert assertion["attributes"]["scope"] == "synthetic workflow only; no clinical calibration"
    assert {v["result"]["verification_class"] for v in assertion["verifications"]} == set(CHECKS)
    for verification in assertion["verifications"]:
        body = dict(verification)
        signature = body.pop("signature")
        assert body["content_digest"] == hashlib.sha256(HANDOUT).hexdigest()
        assert body["tenant_id"] == assertion["tenant_id"]
        verify(
            dict(body, schema="regulated/verification/v1"), signature, body["result"]["verifier_id"]
        )
    approval = dict(bundle["approval"])
    signature = approval.pop("signature")
    verify(dict(approval, schema="regulated/approval-cert/v1"), signature, "health-demo:approval")
    assert set(approval["approver_ids"]) == {"synthetic-clinician", "synthetic-privacy-officer"}
    permit = bundle["permit"]
    verify(
        dict(permit["permit"], schema="regulated/permit/v5"),
        permit["signature"],
        "health-demo:emission",
    )
    assert permit["permit"]["output_digest"] == hashlib.sha256(HANDOUT).hexdigest()
    assert permit["permit"]["approval_ref"] == approval["request_id"]
    assert permit["permit"]["decision_record_hash"] in {e["record_hash"] for e in entries}
