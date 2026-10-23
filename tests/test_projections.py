"""Small offline fixtures; independently verify the signed projection snapshot."""

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.projections import project, run
from regulated_core.signing import Ed25519Signer


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fixture_bundle():
    signer = Ed25519Signer("fixture:evidence")
    previous = "0" * 64
    entries = []
    for seq, (kind, reasons) in enumerate(
        [
            ("require-approval", ["HUMAN_ACCOUNTABILITY_REQUIRED"]),
            ("deny", ["APPROVAL_MISSING"]),
            ("allow", ["OUTCOME_COMMITTED"]),
        ]
    ):
        record = {
            "tenant_id": "synthetic-fixture",
            "decided_at_us": 100 + seq,
            "decision": {"kind": kind, "reason_codes": reasons, "rationale": "unit fixture"},
        }
        digest = hashlib.sha256(canonical(record)).hexdigest()
        link = {"seq": seq, "prev_hash": previous, "record_hash": digest}
        body = dict(link, schema="regulated/evidence/v2", clock_domain="fixture:clock")
        signature = signer.sign_bytes(canonical(body))
        entries.append(
            dict(
                link,
                domain="fixture:clock",
                record=record,
                signature={
                    "key_id": signature.key_id,
                    "alg": signature.alg,
                    "value": signature.value,
                },
            )
        )
        previous = hashlib.sha256(
            canonical(
                dict(link, schema="regulated/evidence-chain/v2", clock_domain="fixture:clock")
            )
        ).hexdigest()
    return {
        "public_keys": {signer.key_id: signer.public_key_bytes.hex()},
        "entries": entries,
        "limits": ["Synthetic offline projection fixture; no target effect."],
    }


def test_views_preserve_pending_and_denied_decisions_without_mutating_source():
    bundle = fixture_bundle()
    before = copy.deepcopy(bundle)
    result = project(bundle, Ed25519Signer("fixture:report"))
    assert bundle == before
    assert "Approval required; this decision alone does not permit release" in result["human"]
    assert "1: Denied. Reasons: APPROVAL_MISSING" in result["human"]
    assert "2: Recorded committed outcome" in result["human"]
    assert "PERMITTED" not in result["human"]
    assert "no independent identity anchor" in result["human"]
    assert [item["decision"] for item in result["audit"]["trace"]] == [
        entry["record"]["decision"] for entry in bundle["entries"]
    ]


def test_independent_dsse_verification_binds_source_audit_and_reader_bytes():
    bundle = fixture_bundle()
    signer = Ed25519Signer("fixture:report")
    result = project(bundle, signer)
    envelope = result["attestation"]
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    payload = base64.b64decode(envelope["payload"], validate=True)
    payload_type = envelope["payloadType"].encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type, len(payload), payload)
    (signature,) = envelope["signatures"]
    assert signature["keyid"] == signer.key_id
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes).verify(
        base64.b64decode(signature["sig"], validate=True), pae
    )
    statement = json.loads(payload)
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    predicate = statement["predicate"]
    assert predicate["source_bundle"] == bundle
    assert predicate["canonical_source_sha256"] == hashlib.sha256(canonical(bundle)).hexdigest()
    assert predicate["audit"] == result["audit"]
    assert predicate["human_report_sha256"] == hashlib.sha256(result["human"].encode()).hexdigest()
    assert statement["subject"] == [
        {"name": "evidence-chain-head", "digest": {"sha256": result["audit"]["heads"][0]["head"]}}
    ]


def test_file_export_retains_source_bytes_and_refuses_existing_folder(tmp_path):
    source = tmp_path / "source.json"
    raw = json.dumps(fixture_bundle(), indent=2).encode() + b"\n"
    source.write_bytes(raw)
    output = tmp_path / "views"
    receipt = run(source, output)
    assert (output / "source-evidence.json").read_bytes() == raw
    assert receipt["source_file_sha256"] == hashlib.sha256(raw).hexdigest()
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(FileExistsError):
        run(source, output)
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before


@pytest.mark.parametrize("order", [(2, 1, 0), (0, 2, 1)], ids=["reversed", "adjacent-swap"])
def test_reordered_signed_entries_are_refused_before_report_signing(order):
    """Rearrange synthetic records; all verification controls remain intact."""
    bundle = fixture_bundle()
    healthy = project(bundle, Ed25519Signer("fixture:healthy-report"))
    assert [row["sequence"] for row in healthy["audit"]["trace"]] == [0, 1, 2]
    original_entries = copy.deepcopy(bundle["entries"])
    bundle["entries"] = [original_entries[index] for index in order]

    class UnusedReportSigner:
        def sign_bytes(self, body):
            raise AssertionError("invalid evidence reached report signing")

    with pytest.raises(ValueError, match="inconsistent evidence chain"):
        project(bundle, UnusedReportSigner())
    assert bundle["entries"] == [original_entries[index] for index in order]
