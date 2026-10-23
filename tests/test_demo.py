"""Observe the extracted demonstration's real output and database evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_reference.demo import LESSON, run


def test_development_database_is_refused_before_output(tmp_path: Path) -> None:
    """A test run must not create outputs or connect to the development database."""
    output = tmp_path / "refused"
    with pytest.raises(ValueError, match="factory_test"):
        run(output, "dbname=factory")
    assert not output.exists()


def test_existing_output_is_preserved(tmp_path: Path) -> None:
    """Rerunning a command cannot overwrite a retained artifact directory."""
    marker = tmp_path / "retained.txt"
    marker.write_bytes(b"retain this evidence\n")
    with pytest.raises(FileExistsError):
        run(tmp_path, "dbname=factory_test")
    assert marker.read_bytes() == b"retain this evidence\n"


def test_real_demo_and_external_signature_checks(tmp_path: Path) -> None:
    """Require PostgreSQL; independently verify exported evidence with public keys."""
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; database qualification must not skip"
    output = tmp_path / "education"
    summary = run(output, dsn)
    assert summary["status"] == "PASS"
    assert summary["missing_approval_refused"]
    assert summary["repeat_authorization_refused"]
    assert summary["spent_nonce_reread"]
    assert (output / "lesson.txt").read_bytes() == LESSON
    bundle = json.loads((output / "evidence.json").read_bytes())

    # This check does not import the core's serialization or trust implementation.
    # Bundle-supplied keys establish consistency, not independently trusted identity.
    def canonical(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def verify(body: dict, signature: dict, key_id: str) -> None:
        assert signature["key_id"] == key_id
        assert signature["alg"] == "ed25519"
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_keys"][key_id]))
        key.verify(bytes.fromhex(signature["value"]), canonical(body))

    previous = "0" * 64
    entries = bundle["entries"]
    assert len(entries) == summary["evidence_entries"]
    assert [
        (e["record"]["decision"]["kind"], e["record"]["decision"]["reason_codes"]) for e in entries
    ] == [
        ("require-approval", ["PUBLISH_REVIEW"]),
        ("deny", ["APPROVAL_MISSING"]),
        ("require-approval", ["PUBLISH_REVIEW"]),
        ("allow", ["OUTCOME_COMMITTED"]),
        ("deny", ["PERMIT_REPLAY"]),
    ]
    recorded_times = [e["record"]["decided_at_us"] for e in entries]
    assert recorded_times == sorted(recorded_times)
    assert recorded_times[-1] >= summary["retry_started_at_us"]
    assert summary["replay_reason"] == "PERMIT_REPLAY"
    assert summary["recording_times_nondecreasing"]
    for sequence, entry in enumerate(entries):
        assert entry["seq"] == sequence
        assert entry["prev_hash"] == previous
        assert entry["record_hash"] == hashlib.sha256(canonical(entry["record"])).hexdigest()
        link = {name: entry[name] for name in ("seq", "prev_hash", "record_hash")}
        body = dict(link, schema="regulated/evidence/v2", clock_domain=entry["domain"])
        verify(body, entry["signature"], "demo:evidence")
        previous = hashlib.sha256(
            canonical(
                dict(link, schema="regulated/evidence-chain/v2", clock_domain=entry["domain"])
            )
        ).hexdigest()

    approval = dict(bundle["approval"])
    signature = approval.pop("signature")
    verify(dict(approval, schema="regulated/approval-cert/v1"), signature, "demo:approval")
    assert approval["approver_ids"] == ["synthetic-instructor"]
    assert any(entry["record_hash"] == approval["decision_record_hash"] for entry in entries)
    permit = bundle["permit"]
    verify(
        dict(permit["permit"], schema="regulated/permit/v5"),
        permit["signature"],
        "demo:emission",
    )
    assert permit["permit"]["approval_ref"] == approval["request_id"]
    assert permit["permit"]["output_digest"] == hashlib.sha256(LESSON).hexdigest()
    assert any(
        entry["record_hash"] == permit["permit"]["decision_record_hash"] for entry in entries
    )
