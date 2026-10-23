"""Local export workflow using detached signed fixtures and explicit host pins."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

import pytest

from test_reconciliation import signed as _signed_fixture

signed = _signed_fixture
_spec = importlib.util.spec_from_file_location("checkpoint_export_cli",
    Path(__file__).resolve().parents[1] / "scripts/export_checkpoint_report.py")
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)


def inputs(tmp_path, signed):
    report, point, receipts, _, keys = signed
    evidence, trust, output = (tmp_path / name for name in ("evidence.json", "trust.json", "export"))
    evidence.write_text(json.dumps([{"checkpoint": point, "report": report, "receipts": receipts}]))
    trust.write_text(json.dumps({"keys": [{"key_id": key.key_id,
        "public_key_hex": key.public_key_bytes.hex(), "alg": "ed25519"} for key in keys]}))
    args = ["--evidence", str(evidence), "--trust", str(trust), "--issuer", "reporter",
        "--witness", "witness-a", "--witness", "witness-b", "--tenant", "tenant-a",
        "--previous-digest", "", "--start-seq", "0", "--end-seq", "1", "--now-us", "20",
        "--output", str(output)]
    return args, evidence, trust, output


def test_cli_exports_reverified_report_with_integrity_receipt(tmp_path, signed):
    args, evidence, trust, output = inputs(tmp_path, signed)
    assert cli.main(args) == 0
    receipt = json.loads((output / "EXPORT.json").read_bytes())
    assert receipt["status"] == "ONE_VERIFIED_CHECKPOINT_OBSERVED"
    assert receipt["input_sha256"] == sha256(evidence.read_bytes()).hexdigest()
    assert receipt["host_trust_sha256"] == sha256(trust.read_bytes()).hexdigest()
    for name, digest in receipt["files"].items():
        assert sha256((output / name).read_bytes()).hexdigest() == digest
    report = json.loads((output / "report.json").read_bytes())
    assert report["observations"]["history_completeness_proven"] is False
    assert report["observations"]["external_independence_proven"] is False


@pytest.mark.parametrize("case", ["missing-witness", "expired", "empty"])
def test_cli_retains_incomplete_evidence_and_nonzero_status(tmp_path, signed, case):
    args, evidence, _, output = inputs(tmp_path, signed)
    value = json.loads(evidence.read_bytes())
    if case == "missing-witness":
        value[0]["receipts"].pop()
    elif case == "expired":
        args[args.index("--now-us") + 1] = "100"
    else:
        value = []
    evidence.write_text(json.dumps(value))
    assert cli.main(args) == 1
    result = json.loads((output / "report.json").read_bytes())
    assert result["observations"]["status"] == "INCOMPLETE_OBSERVATIONS"
    assert result["supplied_evidence"] == value


def test_cli_never_overwrites_a_previous_export(tmp_path, signed):
    args, _, _, output = inputs(tmp_path, signed)
    output.mkdir()
    marker = output / "report.json"
    marker.write_bytes(b"retained original")
    assert cli.main(args) == 2
    assert marker.read_bytes() == b"retained original"
    assert not (output / "EXPORT.json").exists()


@pytest.mark.parametrize("raw", [b'{"keys":[],"keys":[]}', b'{"keys":NaN}', b'x' * (128 * 1024 + 1)],
                         ids=["duplicate-key", "nonfinite", "oversize"])
def test_cli_refuses_invalid_or_unbounded_host_trust_before_output(tmp_path, signed, raw):
    args, _, trust, output = inputs(tmp_path, signed)
    trust.write_bytes(raw)
    assert cli.main(args) == 2
    assert not output.exists()


def test_cli_refuses_duplicate_required_witnesses(tmp_path, signed):
    args, _, _, output = inputs(tmp_path, signed)
    assert cli.main(args + ["--witness", "witness-a"]) == 2
    assert not output.exists()
