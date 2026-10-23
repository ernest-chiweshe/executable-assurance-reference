"""Reporting must expose omissions and refuse corrupted scope inputs."""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("scope_report", ROOT / "scripts/_scope_report.py")
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


def test_complete_declared_register_keeps_evidence_separate_from_scope():
    result = scope.obligations(scope.load_scope())
    assert result["declared_rows"] == 69
    assert {row["id"] for row in result["rows"]} == scope.EXPECTED_IDS
    assert result["engineering_complete"] is False
    assert all(row["status"] == "OPEN" and row["independent_verdict"] is None
               and row["exception"] is None for row in result["rows"])
    assert all(row["source_columns"] and row["evidence_plan"] and row["coverage_limits"]
               and row["mechanism"] for row in result["rows"])
    expiry = next(row for row in result["rows"] if row["id"] == "R-1")
    assert "synthetic" in json.dumps(expiry).lower()
    restore = next(row for row in result["rows"] if row["id"] == "R-2")
    assert "known" in json.dumps(restore).lower()


@pytest.mark.parametrize("name", ["scope-lock.json", "D0-obligation-map-draft-v10.md",
                                  "source-inventory.json", "exclusions-DRAFT-unsigned.json"])
def test_scope_tampering_is_not_silently_accepted(tmp_path, name):
    destination = tmp_path / "scope"
    shutil.copytree(scope.SCOPE, destination)
    path = destination / name
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed"):
        scope.load_scope(destination)


@pytest.mark.parametrize("name,key", [
    ("D0-obligation-map-draft-v10.md", "X-23"),
    ("D0-evidence-plan-part3-R-v2.md", "R-2b"),
])
def test_missing_obligation_or_plan_refuses_report(name, key):
    inputs = scope.load_scope()
    inputs[name] = "\n".join(line for line in inputs[name].splitlines()
                             if not line.startswith("| " + key + " |"))
    with pytest.raises(ValueError, match="Scope ID mismatch"):
        scope.obligations(inputs)


def test_duplicate_rows_refuse_report():
    with pytest.raises(ValueError, match="Duplicate obligation"):
        scope.table_rows("| Id | Obligation |\n| A01 | first |\n| A01 | second |")


def test_changed_and_absent_files_stay_gaps_even_with_a_signature_label(tmp_path):
    inputs = scope.load_scope()
    inventory = json.loads(inputs["source-inventory.json"])
    chosen = inventory["files"][:2]
    changed = tmp_path / chosen[0]["reference_path"]
    changed.parent.mkdir(parents=True)
    changed.write_bytes(b"changed fixture; no source executed")
    draft = json.loads(inputs["exclusions-DRAFT-unsigned.json"])
    for item in draft["exclusions"]:
        item["owner_signature"] = "a string is not verified authorization"
    inputs["exclusions-DRAFT-unsigned.json"] = json.dumps(draft)
    report = scope.parity(inputs, tmp_path)
    rows = {row["source_path"]: row for row in report["rows"]}
    assert rows[chosen[0]["source_path"]]["file_status"] == "DIFF_REQUIRES_REVIEW"
    assert rows[chosen[1]["source_path"]]["file_status"] == "ABSENT"
    assert report["applied_exclusions"] == 0
    assert report["authority_parity_established"] is False
    assert len([row for row in report["rows"] if row["proposed_exclusion"]]) == 4
    assert all(not row["exclusion_applied"] for row in report["rows"])


def test_byte_identity_does_not_establish_integration(tmp_path):
    inputs = scope.load_scope()
    one = {"source_path": "factory/example.py", "reference_path": "src/factory/example.py",
           "git_blob": "unused", "bytes": 7, "sha256": scope.sha(b"fixture")}
    path = tmp_path / one["reference_path"]
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fixture")
    inputs["source-inventory.json"] = json.dumps(
        {"source_commit": "fixture", "scope": "fixture", "files": [one]})
    inputs["exclusions-DRAFT-unsigned.json"] = '{"exclusions": []}'
    result = scope.parity(inputs, tmp_path)
    assert result["file_counts"] == {"BYTE_IDENTICAL": 1}
    assert result["rows"][0]["integration_verdict"] is None
    assert result["authority_parity_established"] is False


def test_inventory_path_cannot_escape_reference(tmp_path):
    inputs = scope.load_scope()
    inventory = json.loads(inputs["source-inventory.json"])
    inventory["files"][0]["reference_path"] = "../outside.py"
    inputs["source-inventory.json"] = json.dumps(inventory)
    with pytest.raises(ValueError, match="outside input root"):
        scope.parity(inputs, tmp_path)


def test_upstream_layout_is_explicit_and_keeps_declared_paths(tmp_path):
    inputs = scope.load_scope()
    one = {"source_path": "factory/example.py", "reference_path": "src/factory/example.py",
           "git_blob": "unused", "bytes": 7, "sha256": scope.sha(b"fixture")}
    inputs["source-inventory.json"] = json.dumps(
        {"source_commit": "fixture", "scope": "fixture", "files": [one]})
    inputs["exclusions-DRAFT-unsigned.json"] = '{"exclusions": []}'
    path = tmp_path / one["source_path"]
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fixture")
    assert scope.parity(inputs, tmp_path)["file_counts"] == {"ABSENT": 1}
    result = scope.parity(inputs, tmp_path, layout="upstream")
    assert result["source_layout"] == "upstream"
    assert result["file_counts"] == {"BYTE_IDENTICAL": 1}
    assert result["rows"][0]["checked_path"] == one["source_path"]
    assert result["rows"][0]["reference_path"] == one["reference_path"]
    assert result["rows"][0]["integration_verdict"] is None
    assert result["authority_parity_established"] is False
    path.write_bytes(b"changed")
    assert scope.parity(inputs, tmp_path, layout="upstream")["file_counts"] == {
        "DIFF_REQUIRES_REVIEW": 1}


def test_unknown_source_layout_refuses_before_reading_inventory(tmp_path):
    with pytest.raises(ValueError, match="Source layout"):
        scope.parity({}, tmp_path, layout="automatic")


@pytest.mark.parametrize("script,flag", [
    ("check_obligations.py", "--require-closed"),
    ("check_parity.py", "--require-identical"),
])
def test_cli_exit_status_distinguishes_valid_report_from_closure(script, flag):
    command = [sys.executable, str(ROOT / "scripts" / script)]
    ordinary = subprocess.run(command, capture_output=True, check=False)
    strict = subprocess.run(command + [flag], capture_output=True, check=False)
    assert ordinary.returncode == 0, ordinary.stderr
    assert strict.returncode == 1, strict.stderr
    assert json.loads(ordinary.stdout) == json.loads(strict.stdout)
