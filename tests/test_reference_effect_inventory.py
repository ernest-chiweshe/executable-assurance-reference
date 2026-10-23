"""Passive inventory covers local reference packages and preserves coverage limits."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from inventory_reference_effects import inventory  # noqa: E402


def source(root, path, text):
    target = root / "src" / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def test_all_packages_and_no_site_files_are_hash_bound_without_import(tmp_path):
    a = source(tmp_path, "assurance_reference/a.py",
               "raise RuntimeError('must never execute')\nfrom pathlib import Path\n"
               "Path('never-written').write_text('synthetic')\n")
    b = source(tmp_path, "factory/b.py", "SQL = 'INSERT INTO fixture VALUES (1)'\n")
    c = source(tmp_path, "regulated_core/c.py", "pass\n")
    report = inventory(tmp_path)
    rows = {row["path"]: row for row in report["files"]}
    assert report["python_files_scanned"] == 3
    assert report["files_with_static_sites"] == 2
    assert report["site_counts"] == {"database": 1, "file": 1}
    for path in (a, b, c):
        assert rows[path.relative_to(tmp_path).as_posix()]["sha256"] == sha256(path.read_bytes()).hexdigest()
    assert rows["src/regulated_core/c.py"]["sites"] == []
    assert not (tmp_path / "never-written").exists()
    assert not report["complete_effect_coverage_proven"] and not report["guard_coverage_proven"]


def test_aliases_are_detected_and_indirect_ports_remain_explicitly_unproven(tmp_path):
    source(tmp_path, "fixture.py", "from subprocess import run as start\n"
           "start(['synthetic'])\nhost.send(message)\n")
    report = inventory(tmp_path)
    assert report["site_counts"] == {"process": 1}
    assert any("Indirect host ports" in item for item in report["limits"])
    assert not report["complete_effect_coverage_proven"]


@pytest.mark.parametrize("case", ["missing", "empty", "invalid-syntax"])
def test_invalid_scope_is_an_error_not_an_empty_clean_report(tmp_path, case):
    if case == "empty":
        (tmp_path / "src").mkdir()
    elif case == "invalid-syntax":
        source(tmp_path, "bad.py", "def broken(\n")
    with pytest.raises((ValueError, SyntaxError)):
        inventory(tmp_path)


def test_cli_json_and_failure_exit(tmp_path):
    source(tmp_path, "fixture.py", "pass\n")
    cmd = [sys.executable, "-B", str(ROOT / "scripts/inventory_reference_effects.py")]
    result = subprocess.run([*cmd, "--root", str(tmp_path)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0
    assert json.loads(result.stdout)["python_files_scanned"] == 1
    bad = subprocess.run([*cmd, "--root", str(tmp_path / "absent")],
                         capture_output=True, text=True, timeout=20)
    assert bad.returncode == 2 and bad.stdout == ""


def test_scanner_retains_exact_original_bytes():
    proof = json.loads((ROOT / "docs/provenance/effect-inventory.json").read_bytes())
    raw = (ROOT / proof["retained_path"]).read_bytes()
    assert sha256(raw).hexdigest() == proof["sha256"]
    import hashlib
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == proof["git_blob"]
