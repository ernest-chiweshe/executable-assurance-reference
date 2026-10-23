"""Static trace reports preserve gaps and never execute recovered modules."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("source_trace", ROOT / "scripts/check_source_trace.py")
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


def fixture(root):
    sources = {"factory/__init__.py": "",
               "factory/policy.py": "from . import helper\n",
               "factory/helper.py": "raise RuntimeError('source must never execute')\nfrom . import policy\n",
               "factory/unrelated.py": "pass\n"}
    entries = []
    for name, text in sources.items():
        data = text.encode()
        path = root / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append({"path": "src/" + name, "source_path": name, "sha256": trace.sha(data),
                        "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    (root / "source-provenance.json").write_text(json.dumps({"source_commit": trace.COMMIT,
        "source_tree": trace.TREE, "files": entries}), encoding="utf-8")
    policy = next(row for row in entries if row["source_path"] == "factory/policy.py")
    inputs = {name: "" for name in trace.ANCHOR_FILES}
    inputs[trace.ANCHOR_FILES[0]] = f"| A03 | `factory/policy.py` | `{policy['git_blob']}` | fixture |"
    return inputs


def test_relative_import_cycles_and_parent_initializers_without_execution(tmp_path):
    report = trace.build_report(tmp_path, fixture(tmp_path))
    rows = {item["path"]: item for item in report["files"]}
    assert rows["src/factory/helper.py"]["traces"] == [{"row_id": "A03",
        "anchor": "src/factory/policy.py", "anchor_document": trace.ANCHOR_FILES[0],
        "path": ["src/factory/policy.py", "src/factory/helper.py"], "edges": ["STATIC_IMPORT"]}]
    assert rows["src/factory/helper.py"]["classification"] == "SUPPORT"
    assert rows["src/factory/__init__.py"]["row_ids"] == ["A03"]
    assert report["untraced_files"] == ["src/factory/unrelated.py"]
    assert report["all_recovered_files_traced"] is False
    assert all(row["integration_verdict"] is None and row["row_test_evidence"] == []
               for row in report["files"])


def test_changed_recovered_source_refuses_trace(tmp_path):
    inputs = fixture(tmp_path)
    (tmp_path / "src/factory/helper.py").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="source bytes changed"):
        trace.build_report(tmp_path, inputs)


def test_anchor_blob_must_match_verified_provenance(tmp_path):
    inputs = fixture(tmp_path)
    inputs[trace.ANCHOR_FILES[0]] = "| A03 | `factory/policy.py` | `" + "0" * 40 + "` | fixture |"
    with pytest.raises(ValueError, match="anchor blob differs"):
        trace.build_report(tmp_path, inputs)


def test_explicit_binding_does_not_gain_independent_acceptance(tmp_path):
    inputs = fixture(tmp_path)
    path = tmp_path / "docs/qualification/source-trace-bindings.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema": "reference/source-row-bindings/v1",
        "scope_lock_sha256": trace.LOCK_SHA256, "files": [{
        "path": "src/factory/unrelated.py", "sha256": trace.sha(b"pass\n"), "row_ids": ["X-1"],
        "reason": "Explicit fixture mapping awaiting review", "consumers": ["src/factory/policy.py"],
    }]}), encoding="utf-8")
    report = trace.build_report(tmp_path, inputs)
    assert report["all_recovered_files_traced"]
    row = next(row for row in report["files"] if row["path"].endswith("unrelated.py"))
    assert row["classification"] == "REFERENCE_BINDING"
    assert row["reference_binding"]["review_verdict"] is None
    assert report["engineering_complete"] is False and report["obligations_promoted"] == 0


def test_current_recovery_trace_is_complete_but_not_implementation_acceptance(request):
    report = trace.build_report(ROOT,
        adaptation_manifest=request.config.getoption("--source-adaptation-manifest"),
        adaptation_sha256=request.config.getoption("--source-adaptation-sha256"))
    assert report["all_recovered_files_traced"]
    assert report["untraced_modules"] == []
    assert report["classification_counts"]["SUPPORT"] > 0
    assert report["reference_bindings_review_required"]
    assert report["engineering_complete"] is False
    assert all(row["row_ids"] and row["integration_verdict"] is None for row in report["files"])


def test_upstream_layout_is_explicit_and_preserves_reference_trace_paths(tmp_path):
    inputs = fixture(tmp_path)
    (tmp_path / "src/factory").rename(tmp_path / "factory")
    with pytest.raises(FileNotFoundError):
        trace.build_report(tmp_path, inputs)
    report = trace.build_report(tmp_path, inputs, layout="upstream")
    rows = {row["path"]: row for row in report["files"]}
    helper = rows["src/factory/helper.py"]
    assert helper["checked_path"] == helper["source_path"] == "factory/helper.py"
    assert helper["traces"][0]["path"] == ["src/factory/policy.py", "src/factory/helper.py"]
    assert report["source_layout"] == "upstream"
    assert report["untraced_files"] == ["src/factory/unrelated.py"]
    assert report["engineering_complete"] is False and report["obligations_promoted"] == 0
    (tmp_path / "factory/helper.py").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="source bytes changed"):
        trace.build_report(tmp_path, inputs, layout="upstream")


def test_upstream_binding_consumer_uses_explicit_layout(tmp_path):
    inputs = fixture(tmp_path)
    path = tmp_path / "docs/qualification/source-trace-bindings.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema": "reference/source-row-bindings/v1",
        "scope_lock_sha256": trace.LOCK_SHA256, "files": [{
        "path": "src/factory/unrelated.py", "sha256": trace.sha(b"pass\n"), "row_ids": ["X-1"],
        "reason": "Fixture consumer; no independent verdict", "consumers": ["src/factory/policy.py"],
    }]}), encoding="utf-8")
    (tmp_path / "src/factory").rename(tmp_path / "factory")
    report = trace.build_report(tmp_path, inputs, layout="upstream")
    row = next(row for row in report["files"] if row["path"] == "src/factory/unrelated.py")
    assert row["reference_binding"]["consumers"] == [{"path": "src/factory/policy.py",
        "checked_path": "factory/policy.py", "sha256": trace.sha((tmp_path / "factory/policy.py").read_bytes())}]
    assert row["reference_binding"]["review_verdict"] is None


def test_unknown_source_layout_refused_before_reading_inputs(tmp_path):
    with pytest.raises(ValueError, match="Unknown source layout"):
        trace.build_report(tmp_path, layout="automatic")
