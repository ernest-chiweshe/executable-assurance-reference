"""An explicit diff proves provenance, never approval or byte identity."""

import difflib
import json

import pytest

from test_source_trace import fixture, trace
from _source_adaptations import git_blob


def adaptation(root):
    inputs = fixture(root)
    path = root / "src/factory/policy.py"
    original = path.read_bytes()
    actual = original + b"# Explicit synthetic adaptation\n"
    path.write_bytes(actual)
    (root / "originals").mkdir()
    (root / "originals/policy.py").write_bytes(original)
    patch = "".join(difflib.unified_diff(
        original.decode().splitlines(keepends=True), actual.decode().splitlines(keepends=True),
        fromfile="a/factory/policy.py", tofile="b/factory/policy.py")).encode()
    (root / "proposal.patch").write_bytes(patch)
    manifest = {"schema": "reference/explicit-source-adaptations/v1",
                "source_commit": trace.COMMIT, "source_tree": trace.TREE,
                "patch_path": "proposal.patch", "patch_sha256": trace.sha(patch), "files": [{
                    "source_path": "factory/policy.py", "path": "src/factory/policy.py",
                    "original_path": "originals/policy.py", "original_sha256": trace.sha(original),
                    "original_git_blob": git_blob(original), "adapted_sha256": trace.sha(actual),
                    "recovered_source": True}]}
    return inputs, manifest


def report(root, inputs, manifest, **kwargs):
    raw = json.dumps(manifest).encode()
    (root / "adaptations.json").write_bytes(raw)
    return trace.build_report(root, inputs, adaptation_manifest="adaptations.json",
                              adaptation_sha256=trace.sha(raw), **kwargs)


def test_explicit_diff_preserves_original_anchor_without_claiming_acceptance(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    result = report(tmp_path, inputs, manifest)
    row = next(row for row in result["files"] if row["path"] == "src/factory/policy.py")
    assert row["byte_identity"] is False
    assert row["sha256"] == manifest["files"][0]["original_sha256"]
    assert row["actual_sha256"] == manifest["files"][0]["adapted_sha256"] != row["sha256"]
    assert row["git_blob"] == manifest["files"][0]["original_git_blob"]
    assert row["direct_rows"] == ["A03"]
    assert row["integration_verdict"] is None
    assert result["explicit_adaptation_manifest"]["approval_verified"] is False
    assert row["explicit_adaptation"]["approval_verified"] is False
    assert result["engineering_complete"] is False and result["obligations_promoted"] == 0
    assert result["adapted_source_files"] == ["src/factory/policy.py"]
    # Presence of a manifest never opts in automatically.
    with pytest.raises(ValueError, match="source bytes changed"):
        trace.build_report(tmp_path, inputs)


@pytest.mark.parametrize("kwargs", [
    {"adaptation_manifest": "adaptations.json"},
    {"adaptation_sha256": "0" * 64},
])
def test_both_explicit_arguments_required(tmp_path, kwargs):
    inputs, _ = adaptation(tmp_path)
    with pytest.raises(ValueError, match="explicit manifest and expected"):
        trace.build_report(tmp_path, inputs, **kwargs)


def test_manifest_pin_required(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    (tmp_path / "adaptations.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest hash"):
        trace.build_report(tmp_path, inputs, adaptation_manifest="adaptations.json",
                           adaptation_sha256="0" * 64)


@pytest.mark.parametrize("path,message", [
    ("originals/policy.py", "Retained original bytes"),
    ("src/factory/policy.py", "Adapted source bytes"),
    ("proposal.patch", "patch hash"),
])
def test_changed_artifact_refused(tmp_path, path, message):
    inputs, manifest = adaptation(tmp_path)
    with (tmp_path / path).open("ab") as stream:
        stream.write(b"# changed\n")
    with pytest.raises(ValueError, match=message):
        report(tmp_path, inputs, manifest)


def test_rehashed_but_unrelated_patch_refused(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    (tmp_path / "proposal.patch").write_bytes(b"unrelated patch\n")
    manifest["patch_sha256"] = trace.sha(b"unrelated patch\n")
    with pytest.raises(ValueError, match="reconstruct the exact pinned patch"):
        report(tmp_path, inputs, manifest)


def test_original_provenance_must_agree(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    path = tmp_path / "source-provenance.json"
    provenance = json.loads(path.read_bytes())
    provenance["files"][1]["sha256"] = "0" * 64
    path.write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(ValueError, match="pinned recovered provenance"):
        report(tmp_path, inputs, manifest)


def test_unlisted_recovered_source_refused(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    path = tmp_path / "source-provenance.json"
    provenance = json.loads(path.read_bytes())
    provenance["files"] = [item for item in provenance["files"]
                           if item["source_path"] != "factory/policy.py"]
    path.write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(ValueError, match="absent from recovered provenance"):
        report(tmp_path, inputs, manifest)


def test_duplicate_paths_refused(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    manifest["files"].append(dict(manifest["files"][0]))
    with pytest.raises(ValueError, match="Duplicate or overlapping"):
        report(tmp_path, inputs, manifest)


@pytest.mark.parametrize("path", ["factory/../policy.py", "factory\\policy.py", "./factory/policy.py"])
def test_noncanonical_patch_labels_refused(tmp_path, path):
    inputs, manifest = adaptation(tmp_path)
    manifest["files"][0]["source_path"] = path
    with pytest.raises(ValueError, match="canonical relative POSIX"):
        report(tmp_path, inputs, manifest)


def test_no_implicit_upstream_layout_adaptation(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    with pytest.raises(ValueError, match="require reference layout"):
        report(tmp_path, inputs, manifest, layout="upstream")


def test_nonrecovered_classification_cannot_hide_modified_recovered_source(tmp_path):
    inputs, manifest = adaptation(tmp_path)
    manifest["files"][0]["recovered_source"] = False
    with pytest.raises(ValueError, match="source bytes changed"):
        report(tmp_path, inputs, manifest)
