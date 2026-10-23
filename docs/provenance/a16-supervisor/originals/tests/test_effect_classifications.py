"""Fail closed on static inventory drift using harmless synthetic source text."""

from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_effect_inventory import check  # noqa: E402


def fixture(root):
    path = root / "src/sample.py"
    path.parent.mkdir()
    raw = b"def prepare(folder):\n    folder.mkdir()\n"
    path.write_bytes(raw)
    return path, {
        "schema": "reference/static-effect-classifications/v1",
        "authorization_exemptions": [],
        "sites": [{
            "path": "src/sample.py", "kind": "file", "line": 2,
            "call_or_sql": "folder.mkdir", "source_sha256": sha256(raw).hexdigest(),
            "classification": "fixture_effect", "locus": "prepare",
            "reason": "Synthetic source fixture; this code is never executed.",
            "authority_review": "Inventory test only; no authorization claim.",
            "not_an_authorization_exemption": True,
        }],
    }


def test_complete_private_candidate_static_sites_are_classified():
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "docs/provenance/effect-site-classifications.json").read_bytes())
    result = check(root, catalog)
    assert result["classified_sites"] == 263
    assert result["static_site_accounting_complete"]
    assert not result["authorization_coverage_proven"]
    assert not result["complete_effect_coverage_proven"]


def test_reviewed_synthetic_source_passes_without_execution(tmp_path):
    _, catalog = fixture(tmp_path)
    assert check(tmp_path, catalog)["classified_sites"] == 1


@pytest.mark.parametrize("location", ("same-module", "new-module"))
def test_new_unclassified_site_fails(tmp_path, location):
    path, catalog = fixture(tmp_path)
    if location == "same-module":
        path.write_bytes(path.read_bytes() + b"    other.mkdir()\n")
    else:
        (path.parent / "new.py").write_text("folder.mkdir()\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unclassified=.*mkdir"):
        check(tmp_path, catalog)


def test_removed_site_requires_catalog_review(tmp_path):
    path, catalog = fixture(tmp_path)
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale=.*mkdir"):
        check(tmp_path, catalog)


def test_changed_site_context_requires_review(tmp_path):
    path, catalog = fixture(tmp_path)
    path.write_bytes(path.read_bytes() + b"# changed context\n")
    with pytest.raises(ValueError, match="source_drift=.*mkdir"):
        check(tmp_path, catalog)


@pytest.mark.parametrize("defect", ("duplicate", "no-reason", "exemption", "unknown-class"))
def test_invalid_classification_refused(tmp_path, defect):
    _, catalog = fixture(tmp_path)
    if defect == "duplicate":
        catalog["sites"].append(catalog["sites"][0].copy())
    elif defect == "no-reason":
        catalog["sites"][0]["reason"] = ""
    elif defect == "exemption":
        catalog["authorization_exemptions"] = ["fixture"]
    else:
        catalog["sites"][0]["classification"] = "implicit"
    with pytest.raises(ValueError):
        check(tmp_path, catalog)
