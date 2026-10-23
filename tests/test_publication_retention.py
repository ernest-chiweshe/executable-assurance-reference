"""Protect the actual corrected publication payload against retention-claim drift."""

import importlib.util
import json
from pathlib import Path
import shutil

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publication_retention", ROOT / "scripts/check_publication_retention.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
CONTRACT = json.loads((ROOT / "docs/retention-contract.json").read_text())
BUNDLE = ROOT / "docs/publication-corrections/retention"


def test_corrected_publication_payload_matches_contract_and_manifest():
    manifest = json.loads((BUNDLE / "CHANGE.json").read_text())
    assert checker.check(BUNDLE, CONTRACT) == manifest["after_sha256"]


@pytest.mark.parametrize("key,old,new", [
    ("paper_a", "**COMPLIANCE** mode", "**GOVERNANCE** mode"),
    ("paper_b", "S3 Object Lock (governance mode)", "S3 Object Lock (compliance mode)"),
    ("paper_a_figure", "compliance mode · write once, read many", "governance mode · write once, read many"),
    ("paper_a", "![Figure 11](figures/fig13-reference-deployment-v1.5.svg)",
     "![Figure 11](figures/fig13-reference-deployment-v1.3.svg)"),
    ("paper_a", "version 1.5 ·", "version 1.4 ·"),
    ("paper_b", "Companion source: Executable-Assurance-v11.md.",
     "Companion source: Executable-Assurance-v10.md."),
])
def test_publication_drift_fails(tmp_path, key, old, new):
    copy = tmp_path / "publications"
    shutil.copytree(BUNDLE, copy)
    path = copy / CONTRACT[key]
    text = path.read_text(encoding="utf-8-sig")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")
    with pytest.raises(ValueError):
        checker.check(copy, CONTRACT)


def test_contract_cannot_relabel_history_or_weaken_production():
    for key, value in (("production_mode", "GOVERNANCE"),
                       ("historical_evaluation_mode", "COMPLIANCE"),
                       ("compliance_mode_measured", True)):
        with pytest.raises(ValueError):
            checker.check(BUNDLE, {**CONTRACT, key: value})
