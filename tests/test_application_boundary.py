"""Exercise the shared declaration while keeping authority in the composition root."""

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from factory.projectos.spec import VerticalSpec, validate_spec
from factory.projectos.synthetic import EDUCATION, HEALTH, propose
from assurance_reference.application_binding import check_binding
from regulated_core import CoursePolicy, HealthPolicy

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("spec,digest", [
    (EDUCATION, "d75513bbb81148a8ae6056fa9aceb51afcbc633900e92553d6e42f0ebb7f0c8c"),
    (HEALTH, "0e74cadf9fe2841d1ec2ae82847314a724b90c9c22bbed3a9ea5586a789b412b"),
])
def test_same_application_contract_preserves_existing_payload(spec, digest):
    assert type(spec) is VerticalSpec
    assert validate_spec(spec) == []
    assert hashlib.sha256(propose(spec)).hexdigest() == digest


def test_declarations_load_without_governance_or_composition_dependencies():
    script = '''
import sys
from importlib.abc import MetaPathFinder
class Boundary(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('regulated_core', 'assurance_reference'):
            raise AssertionError('reverse dependency: ' + fullname)
sys.meta_path.insert(0, Boundary())
sys.path.insert(0, sys.argv[1])
from factory.projectos.synthetic import EDUCATION, HEALTH, propose
assert propose(EDUCATION) and propose(HEALTH)
'''
    subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT / "src")],
        check=True, timeout=15, capture_output=True,
    )


def test_inherited_declaration_bytes_and_static_import_boundary():
    provenance = json.loads((ROOT / "source-provenance-application.json").read_text())
    for item in provenance["files"]:
        assert hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() == item["sha256"]
    for path in (ROOT / "src/factory/projectos").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            assert not any(n.split(".")[0] in ("regulated_core", "assurance_reference")
                           for n in names), path


def test_host_policy_binding_refuses_mismatches():
    check_binding(EDUCATION, CoursePolicy.ref)
    check_binding(HEALTH, HealthPolicy.ref, verifiers=HEALTH.regulated.required_verifiers)
    with pytest.raises(ValueError):
        check_binding(EDUCATION, HealthPolicy.ref)
    with pytest.raises(ValueError):
        check_binding(HEALTH, HealthPolicy.ref, verifiers=())
    bad = replace(HEALTH, regulated=replace(HEALTH.regulated, policy_ref="wrong-policy"))
    with pytest.raises(ValueError):
        check_binding(bad, HealthPolicy.ref, verifiers=HEALTH.regulated.required_verifiers)


def test_invalid_application_stops_before_content_production():
    calls = []
    bad = replace(HEALTH, stages=(), computed_inputs={"content": lambda *_: calls.append(1)})
    with pytest.raises(ValueError):
        propose(bad)
    assert calls == []
