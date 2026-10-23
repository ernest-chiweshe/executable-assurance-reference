"""Original provenance stays exact; explicitly reviewed diffs are checked separately."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import site

ROOT = Path(__file__).resolve().parents[1]


def test_recovered_import_closure_matches_pinned_bytes_and_preserves_prior_sources(request):
    sys.path.insert(0, str(ROOT / "scripts"))
    from _source_adaptations import load_adaptations
    adaptations, _ = load_adaptations(ROOT,
        request.config.getoption("--source-adaptation-manifest"),
        request.config.getoption("--source-adaptation-sha256"), layout="reference")
    report = json.loads((ROOT / "source-provenance-authority.json").read_bytes())
    assert len(report["files"]) == 99
    assert report["source_commit"] == "6bba989aeca27575b971c78a103cbf3745cfda6a"
    assert report["replacements"] == [{
        "path": "src/factory/projectos/__init__.py",
        "before_sha256": "7dc83140e3e36679d699289a3fc3983019bed7cd49fcd275a5e1985015a16ec0",
        "reason": "Restore original ProjectEngine and declaration exports",
    }]
    for manifest in ROOT.glob("source-provenance*.json"):
        for item in json.loads(manifest.read_bytes())["files"]:
            raw = (ROOT / item["path"]).read_bytes()
            if item["path"] in adaptations:
                adaptation = adaptations[item["path"]]
                assert adaptation["original_sha256"] == item["sha256"]
                assert adaptation["original_git_blob"] == item["git_blob"]
                assert adaptation["source_path"] == item["source_path"]
                assert hashlib.sha256(raw).hexdigest() == adaptation["adapted_sha256"]
                raw = (ROOT / adaptation["original_path"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == item["sha256"], item["path"]


def test_original_projectos_exports_are_available():
    from factory.projectos import ProjectEngine, ProjectEngineError, VerticalSpec, validate_spec
    from factory.projectos.engine import ProjectEngine as Engine
    from factory.projectos.errors import ProjectEngineError as Error
    from factory.projectos.spec import VerticalSpec as Spec, validate_spec as validate

    assert (ProjectEngine, ProjectEngineError, VerticalSpec, validate_spec) == (
        Engine, Error, Spec, validate,
    )


def test_authority_imports_do_not_connect_or_load_cloud_sdks():
    code = '''
import sys, socket
from importlib.abc import MetaPathFinder
class NoCloud(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('boto3', 'botocore', 'azure', 'google'):
            raise AssertionError('cloud SDK imported: ' + fullname)
def refuse(*args, **kwargs):
    raise AssertionError('import attempted a network connection')
socket.socket.connect = refuse
socket.create_connection = refuse
sys.meta_path.insert(0, NoCloud())
sys.path.extend(sys.argv[2:])
sys.path.insert(0, sys.argv[1])
import regulated_core.host_runtime
import regulated_core.pack_gate
import regulated_core.prepared_schema_pg
import regulated_core.certificates
import factory.health_ui.session_release
import factory.packs.demonstration_checks
import factory.credentials
import factory.credential_currency
import assurance_reference.host_runtime
import assurance_reference.versioned_cas
import assurance_reference.policy_loading
import assurance_reference.operator_provisioning
import regulated_core.reviewer_sessions
import assurance_reference.reviewer_session_admission
import assurance_reference.reviewed_evidence
import assurance_reference.reviewed_evidence_support
import assurance_reference.reviewed_source_bindings
import factory.packs.demonstrations
import regulated_core.adapters
import factory.cryptoledger
import factory.keyprovider
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT / "src"),
                    *site.getsitepackages(), site.getusersitepackages()],
                   check=True, timeout=20, capture_output=True)
