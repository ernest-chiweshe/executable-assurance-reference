"""Guarded Education/Health installation contracts on disposable bundle copies.

The original signed fixtures and all signature/governance controls stay intact.
Installation is tested independently of activation and operational qualification.
"""

import hashlib
import json
import shutil

import pytest

from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.packs.registry import PackRefused, PackRegistry
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.signing import TrustDirectory


BUNDLES = ("education-0.1.2", "health-workspace-membership")
REFUSALS = {
    "unsigned": "the pack is unsigned",
    "changed-content": "indexed file changed",
    "invalid-signature": "does not verify against the trust directory",
    "missing-provenance": "the pack carries no provenance",
    "wrong-publisher": "not the declared publisher key",
}


def trusted_registry():
    trust = TrustDirectory()
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    return PackRegistry(trust=trust, guard=GovernanceGuard())


def fingerprints(directory):
    return {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize("bundle", BUNDLES)
def test_intact_pack_installs_without_granting_activation(bundle):
    registry = trusted_registry()
    pack = registry.install(FIXTURES / "bundles" / bundle,
                            publisher_key_id=PUBLISHER, today="2026-10-14")
    assert registry.get(pack.reference) is pack
    assert registry.active(pack.manifest.id) is None
    with pytest.raises(GovernanceRefused):
        registry.activate(pack.reference, at="synthetic-unapproved-activation")
    assert registry.active(pack.manifest.id) is None


@pytest.mark.parametrize("bundle", BUNDLES)
@pytest.mark.parametrize("problem", REFUSALS)
def test_invalid_bundle_refuses_install_and_preserves_other_pack(tmp_path, bundle, problem):
    registry = trusted_registry()
    other = next(name for name in BUNDLES if name != bundle)
    prior = registry.install(FIXTURES / "bundles" / other,
                             publisher_key_id=PUBLISHER, today="2026-10-14")
    source = FIXTURES / "bundles" / bundle
    original = fingerprints(source)
    copy = tmp_path / "disposable-pack"
    shutil.copytree(source, copy)
    manifest = json.loads((copy / "pack.json").read_bytes())
    reference = manifest["id"] + "#" + manifest["version"]
    publisher = PUBLISHER
    if problem == "unsigned":
        (copy / ".signatures.json").unlink()
    elif problem == "changed-content":
        content = copy / "kit" / "README.md"
        content.write_bytes(content.read_bytes() + b"\nSynthetic altered fixture text.\n")
    elif problem == "invalid-signature":
        signature_file = copy / ".signatures.json"
        signed = json.loads(signature_file.read_bytes())
        signed["signature"]["value"] = "00"
        signature_file.write_text(json.dumps(signed), encoding="utf-8")
    elif problem == "missing-provenance":
        (copy / "provenance.json").unlink()
    elif problem == "wrong-publisher":
        publisher = "synthetic:unrelated-publisher"
    else:
        raise AssertionError(problem)
    with pytest.raises(PackRefused, match=REFUSALS[problem]):
        registry.install(copy, publisher_key_id=publisher, today="2026-10-14")
    assert registry.get(reference) is None
    assert registry.installed() == (prior,)
    assert registry.get(prior.reference) is prior
    assert registry.active(manifest["id"]) is None
    assert registry.active(prior.manifest.id) is None
    assert fingerprints(source) == original
