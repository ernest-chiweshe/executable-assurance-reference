"""Explicitly synthetic signed application versions for lifecycle contract tests.

The original signed qualification pack is verified and copied, never edited.
Only manifest identity metadata changes; rulebook/content bytes remain pinned.
New provenance names this fixture and its derivation, not a historical build.
"""
import hashlib
import json
import shutil

from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.packs.manifest import load_manifest
from factory.packs.signing import (
    sign_pack, verify_pack_signature, verify_provenance, write_provenance,
)
from regulated_core.signing import TrustDirectory


def file_inventory(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def fixture_trust():
    trust = TrustDirectory()
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    return trust


def build_synthetic_health_version(target, *, version, publisher):
    return _build_version(target, version=version, publisher=publisher,
                          bundle="health-workspace-membership", domain="Health")


def build_synthetic_education_version(target, *, version, publisher):
    return _build_version(target, version=version, publisher=publisher,
                          bundle="education-0.1.2", domain="Education")


def _build_version(target, *, version, publisher, bundle, domain):
    if version not in {"99.0.1", "99.0.2"}:
        raise ValueError("only the two explicit synthetic lifecycle versions are supported")
    original = FIXTURES / "bundles" / bundle
    before = file_inventory(original)
    manifest = load_manifest(original)
    trust = fixture_trust()
    verify_pack_signature(original, manifest, trust, publisher_key_id=PUBLISHER)
    verify_provenance(original, manifest, trust)
    # copytree refuses an existing target; it cannot overwrite retained evidence.
    shutil.copytree(original, target)
    raw = json.loads((target / "pack.json").read_bytes())
    raw.update(version=version, title=f"Fictional {domain} lifecycle test version " + version,
               publisher="Synthetic local lifecycle fixture")
    (target / "pack.json").write_text(json.dumps(raw, sort_keys=True, indent=2), encoding="utf-8")
    derived = load_manifest(target)
    sign_pack(target, derived, publisher)
    write_provenance(target, derived, builder_id=f"synthetic-{domain.lower()}-lifecycle-fixture",
        build_type="local-contract-test-only", external_parameters={
            "fixture": True, "source_reference": manifest.reference,
            "source_manifest_digest": manifest.digest,
            "scope": "Synthetic lifecycle identity only; no deployed or historical version claim",
        }, signer=publisher)
    assert file_inventory(original) == before
    assert derived.files == manifest.files
    return derived

