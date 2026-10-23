"""Explicit synthetic bounded Education pack, preserving the historical 0.1.2 bytes."""
import copy
import hashlib
import json
import shutil

from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.packs.manifest import load_manifest
from factory.packs.registry import load_rulebook_document
from factory.packs.signing import sign_pack, verify_pack_signature, verify_provenance, write_provenance
from regulated_core.policy_document import document_policy, verify_document
from synthetic_health_versions import file_inventory, fixture_trust

SYNTHETIC_VERSION = "99.1.0"
SYNTHETIC_PUBLISHER = "fixture:education-budget-publisher"


def build_bounded_education_fixture(target, *, publisher):
    """Sign a test-only derivative with one unit per action and a one-unit mission ceiling.

    These numeric terms are test data, never a production quota selection.
    No original manifest, rulebook, signature, provenance or trust anchor is edited.
    """
    if publisher.key_id != SYNTHETIC_PUBLISHER:
        raise ValueError("bounded Education requires the explicitly synthetic fixture publisher")
    original = FIXTURES / "bundles" / "education-0.1.2"
    before = file_inventory(original)
    manifest = load_manifest(original)
    trust = fixture_trust()
    verify_pack_signature(original, manifest, trust, publisher_key_id=PUBLISHER)
    verify_provenance(original, manifest, trust)
    old_document = load_rulebook_document(original)
    if not verify_document(trust, old_document):
        raise ValueError("original Education rulebook signature did not verify")
    content = copy.deepcopy(old_document.content)
    for rule in content["rules"].values():
        if "mission_budget" in rule:
            raise ValueError("fixture expects the retained original unbudgeted Education rulebook")
        rule["mission_budget"] = {"limit": 1, "units": 1}
    derived_document = document_policy(publisher, vertical=old_document.vertical,
        policy_id=old_document.policy_id, version=SYNTHETIC_VERSION, content=content,
        jurisdictions=old_document.jurisdictions, effective_from_us=old_document.effective_from_us,
        effective_until_us=old_document.effective_until_us, supersedes=old_document.digest())
    # Existing targets are refused rather than replacing an earlier signed fixture.
    shutil.copytree(original, target)
    document_path = target / "rulebook" / "rulebook.json"
    document_path.write_text(json.dumps({**derived_document.signed_body(), "signature": {
        "key_id": derived_document.signature.key_id, "alg": derived_document.signature.alg,
        "value": derived_document.signature.value}}, sort_keys=True, indent=2), encoding="utf-8")
    raw = json.loads((target / "pack.json").read_bytes())
    raw.update(version=SYNTHETIC_VERSION, title="Synthetic bounded Education budget fixture",
               publisher="Synthetic local budget fixture")
    raw["rulebook"] = {**raw["rulebook"], "digest": derived_document.digest(),
                      "ref": f"{derived_document.vertical}/{derived_document.policy_id}@{SYNTHETIC_VERSION}"}
    raw["files"]["rulebook/rulebook.json"] = hashlib.sha256(document_path.read_bytes()).hexdigest()
    (target / "pack.json").write_text(json.dumps(raw, sort_keys=True, indent=2), encoding="utf-8")
    derived = load_manifest(target)
    sign_pack(target, derived, publisher)
    write_provenance(target, derived, builder_id="synthetic-education-budget-fixture",
        build_type="local-contract-test-only", external_parameters={
            "fixture": True, "source_reference": manifest.reference,
            "source_manifest_digest": manifest.digest, "source_rulebook_digest": old_document.digest(),
            "source_files": before,
            "scope": "Synthetic budget test only; no deployed, historical, owner-signature or production-quota claim",
            "change": "All three action rules declare mission_budget limit=1 units=1",
        }, signer=publisher)
    if file_inventory(original) != before:
        raise AssertionError("historical Education fixture changed")
    return derived
