"""Explicit synthetic sole-owner Education packs, preserving the historical 0.1.2 bytes."""
import copy
import hashlib
import json
import shutil

from assurance_reference.packs import FIXTURES, PUBLISHER
from assurance_reference.sole_owner_approval import SOLE_OWNER_TERM
from factory.packs.manifest import load_manifest
from factory.packs.registry import load_rulebook_document
from factory.packs.signing import sign_pack, verify_pack_signature, verify_provenance, write_provenance
from regulated_core.policy_document import document_policy, verify_document
from synthetic_health_versions import file_inventory, fixture_trust

SYNTHETIC_VERSION = "99.7.0"
SYNTHETIC_PUBLISHER = "fixture:education-sole-owner-publisher"
RELEASE = "education:release-feedback"


def build_sole_owner_education_fixture(target, *, publisher, term=SOLE_OWNER_TERM, requester_may_approve=True):
    """Sign a test-only derivative whose feedback release one teacher may approve, including their own request.

    Every action keeps a one-unit mission ceiling. ``term``/``requester_may_approve`` select the signed
    self-approval terms under test; this is never an owner-signed policy or a production ownership model.
    """
    if publisher.key_id != SYNTHETIC_PUBLISHER:
        raise ValueError("sole-owner Education requires the explicitly synthetic fixture publisher")
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
        rule["mission_budget"] = {"limit": 1, "units": 1}
    approval = content["rules"][RELEASE]["approval"]
    if approval.get("requester_may_approve") or "self_approval_term" in approval:
        raise ValueError("fixture expects the original Education release to forbid self-approval")
    approval.update(requester_may_approve=requester_may_approve, minimum_approvers=1, role_groups=[["teacher"]])
    # A sole-owner workspace has no second reviewer: the signed derivative drops the low-confidence escalation.
    content["rules"][RELEASE].pop("second_review", None)
    if term is not None:
        approval["self_approval_term"] = term
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
    raw.update(version=SYNTHETIC_VERSION, title="Synthetic sole-owner Education fixture",
               publisher="Synthetic local sole-owner fixture")
    raw["rulebook"] = {**raw["rulebook"], "digest": derived_document.digest(),
                      "ref": f"{derived_document.vertical}/{derived_document.policy_id}@{SYNTHETIC_VERSION}"}
    raw["files"]["rulebook/rulebook.json"] = hashlib.sha256(document_path.read_bytes()).hexdigest()
    (target / "pack.json").write_text(json.dumps(raw, sort_keys=True, indent=2), encoding="utf-8")
    derived = load_manifest(target)
    sign_pack(target, derived, publisher)
    write_provenance(target, derived, builder_id="synthetic-education-sole-owner-fixture",
        build_type="local-contract-test-only", external_parameters={
            "fixture": True, "source_reference": manifest.reference,
            "source_manifest_digest": manifest.digest, "source_rulebook_digest": old_document.digest(),
            "source_files": before, "requester_may_approve": requester_may_approve, "self_approval_term": term, "second_review": "removed for the sole-owner release",
            "scope": "Synthetic sole-owner self-approval test only; no deployed, historical or owner-signature claim",
        }, signer=publisher)
    if file_inventory(original) != before:
        raise AssertionError("historical Education fixture changed")
    return derived
