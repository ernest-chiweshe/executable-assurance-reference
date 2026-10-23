"""The bounded Education fixture is signed test data with explicit derivation."""
import copy
import json

import pytest

from assurance_reference.packs import FIXTURES
from factory.packs.registry import PackRegistry, load_rulebook_document
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.policy_document import verify_document
from regulated_core.signing import Ed25519Signer
from synthetic_bounded_education import (
    SYNTHETIC_PUBLISHER, SYNTHETIC_VERSION, build_bounded_education_fixture,
)
from synthetic_health_versions import file_inventory, fixture_trust


def test_bounded_education_installs_without_changing_original_or_activating(tmp_path):
    original = FIXTURES / "bundles" / "education-0.1.2"
    before = file_inventory(original)
    old_doc = load_rulebook_document(original)
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    trust = fixture_trust()
    trust.register_signer(publisher)
    target = tmp_path / "bounded"
    manifest = build_bounded_education_fixture(target, publisher=publisher)
    registry = PackRegistry(trust=trust, guard=GovernanceGuard())
    pack = registry.install(target, publisher_key_id=publisher.key_id, today="2026-10-15")
    assert pack.reference == manifest.reference
    assert pack.manifest.version == SYNTHETIC_VERSION
    assert pack.signature.key_id == publisher.key_id
    assert pack.provenance.builder_id == "synthetic-education-budget-fixture"
    assert pack.provenance.signer_key_id == publisher.key_id
    doc = pack.rulebook.document
    assert doc.version == SYNTHETIC_VERSION and doc.supersedes == old_doc.digest()
    assert verify_document(trust, doc, authority=publisher.key_id)
    assert doc.digest() != old_doc.digest()
    assert set(doc.content["rules"]) == {
        "education:draft-feedback", "education:release-feedback", "education:record-progress"}
    restored = copy.deepcopy(doc.content)
    for action, rule in restored["rules"].items():
        assert pack.rulebook.mission_budget(action) == {"limit": 1, "units": 1}
        assert rule.pop("mission_budget") == {"limit": 1, "units": 1}
    assert restored == old_doc.content
    old_index = json.loads((original / "pack.json").read_bytes())["files"]
    assert {name for name in manifest.files if manifest.files[name] != old_index[name]} == {
        "rulebook/rulebook.json"}
    assert set(manifest.files) == set(old_index)
    parameters = json.loads((target / "provenance.json").read_bytes())[
        "statement"]["predicate"]["buildDefinition"]["externalParameters"]
    assert parameters["fixture"] is True and parameters["source_files"] == before
    assert parameters["source_rulebook_digest"] == old_doc.digest()
    with pytest.raises(GovernanceRefused):
        registry.activate(pack.reference, at="unapproved synthetic activation")
    assert registry.active(manifest.id) is None
    assert file_inventory(original) == before


def test_bounded_fixture_refuses_to_overwrite_existing_version(tmp_path):
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    target = tmp_path / "bounded"
    build_bounded_education_fixture(target, publisher=publisher)
    before = file_inventory(target)
    with pytest.raises(FileExistsError):
        build_bounded_education_fixture(target, publisher=publisher)
    assert file_inventory(target) == before
