"""Offline signed Education derivative integrity; not application qualification."""
import copy
import json

import pytest

from assurance_reference.packs import FIXTURES
from factory.packs.registry import PackRegistry, load_rulebook_document
from factory.packs.signing import verify_pack_signature, verify_provenance
from regulated_core.policy_document import verify_document
from regulated_core.signing import Ed25519Signer
from synthetic_health_versions import file_inventory, fixture_trust
from synthetic_tier4_education import build_tier4_education_fixture, SYNTHETIC_PUBLISHER


def test_tier4_derivative_verifies_and_changes_only_declared_policy_fields(tmp_path):
    original = FIXTURES / "bundles" / "education-0.1.2"
    before = file_inventory(original)
    old = load_rulebook_document(original)
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    target = tmp_path / "tier4"
    manifest = build_tier4_education_fixture(target, publisher=publisher)
    trust = fixture_trust()
    trust.register_signer(publisher)
    assert verify_pack_signature(target, manifest, trust, publisher_key_id=publisher.key_id)
    provenance = verify_provenance(target, manifest, trust)
    assert provenance.signer_key_id == SYNTHETIC_PUBLISHER
    derived = load_rulebook_document(target)
    assert verify_document(trust, derived, authority=publisher.key_id)
    expected = copy.deepcopy(old.content)
    expected["risk_tier"] = 4
    expected["rules"]["education:release-feedback"]["approval"].update(
        minimum_approvers=2, role_groups=[["teacher"], ["head-of-department"]])
    assert derived.content == expected
    assert derived.supersedes == old.digest()
    assert derived.version == "99.4.0"
    registry = PackRegistry(trust=trust)
    installed = registry.install(target, publisher_key_id=publisher.key_id, today="2026-10-14")
    assert installed.rulebook.effective_content == expected
    assert registry.active(manifest.id) is None
    params = json.loads((target / "provenance.json").read_bytes())[
        "statement"]["predicate"]["buildDefinition"]["externalParameters"]
    assert params["source_files"] == before
    assert params["source_rulebook_digest"] == old.digest()
    assert file_inventory(original) == before


def test_fixture_requires_its_named_synthetic_publisher(tmp_path):
    with pytest.raises(ValueError, match="explicitly synthetic"):
        build_tier4_education_fixture(tmp_path / "tier4", publisher=Ed25519Signer("fixture:other"))
    assert not (tmp_path / "tier4").exists()


def test_existing_fixture_target_is_preserved(tmp_path):
    target = tmp_path / "retained"
    target.mkdir()
    marker = target / "retained.txt"
    marker.write_text("retained")
    with pytest.raises(FileExistsError):
        build_tier4_education_fixture(target, publisher=Ed25519Signer(SYNTHETIC_PUBLISHER))
    assert marker.read_text() == "retained"
    assert list(target.iterdir()) == [marker]
