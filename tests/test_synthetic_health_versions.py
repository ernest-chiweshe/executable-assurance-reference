"""Lawful local application versions retain signed rulebook/content identity."""
import json

import pytest

from assurance_reference.packs import FIXTURES
from factory.packs.registry import PackRegistry
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.signing import Ed25519Signer
from synthetic_health_versions import (
    build_synthetic_education_version, build_synthetic_health_version, file_inventory, fixture_trust,
)


@pytest.mark.parametrize("domain,bundle,builder", [
    ("health", "health-workspace-membership", build_synthetic_health_version),
    ("education", "education-0.1.2", build_synthetic_education_version),
])
def test_two_synthetic_versions_install_without_mutating_original_or_activating(tmp_path, domain, bundle, builder):
    original = FIXTURES / "bundles" / bundle
    before = file_inventory(original)
    publisher = Ed25519Signer(f"fixture:{domain}-lifecycle-publisher")
    trust = fixture_trust()
    trust.register_signer(publisher)
    registry = PackRegistry(trust=trust, guard=GovernanceGuard())
    packs = []
    for version in ("99.0.1", "99.0.2"):
        target = tmp_path / version
        manifest = builder(target, version=version, publisher=publisher)
        pack = registry.install(target, publisher_key_id=publisher.key_id, today="2026-10-14")
        assert pack.reference == manifest.reference
        assert pack.signature.key_id == publisher.key_id
        assert pack.provenance.builder_id == f"synthetic-{domain}-lifecycle-fixture"
        assert pack.provenance.signer_key_id == publisher.key_id
        provenance = json.loads((target / "provenance.json").read_bytes())
        assert provenance["statement"]["predicate"]["buildDefinition"]["externalParameters"]["fixture"] is True
        with pytest.raises(GovernanceRefused):
            registry.activate(pack.reference, at="unapproved synthetic activation")
        assert registry.active(manifest.id) is None
        packs.append(pack)
    assert packs[0].manifest.id == packs[1].manifest.id
    assert packs[0].manifest.digest != packs[1].manifest.digest
    assert packs[0].rulebook.document == packs[1].rulebook.document
    assert packs[0].manifest.files == packs[1].manifest.files
    assert registry.versions(packs[0].manifest.id) == ("99.0.1", "99.0.2")
    assert file_inventory(original) == before
