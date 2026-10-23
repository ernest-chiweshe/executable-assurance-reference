"""Guarded E/H version selection, tenant pin isolation and actual application release.

Normal tier-4 approvals, reporting lines, positive cooling and monitor clearance
remain in force. Both domains use explicitly synthetic lifecycle versions;
the original bundles and underlying signed rulebooks retain their bytes.
"""
import json
import os
from dataclasses import replace

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.health_ui.documents import CLINICIAN, OBSERVATION, Paragraph, Session, build_document
from factory.health_ui.templates import CONSULTATION
from factory.packs.registry import PackRegistry
from partitioned_governance_fixture import GovernedFixture
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome
from synthetic_health_versions import build_synthetic_education_version, build_synthetic_health_version
import test_clinical_finalisation as clinical_contracts
import test_education_session_release as education_contracts


class GovernedRegistryFixture(PackRegistry):
    def authorize(self, engine, **parameters):
        return engine.authorize_for_target(**parameters)


@pytest.mark.parametrize("domain", ["education", "health"])
def test_governed_pin_survives_global_rollback_and_only_governs_its_application_tenant(tmp_path, domain):
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    if domain == "education":
        app = build_education_fixture(roles, tmp_path / "application", partitioned_lifecycle=True)
        tenant, original = "school-a", "education-0.1.2"
    else:
        app = build_clinical_fixture(roles, tmp_path / "application", partitioned_lifecycle=True)
        tenant, original = app.clinician.workspace_id, "health-workspace-membership"
    g = GovernedFixture(roles)
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        g.trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    registry = GovernedRegistryFixture(trust=g.trust, activation=g.packs.ledger)
    original_pack = registry.install(FIXTURES / "bundles" / original,
                                     publisher_key_id=PUBLISHER, today="2026-10-14")
    # Education 0.1.1 lacks two collections already in the application's 0.1.2;
    # its downgrade is correctly refused. Derived test versions preserve all
    # original schemas and authority bytes, allowing lawful lifecycle exercise.
    builder = build_synthetic_education_version if domain == "education" else build_synthetic_health_version
    publisher = Ed25519Signer(f"fixture:{domain}-lifecycle-publisher")
    g.trust.register_signer(publisher)
    references = []
    for version in ("99.0.1", "99.0.2"):
        path = tmp_path / version
        builder(path, version=version, publisher=publisher)
        references.append(registry.install(path, publisher_key_id=publisher.key_id,
                                            today="2026-10-14").reference)
    first, second = references
    g.packs = registry
    pack_id = original_pack.manifest.id
    for reference in (first, second):
        result, _, _, _ = g.enact("governance-office", {"activate": reference, "at": "fixture"})
        assert result.outcome is Outcome.COMMITTED, result.detail
    result, _, _, _ = g.enact("governance-office", {"pin": original_pack.reference, "tenant": tenant})
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert registry.activation_for(tenant, pack_id).reference == original_pack.reference
    assert registry.activation_for("other-application-tenant", pack_id).reference == second
    assert registry.ledger.pinned("other-application-tenant", pack_id) is None
    result, target, authorization, output = g.enact("governance-office", {
        "rollback": pack_id, "rollback_to": first, "at": "fixture", "reason": "Synthetic governed rollback"})
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert registry.active(pack_id).reference == first
    assert registry.activation_for("other-application-tenant", pack_id).reference == first
    assert registry.activation_for(tenant, pack_id).reference == original_pack.reference
    before = target.current_state()
    assert target.commit(authorization.permit, output).outcome is Outcome.COMMITTED
    assert target.reconcile(authorization.permit).outcome is Outcome.COMMITTED
    assert target.current_state() == before
    # The application's separately composed receiver rereads the retained pin.
    assert app.stores.activation.resolve_record(tenant, pack_id).reference == original_pack.reference
    if domain == "education":
        # Begin a fresh release request after the governance operations finish.
        # Existing evidence/permits retain their original times and age bounds.
        app.context = replace(app.context, now_us=app.clock.now_us())
        education_contracts.test_two_authenticated_reviewers_release_exact_fictional_artifact(app)
    else:
        document = build_document(CONSULTATION, "Fictional record title", "case-fixture", "Invented subject", [])
        for section in document.sections:
            section.paragraphs.append(Paragraph("Invented local test text; no clinical advice.",
                                                OBSERVATION, origin=CLINICIAN))
        session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
            "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
            workspace_id=app.clinician.workspace_id, documents=[document])
        app.store.save(session)
        app.session, app.document = session, document
        clinical_contracts.test_health_finalisation_commits_exact_retained_bytes_and_export_manifest(app)
