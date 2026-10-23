"""Queued guarded local applications on the explicitly migrated lifecycle.

Original signed bootstrap, session admission, reviews and receiving guards run.
No direct guarded-registry mutation or external provider is used.
"""
import os

import psycopg
import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from factory.health_ui.documents import CLINICIAN, OBSERVATION, Paragraph, Session, build_document
from factory.health_ui.templates import CONSULTATION
from factory.projectos.regulated import EmissionContext
from factory.verticals.product_spec.export import render_product_spec_markdown
import test_clinical_finalisation as health_contracts
import test_education_session_release as education_contracts
from test_product_spec_authority import ScriptedFactory, approve


@pytest.fixture
def partitioned_roles():
    return provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])


def assert_partitioned(app):
    assert isinstance(app.stores.activation, PartitionedActivationLedger)
    assert app.stores.activation._pool is app.stores.pool
    with app.stores.pool.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM pack_lifecycle")
        assert conn.execute("SELECT count(*) FROM reference_pack_tenants_v1").fetchone() == (0,)


@pytest.mark.parametrize("case", ["two-reviewers", "revoked-requester"])
def test_partitioned_education_uses_original_review_and_receiving_contracts(partitioned_roles, tmp_path, case):
    app = build_education_fixture(partitioned_roles, tmp_path, partitioned_lifecycle=True)
    assert_partitioned(app)
    if case == "two-reviewers":
        education_contracts.test_two_authenticated_reviewers_release_exact_fictional_artifact(app)
    else:
        education_contracts.test_revoked_requester_session_refuses_previously_approved_release(app)
    assert len(app.stores.activation.pack_ids()) == 1


@pytest.mark.parametrize("case", ["committed", "revoked-before-receiving"])
def test_partitioned_health_preserves_final_record_and_receiving_refusal(partitioned_roles, tmp_path, case):
    app = build_clinical_fixture(partitioned_roles, tmp_path, partitioned_lifecycle=True)
    assert_partitioned(app)
    document = build_document(CONSULTATION, "Fictional record title", "case-fixture", "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented local qualification text; no patient or clinical advice.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
        workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    app.session, app.document = session, document
    if case == "committed":
        health_contracts.test_health_finalisation_commits_exact_retained_bytes_and_export_manifest(app)
    else:
        health_contracts.test_session_revoked_after_approval_is_refused_at_receiving_boundary(app)
    assert app.stores.activation.pack_ids() == (app.pack.manifest.id,)


def test_partitioned_host_keeps_neutral_product_spec_on_authority_path_without_pack(partitioned_roles, tmp_path):
    app = build_product_spec_fixture(partitioned_roles, tmp_path, factory=ScriptedFactory(),
                                    partitioned_lifecycle=True)
    assert_partitioned(app)
    app.engine.new("inventory", title="Fictional inventory", idea="A local workshop fixture")
    for stage in ("problem", "solution", "scope", "spec"):
        app.engine.run_stage("inventory", stage, tenant=app.tenant)
    app.context = EmissionContext(tenant=app.tenant, actor_id="requester", project_id="inventory",
        vertical_name=app.spec.name, action_id="release", nonce="fixture-release",
        now_us=app.clock.now_us(), not_after_us=app.clock.now_us() + 30_000_000, release_target=str(app.path))
    _, assembled = app.engine.assemble("inventory", tenant=app.tenant, context=app.context)
    assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
    context = approve(app)
    expected = render_product_spec_markdown(app.engine.contract("inventory"))
    app.engine.release("inventory", str(app.path), context=context)
    assert app.path.read_text(encoding="utf-8") == expected
    assert app.state.load("inventory")["release_outcomes"][-1]["state"] == "committed"
    assert app.stores.recorder.verify_chain(app.tenant)
    assert app.domain_packs == () and app.stores.activation.pack_ids() == ()
    modified = app.path.stat().st_mtime_ns
    app.engine.release("inventory", str(app.path), context=context)
    assert app.path.stat().st_mtime_ns == modified
