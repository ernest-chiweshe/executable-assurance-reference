"""Three fictional applications sharing one restricted-role authority schema.

Each application retains its explicitly scoped fixture trust directory. Public
keys must therefore stay attached to the application's evidence bundle, not be
merged by their fixture key labels. This is a database/composition qualification
fixture, not proof of a deployed common key-management or identity service.
"""

from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_education_restore import review  # noqa: E402
from qualify_product_spec_restore import prepare, ScriptedFactory  # noqa: E402
from assurance_reference.education_workflow import compose_education_workflow  # noqa: E402
from assurance_reference.local_education_fixture import build_education_fixture  # noqa: E402
from assurance_reference.local_clinical_fixture import build_clinical_fixture  # noqa: E402
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture  # noqa: E402
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_COMMITTED,  # noqa: E402
    Paragraph, Session, build_document)
from factory.health_ui.templates import CONSULTATION  # noqa: E402


def compose_and_release(roles, root):
    paths = {name: root / name for name in ("education", "health", "product_spec")}
    for path in paths.values():
        path.mkdir()
    education = build_education_fixture(roles, paths["education"], scoped_authority=True,
                                        partitioned_lifecycle=True)
    state, protocol = compose_education_workflow(education)
    state.create("geometry", {"contract": education.contract, "source_material": education.scoped.retained})
    context = replace(education.context, release_target=str(education.path),
                      retained_state=state.load("geometry")["source_material"])
    prepared = protocol.contract("geometry", tenant="school-a", context=context)
    context = review(education, prepared.for_approval(), context)
    protocol.release("geometry", str(education.path), context)
    observed = protocol.observe("geometry", str(education.path), context)
    assert observed.outcome.state == "committed" and observed.receipt and observed.receiving_record
    assert education.path.read_bytes() == prepared.prepared.content
    education.workflow_state, education.workflow = state, protocol
    education.release_context, education.release_observation = context, observed

    health = build_clinical_fixture(roles, paths["health"], partitioned_lifecycle=True)
    document = build_document(CONSULTATION, "Fictional integrated record", "case-fixture", "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented qualification text; no patient or clinical advice.",
                                           OBSERVATION, origin=CLINICIAN))
    session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=health.clinician.owner_id,
        workspace_id=health.clinician.workspace_id, documents=[document])
    health.store.save(session)
    health.session, health.document = session, document
    outcome = health.finaliser.finalise(session, document, health.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    health.release_outcome = outcome
    health.lineage_snapshot = health.lineage.get(outcome.nonce)
    assert health.lineage_snapshot["evidence"]["qualification_lineage"]["reports"][0]["report_digest"] == health.report.digest()
    health.path = next(health.records.rglob("*.docx"))
    # Settlement saves the signed document through the store; the caller's
    # pre-settlement object is not the durable finalisation record.
    health.session = health.store.get(session.session_id, session.owner_id)
    health.document = health.session.document(document.doc_id)
    assert health.document.finalisation == outcome
    assert health.finaliser.committed_bytes(health.document) == health.path.read_bytes()

    # Existing domain packs coexist in this schema. The neutral workflow must
    # not add, activate or depend on one, nor assert that the global catalog is empty.
    pack_ids = health.stores.activation.pack_ids()
    product = build_product_spec_fixture(roles, paths["product_spec"], factory=ScriptedFactory(),
                                         partitioned_lifecycle=True)
    context, _, content = prepare(product, "geometry", product.path)
    product.engine.release("geometry", str(product.path), context=context)
    observed = product.engine.observe_release("geometry", str(product.path), context=context)
    assert observed.outcome.state == "committed" and observed.receipt and observed.receiving_record
    assert product.path.read_bytes() == content
    assert product.domain_packs == () and product.stores.activation.pack_ids() == pack_ids
    product.release_context, product.release_observation = context, observed
    return SimpleNamespace(education=education, health=health, product_spec=product, roles=roles)


def project_scope_observation(matrix):
    """Read-only cross-application matrix using the actual restricted login."""
    e, h, p = matrix.education, matrix.health, matrix.product_spec
    scopes = (("education", e.identities["requester"].tenant, "education"),
              ("health", h.authenticated.tenant, h.lineage._pool.namespace),
              ("product_spec", p.tenant, "product-spec"))
    found = {}
    with matrix.roles.project_state.connection() as conn, conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        for tenant_name, tenant, _ in scopes:
            for namespace_name, _, namespace in scopes:
                conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
                conn.execute("SELECT set_config('app.project_namespace',%s,true)", (namespace,))
                count = conn.execute("SELECT count(*) FROM projectos_states").fetchone()[0]
                assert count == (1 if tenant_name == namespace_name else 0)
                found[tenant_name + "/" + namespace_name] = count
    return found
