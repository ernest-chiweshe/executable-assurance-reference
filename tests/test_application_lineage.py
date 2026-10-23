"""Current composed releases and four views; run only in the owned serial PG window."""

import copy
import json
from hashlib import sha256

from securesystemslib.dsse import Envelope

from assurance_reference.projections import project
from factory.health_ui.documents import FINALISATION_COMMITTED
from regulated_core.canonical import canonical_bytes
from regulated_core.signing import Ed25519Signer
from test_clinical_finalisation import clinical, roles  # noqa: F401
from test_education_scoped_release import scoped, source_decision, commit  # noqa: F401
from test_education_session_release import approved_request
from test_external_attestation import external_key
from test_product_spec_authority import product, approve  # noqa: F401

# ruff: noqa: F811


def four_views(app, tenant, evidence, output):
    lineage = evidence["qualification_lineage"]
    assert lineage["reports"][0]["report_digest"] == app.report.digest()
    assert lineage["reports"][0]["dataset_reference"]["digest"] == app.report.dataset_digest
    record_hash = lineage["decision_record_hash"]
    entries = app.stores.recorder.entries(tenant)
    assert app.stores.recorder.verify_chain(tenant)
    assert any(entry.record_hash == record_hash for entry in entries)
    assert evidence["authorization_decision"]["record_hash"] == record_hash
    source = json.loads(canonical_bytes({"entries": entries, "public_keys": app.public_keys,
        "release_evidence": evidence, "scope": "Current fictional local release; no deployment qualification"}))
    before = copy.deepcopy(source)
    signer = Ed25519Signer("fixture:application-projection")
    views = project(source, signer, complete=True, system_name="Local fictional reference", provider="Test operator")
    parsed = Envelope.from_dict(copy.deepcopy(views["attestation"]))
    key = external_key(signer)
    assert parsed.verify([key], threshold=1) == {signer.key_id: key}
    predicate = json.loads(parsed.payload)["predicate"]
    assert predicate["source_bundle"] == before == source
    assert predicate["source_bundle"]["release_evidence"]["qualification_lineage"] == lineage
    assert predicate["regulator"] == views["regulator"]
    assert predicate["audit"] == views["audit"]
    # Trace from the released decision through the audit pointers into the signed source.
    audit = views["audit"]
    assert any(item["record_hash"] == record_hash for item in audit["trace"])
    references = {
        "/release_evidence/qualification_lineage/decision_record_hash": record_hash,
        "/release_evidence/qualification_lineage/reports/0/report_digest": app.report.digest(),
        "/release_evidence/qualification_lineage/reports/0/dataset_reference/id": app.report.dataset_id,
        "/release_evidence/qualification_lineage/reports/0/dataset_reference/version": app.report.dataset_version,
        "/release_evidence/qualification_lineage/reports/0/dataset_reference/digest": app.report.dataset_digest,
    }
    for pointer, expected in references.items():
        matches = [item for item in audit["field_inventory"] if item["source_pointer"] == pointer]
        assert len(matches) == 1
        assert matches[0]["value_sha256"] == sha256(canonical_bytes(expected)).hexdigest()
        assert matches[0]["retained_in"] == "attestation.predicate.source_bundle"
        resolved = predicate["source_bundle"]
        for token in pointer.lstrip("/").split("/"):
            resolved = resolved[int(token)] if isinstance(resolved, list) else resolved[token]
        assert resolved == expected
    assert views["regulator"]["application_evidence_complete"] is False
    output.write_bytes(canonical_bytes({"source": source, "views": views,
                                       "report_public_key": signer.public_key_bytes.hex()}))


def test_scoped_education_retains_qualification_lineage_and_four_views(scoped, tmp_path):
    source_decision(scoped)
    context, decision = approved_request(scoped)
    result = commit(scoped, context, decision)
    assert result.state == "committed", result
    assert scoped.path.read_bytes() == scoped.body
    four_views(scoped, "school-a", decision.evidence, tmp_path / "education-lineage.json")


def test_product_spec_project_retains_qualification_lineage_and_four_views(product, tmp_path):
    context = approve(product)
    product.engine.release("inventory", str(product.path), context=context)
    assert product.path.exists() and product.domain_packs == ()
    saved = product.state.load("inventory")
    assert saved["release_outcomes"][-1]["state"] == "committed"
    four_views(product, product.tenant, saved["emissions"][-1]["evidence"], tmp_path / "product-lineage.json")


def test_health_retains_qualification_lineage_and_four_views(clinical, tmp_path):
    # Observe the actual returned answer; all authorization/receiving guards run.
    # Read back the durable snapshot as well as observing the returned answer.
    captured = []
    original = clinical.gate.authorize_release

    def observe(**request):
        answer = original(**request)
        captured.append(answer)
        return answer

    clinical.gate.authorize_release = observe
    outcome = clinical.finaliser.finalise(clinical.session, clinical.document, clinical.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    assert len(captured) == 1 and captured[0].allowed
    retained = clinical.lineage.get(outcome.nonce)
    assert retained["evidence"] == captured[0].evidence
    four_views(clinical, clinical.clinician.workspace_id, retained["evidence"],
               tmp_path / "health-lineage.json")
