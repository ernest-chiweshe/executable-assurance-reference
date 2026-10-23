"""Offline real rendering/state checks; no approval gate or database exercised."""
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest

from assurance_reference.clinical_review import ReviewedClinicalFinalisation
from assurance_reference.clinical_review_attempts import prepare_packet
from factory.health_ui.clinical_release import FinalisationRefused
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_PENDING,
    Paragraph, Session, build_document)
from factory.health_ui.identity import ClinicianIdentity
from factory.health_ui.store import Store
from factory.health_ui.templates import CONSULTATION
from factory.ledger import FileArtifactStore
from factory.projectos.spec import RegulatedBlock, VerticalSpec


class TargetDescriptionOnly:
    def describe_target(self, *, spec, out_path, context):
        return {"kind": "filesystem", "identity": out_path, "expected_state": "absent"}


def prepared(tmp_path):
    clock = [100]
    identity = ClinicianIdentity("clinician-a", "fixture-a", "Fictional clinician", "workspace",
                                 "exact-session-reference", 10.0)
    store = Store(tmp_path / "consultations.json")
    artifacts = FileArtifactStore(tmp_path / "artifacts")
    packets = {}
    attempts = SimpleNamespace(retain=lambda packet: packets.setdefault(packet["context"]["nonce"], packet),
                               get=lambda nonce: packets.get(nonce))
    spec = VerticalSpec("health", "knowledge-backed", "health", "session_id", (),
        regulated=RegulatedBlock(policy_ref="health/clinical-writing", intended_use="clinical-writing",
                                 policy_digest="a" * 64, pack_version="fixture-only"))
    caller = ReviewedClinicalFinalisation(review_attempts=attempts, gate=TargetDescriptionOnly(),
        spec=spec, store=store, artifacts=artifacts, finalised_root=tmp_path / "finalised",
        workspace_id=identity.workspace_id, now_us=lambda: clock[0],
        clock_utc=lambda: "2026-10-16T00:00:00+00:00", nonce=lambda: "attempt-one",
        authorisation_window_us=1000)
    document = build_document(CONSULTATION, "Fictional title", "fixture-case", "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Fictional preparation test text.", OBSERVATION, origin=CLINICIAN))
    session = Session("fixture-case", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-16T00:00:00+00:00", owner_id=identity.owner_id, workspace_id=identity.workspace_id,
        documents=[document])
    store.save(session)
    record, context, contract, body = caller._prepare_finalisation(session, document, identity)
    attempts.retain(prepare_packet(context=context, contract=contract,
                                  artifact_address=record.artifact_address, artifact=body))
    return caller, store, artifacts, session, document, identity, record, body, clock


def test_preparation_freezes_and_retains_exact_render_without_authority_or_output(tmp_path):
    caller, store, artifacts, session, document, identity, record, body, clock = prepared(tmp_path)
    stored = store.get(session.session_id, identity.owner_id).document(document.doc_id)
    assert stored.finalisation.state == FINALISATION_PENDING and stored.is_frozen
    assert sha256(body).hexdigest() == record.artifact_sha256
    assert artifacts.get(caller._tenant, record.artifact_address) == body
    assert body.startswith(b"PK")
    clock[0] = 200
    contract, context = caller.review_request(session, document, identity)
    assert context.nonce == record.nonce and context.not_after_us == 1100
    assert context.approval is None
    assert contract["clinical_session"]["reference"] == identity.session_reference
    assert not (tmp_path / "finalised").exists()


def test_new_login_does_not_rebind_pending_review(tmp_path):
    caller, _, _, session, document, identity, _, _, _ = prepared(tmp_path)
    with pytest.raises(FinalisationRefused, match="session changed"):
        caller.review_request(session, document, replace(identity, session_reference="new-login"))


def test_expired_attempt_requires_receipt_recovery(tmp_path):
    caller, _, _, session, document, identity, _, _, clock = prepared(tmp_path)
    clock[0] = 1100
    with pytest.raises(FinalisationRefused, match="recovery deadline"):
        caller.review_request(session, document, identity)


def test_ordinary_finalise_implementation_is_inherited():
    from factory.health_ui.clinical_release import ClinicalFinalisation
    assert ReviewedClinicalFinalisation.finalise is ClinicalFinalisation.finalise
