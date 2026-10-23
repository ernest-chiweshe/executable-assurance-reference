"""Actual Health finaliser budget observation; fictional document, intact guards."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
from threading import Barrier

import pytest

from application_budget_observation import BudgetSigningObserver, assert_recorded_budget_refusal
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_roles import provision_local_roles
from factory.health_ui import export as export_mod
from factory.projectos.governed_release import MISSION_FIELD
from regulated_core.models import Actor
from factory.health_ui.clinical_release import FinalisationRefused
from factory.health_ui.documents import (CLINICIAN, OBSERVATION, FINALISATION_COMMITTED,
    SIGNED, FINALISATION_PENDING, Finalisation, Paragraph, Session, build_document)
from factory.health_ui.templates import CONSULTATION


def build_app(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    observed = BudgetSigningObserver(roles.allocator)
    app = build_clinical_fixture(roles, tmp_path, signer_factory=observed)
    document = build_document(CONSULTATION, "Fictional budget record", "budget-case",
                              "Invented subject", [])
    for section in document.sections:
        section.paragraphs.append(Paragraph("Invented local qualification text; no clinical advice.",
                                            OBSERVATION, origin=CLINICIAN))
    session = Session("budget-case", "Fictional clinician", "Fixture", "Invented subject",
        "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
        workspace_id=app.clinician.workspace_id, documents=[document])
    app.store.save(session)
    return app, observed, session, document


def test_health_finaliser_reserves_before_signing_and_consumes_on_commit(tmp_path):
    app, observed, session, document = build_app(tmp_path)
    mission = f"clinical-writing:{session.session_id}:{document.doc_id}@{document.digest()}"
    tenant = app.clinician.workspace_id
    assert app.stores.budget.committed(tenant, mission) == 0
    outcome = app.finaliser.finalise(session, document, app.clinician)
    assert outcome.state == FINALISATION_COMMITTED, outcome.detail
    assert len(observed.signed) == 1 and observed.signed[0][:2] == (tenant, mission)
    assert app.stores.budget.committed(tenant, mission) == 1
    stored_session = app.store.get(session.session_id, app.clinician.owner_id)
    stored = stored_session.document(document.doc_id)
    assert stored.status == SIGNED
    content = app.finaliser.committed_bytes(stored)
    assert content == app.artifacts.get(app.finaliser._tenant, outcome.artifact_address)
    assert len(list(app.records.rglob("*.docx"))) == 1
    # Domain finalisation refuses already signed documents before the budget gate.
    # This is explicitly NOT evidence of budget-exhaustion or concurrent-last-unit coverage.
    with pytest.raises(FinalisationRefused, match="already signed or being finalised"):
        app.finaliser.finalise(stored_session, stored, app.clinician)
    assert len(observed.signed) == 1 and app.stores.budget.committed(tenant, mission) == 1
    assert app.stores.recorder.verify_chain(tenant)


def prepare_release(app, session, document):
    """Use the finaliser's real preparation primitives and persist its pending record.

    These gate contracts stop before application settlement. The separate
    finaliser test above covers settlement and the signed-document guard.
    """
    finaliser = app.finaliser
    version = document.digest()
    signed_utc = finaliser._clock_utc()
    content = export_mod.docx_bytes(finaliser._as_signed(
        document, app.clinician.display_name, signed_utc, version))
    record = Finalisation(state=FINALISATION_PENDING, document_digest=version,
        artifact_address=app.artifacts.put(finaliser._tenant, content),
        artifact_sha256=sha256(content).hexdigest(), signer=app.clinician.display_name,
        signed_utc=signed_utc, nonce="prepared-clinical-budget", started_us=app.clock.now_us())
    document.finalisation = record
    app.store.save(session)
    assert app.store.get(session.session_id, app.clinician.owner_id).document(document.doc_id).is_frozen
    context = finaliser._context(session, document, app.clinician, record)
    contract = finaliser._contract(session, document, record, content, context, app.clinician)
    return context, contract, content


def approved_gate_request(app, prepared, nonce):
    original, contract, content = prepared
    context = replace(original, nonce=nonce, now_us=app.clock.now_us())
    certificate = app.gate.request_approval(contract, context, (
        Actor(app.clinician.user_id, app.clinician.workspace_id, frozenset({"clinician"})),))
    return dict(spec=app.spec, contract=contract, out_path=context.release_target,
                context=replace(context, approval=certificate, now_us=app.clock.now_us()),
                artifact=content)


def assert_budget_exhausted(app, decision):
    assert_recorded_budget_refusal(app, decision, "BUDGET_EXCEEDED", tenant=app.clinician.workspace_id)


def assert_gate_commit(app, observed, request, decision):
    permit = decision.permit.permit.permit
    tenant, mission = request["context"].tenant, request["contract"][MISSION_FIELD]
    assert permit.mission == mission and permit.budget_units == 1
    assert observed.signed == [(tenant, mission, permit.budget_reservation)]
    assert app.stores.budget.committed(tenant, mission) == 0
    assert not list(app.records.rglob("*.docx"))
    request = {**request, "context": replace(request["context"], now_us=app.clock.now_us())}
    result = app.gate.commit_release(**request, decision=decision)
    assert result.state == "committed", result.detail
    assert Path(request["out_path"]).read_bytes() == request["artifact"]
    assert len(list(app.records.rglob("*.docx"))) == 1
    assert app.stores.budget.committed(tenant, mission) == 1
    receipt = app.gate.reconcile_release(spec=app.spec, out_path=request["out_path"],
        context=request["context"], nonce=request["context"].nonce,
        artifact_sha256=sha256(request["artifact"]).hexdigest())
    assert receipt.state == "committed" and receipt.evidence["target_holds"] is True
    assert app.stores.recorder.verify_chain(tenant)


def test_health_gate_held_last_unit_refuses_another_reviewed_request(tmp_path):
    app, observed, session, document = build_app(tmp_path)
    prepared = prepare_release(app, session, document)
    first_request = approved_gate_request(app, prepared, "held-first")
    second_request = approved_gate_request(app, prepared, "held-second")
    first_request["context"] = replace(first_request["context"], now_us=app.clock.now_us())
    first = app.gate.authorize_release(**first_request)
    assert first.allowed, first.reason
    second_request["context"] = replace(second_request["context"], now_us=app.clock.now_us())
    second = app.gate.authorize_release(**second_request)
    assert_budget_exhausted(app, second)
    assert not app.stores.permits.used(app.clinician.workspace_id, "held-second")
    assert_gate_commit(app, observed, first_request, first)


def test_health_gate_concurrent_last_unit_gives_one_authority_and_one_commit(tmp_path):
    app, observed, session, document = build_app(tmp_path)
    prepared = prepare_release(app, session, document)
    requests = [approved_gate_request(app, prepared, f"competing-clinical-{i}") for i in range(2)]
    start = Barrier(2)

    def compete(request):
        start.wait(timeout=20)
        current = {**request, "context": replace(request["context"], now_us=app.clock.now_us())}
        return app.gate.authorize_release(**current)

    with ThreadPoolExecutor(max_workers=2) as workers:
        decisions = list(workers.map(compete, requests))
    winners = [i for i, decision in enumerate(decisions) if decision.allowed]
    assert len(winners) == 1
    winner = winners[0]
    assert_budget_exhausted(app, decisions[1 - winner])
    assert not app.stores.permits.used(app.clinician.workspace_id,
                                      requests[1 - winner]["context"].nonce)
    assert_gate_commit(app, observed, requests[winner], decisions[winner])
