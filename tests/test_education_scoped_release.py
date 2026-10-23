"""Signed fictional appointments/witnesses through the real restricted PG receiver."""

from dataclasses import replace
import hashlib
import os
from threading import Event, Thread

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.canonical import canonical_bytes
from regulated_core.permit import EmissionError
from test_education_session_release import approved_request


@pytest.fixture
def scoped(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    return build_education_fixture(roles, tmp_path, scoped_authority=True)


def source_decision(app, *, confirmed=True, request_id="scripted-source-confirmation"):
    context = replace(app.context, actor_id="teacher", now_us=app.clock.now_us())
    gate = app.gates["teacher"]
    view = gate.get_source_review(spec=app.spec, contract=app.contract, context=context)
    result = gate.confirm_source_review(spec=app.spec, contract=app.contract, context=context,
        expected_material_digest=view["material_digest"], confirmed=confirmed, request_id=request_id)
    app.context = replace(app.context, now_us=app.clock.now_us())
    return result


def commit(app, context, decision):
    return app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
        context=context, decision=decision, artifact=app.body, out_path=str(app.path))


def test_scoped_education_witness_and_two_appointments_reach_real_effect(scoped):
    app = scoped
    view = app.gates["teacher"].get_source_review(spec=app.spec, contract=app.contract,
        context=replace(app.context, actor_id="teacher", now_us=app.clock.now_us()))
    assert view["can_confirm"] and not view["confirmed"]
    assert not app.path.exists()
    assert source_decision(app)["confirmed"]
    context, decision = approved_request(app)
    saved = app.gates["requester"].resolve_review_context(spec=app.spec,
        contract=app.contract, context=context).approval
    assert {r.role for r in saved.credential_receipts} == {"teacher", "head-of-department"}
    assert all(r.provider.startswith("owner-enrollment:") for r in saved.credential_receipts)
    result = commit(app, context, decision)
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    receipt = app.gates["requester"].release_receipt(spec=app.spec, out_path=str(app.path),
        tenant="school-a", nonce=context.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None and app.stores.recorder.verify_chain("school-a")
    assert app.gates["requester"].resolve_review_context(spec=app.spec,
        contract=app.contract, context=context).approval == saved  # never re-sign
    (app.path.parent / "scoped-education-release-evidence.json").write_bytes(canonical_bytes({
        "scope": "Restricted PG scoped Education receiving path; scripted fictional human decisions",
        "public_keys": app.public_keys, "contract": app.contract, "approved": saved,
        "signed_permit": decision.permit.permit, "receipt": receipt, "outcome": result,
        "chain": app.stores.recorder.entries("school-a"),
        "limits": ["No actual human judgement or owner appointment claim", "D1 and X6/X19 remain OPEN",
                   "Host passwords remain trusted; no deployed HSM or compliance WORM claim"],
    }))


@pytest.mark.parametrize("change", ["appointment", "enrollment", "source-rejection", "scope", "retained-source"])
def test_changed_authority_after_permit_refuses_before_effect(scoped, change):
    app = scoped
    source_decision(app)
    context, decision = approved_request(app)
    if change == "appointment":
        app.scoped.appoint("revoked")
    elif change == "enrollment":
        app.scoped.enroll("tobedeleted")
    elif change == "source-rejection":
        assert not source_decision(app, confirmed=False, request_id="scripted-rejection")["confirmed"]
    elif change == "scope":
        app.scoped.scopes[("school-a", "geometry")] = replace(app.scoped.scope, class_id="changed-class")
    else:
        app.scoped.retained["learner_draft"] = "Changed after approval"
    result = commit(app, context, decision)
    assert result.state == "failed", result
    assert not app.path.exists() and app.stores.recorder.verify_chain("school-a")


def test_final_effect_callback_rechecks_current_assessment(scoped):
    app = scoped
    source_decision(app)
    context, decision = approved_request(app)
    authority = app.gates["requester"]._credverify
    with authority.admit_release(contract=app.contract, context=context,
                                 authorization=decision.permit) as before_effect:
        before_effect()
        app.scoped.scopes[("school-a", "geometry")] = replace(app.scoped.scope, assessment_id="changed")
        with pytest.raises(EmissionError):
            before_effect()
    assert not app.path.exists()


@pytest.mark.parametrize("change", ["appointment", "source-rejection"])
def test_receiving_guard_serializes_signed_revocation_and_source_rejection(scoped, change):
    app = scoped
    source_decision(app)
    context, decision = approved_request(app)
    entered, finished = Event(), Event()
    failures = []
    def withdraw():
        entered.set()
        try:
            if change == "appointment":
                app.scoped.appoint("revoked")
            else:
                source_decision(app, confirmed=False, request_id="concurrent-rejection")
        except Exception as error:
            failures.append(error)
        finally:
            finished.set()
    worker = Thread(target=withdraw, daemon=True)
    authority = app.gates["requester"]._credverify
    try:
        with authority.admit_release(contract=app.contract, context=context,
                                     authorization=decision.permit) as before_effect:
            worker.start()
            assert entered.wait(2)
            assert not finished.wait(0.2)
            before_effect()
            assert not finished.is_set(), failures
    finally:
        if worker.ident is not None:
            worker.join(15)
    assert finished.is_set() and not worker.is_alive() and not failures, failures
    result = commit(app, context, decision)
    assert result.state == "failed" and not app.path.exists(), result
    assert app.stores.recorder.verify_chain("school-a")
