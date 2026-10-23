"""X-13 on the retained local Health final-record path: create-only bytes and receipt recovery without re-render.

Fictional data; isolated PostgreSQL. Each case drives the ordinary finaliser steps (freeze and render once,
approve, authorize, commit) with intact guards; an interruption is the process stopping between two of those steps.
"""
from dataclasses import replace
import pathlib

import pytest

import factory.health_ui.clinical_release as clinical_release
from factory.health_ui.documents import FINALISATION_COMMITTED, FINALISATION_PENDING
from regulated_core.models import Actor
from test_clinical_finalisation import clinical, roles  # noqa: F401


def _authorized(c):
    """Freeze, render once, approve and authorize exactly as finalise does; return what the commit needs."""
    record, context, contract, content = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    certificate = c.finaliser._gate.request_approval(
        contract, context, (Actor(c.clinician.user_id, c.finaliser._workspace, frozenset({"clinician"})),))
    approved = replace(context, approval=certificate)
    decision = c.finaliser._gate.authorize_release(spec=c.finaliser._spec, contract=contract,
        out_path=c.finaliser._target(record), context=approved, artifact=content)
    assert decision.allowed, decision.reason
    return record, approved, contract, content, decision


def test_permit_deadline_is_the_attempts_recovery_deadline(clinical):  # noqa: F811
    c = clinical
    record, approved, contract, content, decision = _authorized(c)
    assert approved.not_after_us == record.started_us + c.finaliser._window_us
    assert decision.permit.permit.permit.expires_at_us <= approved.not_after_us


def test_create_only_target_refuses_to_replace_anything_present(clinical):  # noqa: F811
    c = clinical
    record, approved, contract, content, decision = _authorized(c)
    target = c.finaliser._target(record)
    occupied = pathlib.Path(target)
    occupied.parent.mkdir(parents=True, exist_ok=True)
    occupied.write_bytes(b"something already here")  # Present before the effect; create-only must not replace it.
    outcome = c.finaliser._gate.commit_release(spec=c.finaliser._spec, contract=contract, decision=decision,
        artifact=content, out_path=target, context=replace(approved, now_us=c.finaliser._now_us()))
    assert outcome.state != "committed"
    assert occupied.read_bytes() == b"something already here"


def test_interrupted_attempt_resolves_from_receipt_without_rerender(clinical, monkeypatch):  # noqa: F811
    c = clinical
    record, approved, contract, content, decision = _authorized(c)
    committed = c.finaliser._gate.commit_release(spec=c.finaliser._spec, contract=contract, decision=decision,
        artifact=content, out_path=c.finaliser._target(record), context=replace(approved, now_us=c.finaliser._now_us()))
    assert committed.state == "committed"
    # Named point "committed-before-settle": the process stopped before the document was settled.
    assert c.document.finalisation is record and record.state == FINALISATION_PENDING
    renders = []
    monkeypatch.setattr(clinical_release.export_mod, "docx_bytes",
                        lambda *args, **kwargs: renders.append(1) or b"never")
    with pytest.raises(clinical_release.FinalisationRefused, match="authorisation window"):
        c.finaliser.resolve(c.session, c.document, c.clinician)
    # Ordinary elapsed time past the attempt's authorisation window; guards unchanged.
    c.finaliser._now_us = lambda: record.started_us + c.finaliser._window_us + 1
    settled = c.finaliser.resolve(c.session, c.document, c.clinician)
    assert settled.state == FINALISATION_COMMITTED
    assert renders == []
    stored = c.store.get(c.session.session_id, c.clinician.owner_id).document(c.document.doc_id)
    assert c.finaliser.committed_bytes(stored) == content
    assert len(list(c.records.rglob("*.docx"))) == 1
