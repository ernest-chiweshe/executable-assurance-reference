"""X-13 refusals on the actual local Health final-record path; fictional data, isolated PostgreSQL.

Each refusal leaves no released record. A frozen pending attempt is settled only by
its owner, only after its authorisation window, and never by finalising again.
"""
from dataclasses import replace

import pytest

from factory.health_ui.clinical_release import FinalisationRefused
from factory.health_ui.documents import FINALISATION_PENDING
from test_clinical_finalisation import clinical, roles  # noqa: F401


def _other(clinician):
    return replace(clinician, user_id="fictional-other-clinician", username="other-clinician",
                   display_name="Other fictional clinician")


def _pending(c):
    record, *_ = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    assert record.state == FINALISATION_PENDING and c.document.finalisation is record
    return record


def test_non_owner_clinician_cannot_finalise(clinical):  # noqa: F811
    c = clinical
    with pytest.raises(FinalisationRefused, match="own clinician"):
        c.finaliser.finalise(c.session, c.document, _other(c.clinician))
    assert c.document.finalisation is None
    assert not list(c.records.rglob("*.docx"))


def test_pending_attempt_cannot_be_finalised_again(clinical):  # noqa: F811
    c = clinical
    _pending(c)
    with pytest.raises(FinalisationRefused, match="already signed or being finalised"):
        c.finaliser.finalise(c.session, c.document, c.clinician)
    assert not list(c.records.rglob("*.docx"))


def test_pending_attempt_is_not_resolved_inside_its_window(clinical):  # noqa: F811
    c = clinical
    record = _pending(c)
    with pytest.raises(FinalisationRefused, match="authorisation window"):
        c.finaliser.resolve(c.session, c.document, c.clinician)
    assert c.document.finalisation is record and record.state == FINALISATION_PENDING
    assert not list(c.records.rglob("*.docx"))


def test_non_owner_cannot_resolve_after_the_window(clinical):  # noqa: F811
    c = clinical
    record = _pending(c)
    # Ordinary elapsed time past the attempt's authorisation window; guards unchanged.
    c.finaliser._now_us = lambda: record.started_us + c.finaliser._window_us + 1
    with pytest.raises(FinalisationRefused, match="own clinician can resolve"):
        c.finaliser.resolve(c.session, c.document, _other(c.clinician))
    assert c.document.finalisation is record and record.state == FINALISATION_PENDING
    assert not list(c.records.rglob("*.docx"))
