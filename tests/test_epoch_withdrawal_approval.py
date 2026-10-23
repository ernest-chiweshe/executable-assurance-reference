"""Actual local review-service composition without database or signing calls."""
import pytest

from assurance_reference.epoch_withdrawal_approval import EpochWithdrawalApprovalService
from assurance_reference.local_sessions import LocalSessions
from regulated_core.governance_roster import RosterCredentials
from regulated_core.permit import EmissionError
from test_epoch_withdrawal_target import composition


def configured():
    app = composition()
    loader = app.parameters["loader"]
    sessions = LocalSessions(reader=app.pool, issuer=app.pool, clock=app.store.clock)
    credentials = RosterCredentials(loader.roster, loader.installation, app.keys["roster"])
    return app, loader, sessions, credentials


def test_local_approval_service_pins_exact_services_without_io():
    app, loader, sessions, credentials = configured()
    service = EpochWithdrawalApprovalService(loader=loader, sessions=sessions, credentials=credentials)
    assert service.tenant_id == "tenant"
    assert service.loader is loader and service.sessions is sessions
    assert service.credentials is credentials


def test_other_session_clock_refuses_before_io():
    app, loader, sessions, credentials = configured()
    other = composition()
    sessions = LocalSessions(reader=app.pool, issuer=app.pool, clock=other.store.clock)
    with pytest.raises(TypeError, match="exact loader"):
        EpochWithdrawalApprovalService(loader=loader, sessions=sessions, credentials=credentials)


def test_other_roster_credentials_refuse_before_io():
    app, loader, sessions, credentials = configured()
    other = composition()
    different = RosterCredentials(other.parameters["loader"].roster,
                                  loader.installation, app.keys["roster"])
    with pytest.raises(TypeError, match="exact loader"):
        EpochWithdrawalApprovalService(loader=loader, sessions=sessions, credentials=different)


def test_missing_session_service_refuses_before_io():
    app, loader, sessions, credentials = configured()
    with pytest.raises(TypeError, match="exact loader"):
        EpochWithdrawalApprovalService(loader=loader, sessions=None, credentials=credentials)


def test_absent_decision_reference_refuses_before_authentication_or_io():
    app, loader, sessions, credentials = configured()
    service = EpochWithdrawalApprovalService(loader=loader, sessions=sessions, credentials=credentials)
    with pytest.raises(EmissionError, match="exact review and decision IDs"):
        service.approve(token="not submitted", review_id="review", decision_record_id="",
                        change={"tenant": "tenant", "prior_epoch": 0, "reason": "Withdraw"})
