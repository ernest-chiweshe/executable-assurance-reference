"""Synthetic host-route contracts; no production state or vulnerability workflow."""

from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from types import SimpleNamespace

import pytest

from assurance_reference.approval_observations import ApprovalObservations
from assurance_reference.observed_review import CaptureUncertain, ObservedMaterialReview
from assurance_reference.review_material import MaterialReview, material_contract
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from regulated_core.approval_evidence import ReviewError
from regulated_core.clock import ClockReading
from regulated_core.signing import Ed25519Signer, TrustDirectory


class FixtureClock:
    domain = "capture-fixture"
    now = 10

    def read(self):
        return ClockReading(self.domain, self.now)


class FixtureSessions:
    active = True

    @contextmanager
    def admit(self, identity):
        def current():
            if not self.active:
                raise SessionRefused("fixture session withdrawn")
        current()
        yield current
        current()


class FixtureJournal:
    def __init__(self, signer, trust):
        self.signer, self.trust = signer, trust
        self.rows, self.fail = {}, False
        self.after_retain = lambda: None

    def retain_signed(self, payload, signature):
        assert self.trust.verify(payload, signature)
        if self.fail:
            raise OSError("synthetic retention unavailable")
        assert payload["alert_id"] not in self.rows
        self.rows[payload["alert_id"]] = {"payload": payload, "signature": asdict(signature)}
        self.after_retain()

    def read(self, identifier, *, tenant_id):
        return self.rows[identifier]


class FixtureGate:
    def __init__(self):
        self.grants = 0
        self.raise_after_grant = False
        self.before_return = lambda: None
        self.confirm = True

    def get_review(self, **request):
        return {"review_id": "review-one", "decision_record_hash": "a" * 64,
            "project_id": "fictional", "action_id": "release", "nonce": "one",
            "requester_id": "author", "expires_at_us": 1000, "reason": "Fixture review",
            "required_role_groups": [["teacher"]], "minimum_approvers": 1,
            "status": "awaiting-review", "approver_ids": []}

    def grant_review(self, **request):
        self.grants += 1
        if self.raise_after_grant:
            raise OSError("synthetic uncertain grant return")
        self.before_return()
        return {**self.get_review(**request),
                "approver_ids": [request["context"].actor_id] if self.confirm else []}


@pytest.fixture
def case():
    observer, journal_signer = Ed25519Signer("fixture-observer"), Ed25519Signer("fixture-journal")
    trust = TrustDirectory()
    trust.register_signer(observer)
    trust.register_signer(journal_signer)
    journal = FixtureJournal(journal_signer, trust)
    clock, sessions, gate = FixtureClock(), FixtureSessions(), FixtureGate()
    identity = AuthenticatedSession("tenant-one", "reviewer", "fixture", "session-one", 1000)
    observations = ApprovalObservations(tenant=identity.tenant, journal=journal, sessions=sessions,
        observer_key_ids=(observer.key_id,), reader_principals=("quality",))
    config = dict(observations=observations, signer=observer, clock=clock, sessions=sessions,
                  authenticated=identity, synthetic=True, maximum_pending=2, ticket_lifetime_us=100)
    route = ObservedMaterialReview(MaterialReview(gate), **config)
    body = b"Fictional artifact\n"
    contract = material_contract({"prepared_release": {"artifact_sha256": sha256(body).hexdigest()},
        "release_target": {"kind": "file", "identity": "fixture", "expected_state": "old"}},
        prior_artifact=None, reversibility="Fixture", exposure="Fixture only",
        checker_findings=["Synthetic"], uncertainty="No real human observation")
    request = dict(spec=None, contract=contract, context=SimpleNamespace(
        tenant=identity.tenant, actor_id=identity.principal, actor_roles=(), is_producer=False),
        review_id="review-one", artifact=body)
    return SimpleNamespace(route=route, config=config, gate=gate, clock=clock, sessions=sessions,
                           journal=journal, request=request)


def finish(c, presented, **changes):
    return c.route.finish(**c.request, **{"presentation_ticket": presented["presentation_ticket"],
        "displayed_sha256": presented["view"]["display_sha256"],
        "outcome": "approved", "role": "teacher", **changes})


def test_capture_uses_host_time_identity_and_original_grant(case):
    c = case
    presented = c.route.present(**c.request)
    assert not c.journal.rows and c.gate.grants == 0
    c.clock.now = 30
    result = finish(c, presented)
    event = c.journal.rows[result["observation_id"]]["payload"]["event"]
    assert event == {"schema": "reference/approval-workflow-observation/v1", "tenant": "tenant-one",
        "reviewer": "reviewer", "review_id": "review-one", "decision_sha256": "a" * 64,
        "display_sha256": presented["view"]["display_sha256"], "outcome": "approved",
        "clock_domain": "capture-fixture", "presented_us": 10, "decided_us": 30, "synthetic": True}
    assert c.gate.grants == 1 and result["grant"]["approver_ids"] == ["reviewer"]
    with pytest.raises(ReviewError, match="consumed"):
        finish(c, presented)
    assert c.gate.grants == 1


@pytest.mark.parametrize("outcome", ["refused", "escalated"])
def test_human_choice_records_without_grant_or_release(case, outcome):
    c = case
    result = finish(c, c.route.present(**c.request), outcome=outcome)
    assert result["grant"] is None and c.gate.grants == 0
    assert c.journal.rows[result["observation_id"]]["payload"]["event"]["outcome"] == outcome


@pytest.mark.parametrize("change", ["ack", "material", "identity", "expired", "clock", "revoked"])
def test_invalid_capture_preconditions_stop_before_grant_and_retention(case, change):
    c = case
    presented = c.route.present(**c.request)
    options = {}
    if change == "ack":
        options["displayed_sha256"] = "b" * 64
    elif change == "material":
        c.request["contract"]["approval_material_v1"]["uncertainty"] = "Changed declaration"
    elif change == "identity":
        c.request["context"].actor_id = "different"
    elif change == "expired":
        c.clock.now = 110
    elif change == "clock":
        c.clock.domain = "other-domain"
    else:
        c.sessions.active = False
    with pytest.raises((ReviewError, SessionRefused)):
        finish(c, presented, **options)
    assert c.gate.grants == 0 and not c.journal.rows


def test_failed_grant_is_unknown_and_never_fabricates_refusal_or_retries(case):
    c = case
    presented = c.route.present(**c.request)
    c.gate.raise_after_grant = True
    with pytest.raises(CaptureUncertain) as caught:
        finish(c, presented)
    assert caught.value.phase == "grant-outcome-unknown" and not caught.value.grant_returned
    assert caught.value.event is None and caught.value.signature is None
    assert c.gate.grants == 1 and not c.journal.rows
    with pytest.raises(ReviewError):
        finish(c, presented)
    assert c.gate.grants == 1


def test_incomplete_grant_return_is_not_recorded_as_approved(case):
    c = case
    c.gate.confirm = False
    with pytest.raises(CaptureUncertain) as caught:
        finish(c, c.route.present(**c.request))
    assert caught.value.grant_returned and caught.value.phase == "grant-outcome-unknown"
    assert caught.value.event is None and not c.journal.rows


def test_journal_failure_after_grant_preserves_exact_reconciliation_data(case):
    c = case
    presented = c.route.present(**c.request)
    c.journal.fail = True
    with pytest.raises(CaptureUncertain) as caught:
        finish(c, presented)
    error = caught.value
    assert error.phase == "observation-retention-unconfirmed" and error.grant_returned
    assert error.grant_result["approver_ids"] == ["reviewer"]
    c.journal.fail = False
    # Explicit host reconciliation retains the exact observation; it does not
    # repeat the original grant. Uncertain duplicate appends need separate reads.
    c.config["observations"].record(error.event, error.signature)
    assert c.gate.grants == 1 and len(c.journal.rows) == 1


def test_post_retention_revocation_reports_uncertainty_without_undo_claim(case):
    c = case
    c.journal.after_retain = lambda: setattr(c.sessions, "active", False)
    with pytest.raises(CaptureUncertain) as caught:
        finish(c, c.route.present(**c.request))
    assert caught.value.phase == "post-retention-session-unconfirmed"
    assert c.gate.grants == 1 and len(c.journal.rows) == 1


def test_capacity_is_bounded_expired_tickets_reclaimed_and_restart_loses_tickets(case):
    c = case
    first = c.route.present(**c.request)
    c.route.present(**c.request)
    with pytest.raises(ReviewError, match="capacity"):
        c.route.present(**c.request)
    c.clock.now = 110
    c.route.present(**c.request)
    with pytest.raises(ReviewError, match="absent"):
        finish(c, first)
    fresh = c.route.present(**c.request)
    c.route = ObservedMaterialReview(MaterialReview(c.gate), **c.config)
    with pytest.raises(ReviewError, match="absent"):
        finish(c, fresh)
    assert c.gate.grants == 0 and not c.journal.rows


def test_untrusted_observer_configuration_refuses_before_any_grant(case):
    c = case
    c.route = ObservedMaterialReview(MaterialReview(c.gate),
        **{**c.config, "signer": Ed25519Signer("unknown-observer")})
    with pytest.raises(ValueError, match="observer signature"):
        c.route.present(**c.request)
    assert c.gate.grants == 0 and not c.journal.rows


def test_capture_preserves_underlying_screening_or_assignment_refusal(case):
    class EscalatingRoute(MaterialReview):
        def grant(self, **request):
            raise ReviewError("fixture host route requires escalation")

    c = case
    c.route = ObservedMaterialReview(EscalatingRoute(c.gate), **c.config)
    with pytest.raises(CaptureUncertain):
        finish(c, c.route.present(**c.request))
    assert c.gate.grants == 0 and not c.journal.rows
