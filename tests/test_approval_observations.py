"""Detached synthetic workflow records, session contracts and signed audit ports."""

from contextlib import contextmanager
from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from assurance_reference.alerts import AlertUnavailable
from assurance_reference.approval_observations import ApprovalObservations, PURPOSE, SCHEMA
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from regulated_core.canonical import digest_hex
from regulated_core.signing import Ed25519Signer, TrustDirectory


class SyntheticJournal:
    def __init__(self):
        self.signer = Ed25519Signer("journal")
        self.trust = TrustDirectory()
        self.trust.register_signer(self.signer)
        self.rows, self.reads = {}, []
        self.unavailable_stage = None

    def retain_signed(self, payload, signature):
        assert self.trust.verify(payload, signature)
        if payload.get("stage") == self.unavailable_stage and self.unavailable_stage is not None:
            raise OSError("synthetic audit unavailable")
        assert payload["alert_id"] not in self.rows
        self.rows[payload["alert_id"]] = json.loads(json.dumps(
            {"payload": payload, "signature": asdict(signature)}))

    def read(self, identifier, *, tenant_id):
        self.reads.append(identifier)
        value = self.rows[identifier]
        assert value["payload"]["tenant_id"] == tenant_id
        return json.loads(json.dumps(value))


class SyntheticSessions:
    def __init__(self, identity):
        self.identity, self.active, self.checks, self.refuse_at = identity, False, 0, None

    @contextmanager
    def admit(self, identity):
        if identity != self.identity:
            raise SessionRefused("synthetic session differs")
        self.active = True

        def current():
            self.checks += 1
            if not self.active or self.checks == self.refuse_at:
                raise SessionRefused("synthetic session ended")

        try:
            yield current
        finally:
            self.active = False


@pytest.fixture
def case():
    journal = SyntheticJournal()
    observer = Ed25519Signer("workflow-observer")
    journal.trust.register_signer(observer)
    identity = AuthenticatedSession("tenant-a", "quality-reader", "fixture", "session-ref", 1000)
    sessions = SyntheticSessions(identity)
    service = ApprovalObservations(tenant="tenant-a", journal=journal, sessions=sessions,
        observer_key_ids=(observer.key_id,), reader_principals=(identity.principal,))
    return SimpleNamespace(journal=journal, observer=observer, identity=identity,
                           sessions=sessions, service=service)


def event(**changes):
    return {"schema": SCHEMA, "tenant": "tenant-a", "review_id": "review-1",
            "reviewer": "reviewer-1", "decision_sha256": "a" * 64,
            "display_sha256": "b" * 64, "outcome": "approved", "clock_domain": "fixture-clock",
            "presented_us": 10, "decided_us": 30, "synthetic": True, **changes}


def retain(c, **changes):
    data = event(**changes)
    return c.service.record(data, c.observer.sign(data))


def host_service(c, identifiers, **changes):
    # Test-host configuration; these references are never accepted by report().
    cohort = {"cohort_id": "fixed-period", "clock_domain": "fixture-clock", "start_us": 0,
              "end_us": 100, "evidence_kind": "synthetic-fixture", "observation_ids": tuple(identifiers)}
    return ApprovalObservations(**{"tenant": "tenant-a", "journal": c.journal,
        "sessions": c.sessions, "observer_key_ids": (c.observer.key_id,),
        "reader_principals": (c.identity.principal,), "cohorts": (cohort,), **changes})


def report(c, identifiers, **changes):
    return host_service(c, identifiers).report(**{"authenticated": c.identity, "purpose": PURPOSE,
                                                 "cohort_id": "fixed-period", **changes})


def five_reviewers(c):
    return [retain(c, reviewer=f"reviewer-{index}") for index in range(5)]


def audits(c):
    return [v["payload"] for v in c.journal.rows.values() if "stage" in v["payload"]]


def test_signed_roundtrip_aggregate_and_audited_access_preserves_refusal(case):
    c = case
    identifiers = [retain(c), retain(c, reviewer="reviewer-2", outcome="refused", decided_us=50),
                   retain(c, reviewer="reviewer-3", outcome="escalated", decided_us=20),
                   retain(c, reviewer="reviewer-4"), retain(c, reviewer="reviewer-5", outcome="refused")]
    result = report(c, identifiers)
    assert result["outcome_counts"] == {"approved": 2, "refused": 2, "escalated": 1}
    assert result["approved_fraction"] == {"numerator": 2, "denominator": 5}
    assert result["duration_us"] == {"sum": 110, "count": 5}
    assert result["synthetic_count"] == 5 and result["automatic_consequences"] == []
    assert not result["timing_accuracy_established"]
    assert not result["institutional_protection_established"]
    assert result["all_presentations_count"] is None  # Unknown is never reported as zero.
    assert not result["abandoned_presentations_measured"]
    assert not result["population_approval_rate_established"]
    assert "conditional on completion" in result["coverage"]
    assert "abandoned, expired or lost" in result["coverage"]
    assert "reviewer-1" not in json.dumps(result) and "quality-reader" not in json.dumps(result)
    before, after = audits(c)
    assert [before["stage"], after["stage"]] == ["READ_REQUESTED", "REPORT_PREPARED"]
    assert before["request_id"] == after["request_id"] == result["request_id"]
    assert before["report_sha256"] is None and after["report_sha256"] == digest_hex(result)
    assert after["sample_sha256"] == digest_hex(sorted(identifiers))
    assert not c.sessions.active


@pytest.mark.parametrize("change", ["purpose", "tenant", "principal", "session"])
def test_unauthorized_read_has_no_observation_access(case, change):
    c = case
    identifiers = [retain(c)]
    changes = {"purpose": "personnel-discipline"} if change == "purpose" else {
        "authenticated": replace(c.identity, **{
            {"tenant": "tenant", "principal": "principal", "session": "reference"}[change]: "other"})}
    with pytest.raises(SessionRefused):
        report(c, identifiers, **changes)
    assert c.journal.reads == [] and audits(c) == []


@pytest.mark.parametrize("stage", ["READ_REQUESTED", "REPORT_PREPARED"])
def test_audit_unavailable_never_returns_a_report(case, stage):
    c = case
    identifiers = five_reviewers(c)
    c.journal.unavailable_stage = stage
    with pytest.raises(AlertUnavailable):
        report(c, identifiers)
    assert (c.journal.reads == []) == (stage == "READ_REQUESTED")
    assert not c.sessions.active


def test_session_checked_again_after_final_audit_before_disclosure(case):
    c = case
    identifiers = five_reviewers(c)
    c.sessions.refuse_at = 8
    with pytest.raises(SessionRefused):
        report(c, identifiers)
    assert audits(c)[-1]["stage"] == "REPORT_PREPARED"  # Not a claim of delivery.
    assert not c.sessions.active


def test_conflicting_final_observations_require_reconciliation(case):
    c = case
    identifiers = [retain(c), retain(c, outcome="refused")]
    with pytest.raises(ValueError, match="reconciliation"):
        report(c, identifiers)
    assert len(audits(c)) == 1


def test_missing_observation_does_not_produce_partial_success(case):
    c = case
    with pytest.raises(KeyError):
        report(c, ["approval-observation:" + "0" * 64])
    assert len(audits(c)) == 1


@pytest.mark.parametrize("change", [
    {"tenant": "other"}, {"presented_us": True}, {"decided_us": 9},
    {"synthetic": "yes"}, {"decision_sha256": "short"}, {"extra": "not-collected"},
])
def test_fixed_schema_and_scope_refused_before_retention(case, change):
    c = case
    data = event(**change)
    with pytest.raises(ValueError):
        c.service.record(data, c.observer.sign(data))
    assert c.journal.rows == {}


def test_only_host_pinned_observer_signature_is_recorded(case):
    c = case
    data = event()
    with pytest.raises(ValueError):
        c.service.record(data, c.journal.signer.sign(data))
    assert c.journal.rows == {}


def test_sample_must_be_bounded_and_distinct(case):
    c = case
    identifier = retain(c)
    for items in ([], [identifier, identifier], [identifier] * 257):
        with pytest.raises(ValueError):
            report(c, items)
    assert not c.journal.reads and not audits(c)


@pytest.mark.parametrize("distinct", [1, 4])
def test_cohort_minimum_distinct_reviewers_is_required(case, distinct):
    c = case
    identifiers = [retain(c, review_id=f"review-{i}", reviewer=f"reviewer-{i % distinct}")
                   for i in range(5)]
    with pytest.raises(ValueError, match="minimum distinct"):
        report(c, identifiers)
    assert [row["stage"] for row in audits(c)] == ["READ_REQUESTED"]


def test_reader_can_only_request_the_fixed_host_cohort(case):
    c = case
    ids = five_reviewers(c)
    route = host_service(c, ids)
    with pytest.raises(TypeError):
        route.report(authenticated=c.identity, purpose=PURPOSE, observation_ids=ids)
    with pytest.raises(ValueError, match="configured host cohort"):
        route.report(authenticated=c.identity, purpose=PURPOSE, cohort_id="not-configured")
    first = route.report(authenticated=c.identity, purpose=PURPOSE, cohort_id="fixed-period")
    second = route.report(authenticated=c.identity, purpose=PURPOSE, cohort_id="fixed-period")
    assert {k: v for k, v in first.items() if k != "request_id"} == {
        k: v for k, v in second.items() if k != "request_id"}


@pytest.mark.parametrize("change", [{"minimum_reviewers": 4}, {"minimum_reviewers": True}])
def test_host_cannot_configure_a_reviewer_floor_below_five(case, change):
    with pytest.raises(ValueError, match="floor"):
        host_service(case, five_reviewers(case), **change)


def test_host_configuration_refuses_overlapping_periods_and_reference_reuse(case):
    c = case
    ids = five_reviewers(c)
    first = {"cohort_id": "first", "clock_domain": "fixture-clock", "start_us": 0,
             "end_us": 100, "evidence_kind": "synthetic-fixture", "observation_ids": tuple(ids)}
    for second in ({**first, "cohort_id": "second"},
                   {**first, "cohort_id": "second", "start_us": 100, "end_us": 200}):
        with pytest.raises(ValueError, match="disjoint"):
            host_service(c, ids, cohorts=(first, second))


@pytest.mark.parametrize("change", [{"decided_us": 100}, {"clock_domain": "other-clock"}])
def test_observations_must_match_the_host_period_and_clock(case, change):
    c = case
    ids = [retain(c, reviewer=f"reviewer-{i}", **change) for i in range(5)]
    with pytest.raises(ValueError, match="fixed cohort period"):
        report(c, ids)


@pytest.mark.parametrize("kind,flags,allowed", [
    ("synthetic-fixture", [True] * 5, True),
    ("observed", [False] * 5, True),
    ("synthetic-fixture", [False] * 5, False),
    ("observed", [True] * 5, False),
    ("observed", [False, True, True, True, True], False),
    ("synthetic-fixture", [False, True, True, True, True], False),
])
def test_host_evidence_kind_is_homogeneous_and_explicit(case, kind, flags, allowed):
    c = case
    ids = [retain(c, reviewer=f"reviewer-{i}", synthetic=flag) for i, flag in enumerate(flags)]
    cohort = {"cohort_id": "fixed-period", "clock_domain": "fixture-clock", "start_us": 0,
              "end_us": 100, "evidence_kind": kind, "observation_ids": tuple(ids)}
    route = host_service(c, ids, cohorts=(cohort,))
    if allowed:
        result = route.report(authenticated=c.identity, purpose=PURPOSE, cohort_id="fixed-period")
        assert result["evidence_kind"] == kind
        assert result["synthetic_count"] == sum(flags)
    else:
        with pytest.raises(ValueError, match="evidence kind"):
            route.report(authenticated=c.identity, purpose=PURPOSE, cohort_id="fixed-period")
        assert [r["stage"] for r in audits(c)] == ["READ_REQUESTED"]


@pytest.mark.parametrize("counts,allowed", [([1, 1, 1, 1, 1], True),
    ([2, 2, 2, 2, 2], True), ([2, 1, 1, 1, 1], False), ([2, 2, 2, 2, 1, 1], True)])
def test_each_reviewers_record_share_obeys_host_minimum(case, counts, allowed):
    c = case
    ids = [retain(c, reviewer=f"reviewer-{i}", review_id=f"review-{j}")
           for i, count in enumerate(counts) for j in range(count)]
    if allowed:
        result = report(c, ids)
        assert result["maximum_reviewer_share"] == {"numerator": 1, "denominator": 5}
    else:
        with pytest.raises(ValueError, match="maximum record share"):
            report(c, ids)
        assert [r["stage"] for r in audits(c)] == ["READ_REQUESTED"]
