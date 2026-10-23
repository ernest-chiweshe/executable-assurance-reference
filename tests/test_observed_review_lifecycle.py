"""Synthetic ticket lifecycle contracts; original capture controls stay intact."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from assurance_reference.observed_review import CaptureUncertain
from regulated_core.approval_evidence import ReviewError
from test_observed_review import case as case, finish


def test_concurrent_finish_consumes_one_ticket_and_records_one_choice(case):
    c = case
    presented = c.route.present(**c.request)
    start = Barrier(2)

    def submit():
        start.wait(timeout=10)
        try:
            return finish(c, presented)
        except ReviewError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: submit(), range(2)))
    completed = [result for result in results if isinstance(result, dict)]
    refused = [result for result in results if isinstance(result, ReviewError)]
    assert len(completed) == len(refused) == 1
    assert "absent, consumed or lost" in str(refused[0])
    assert c.gate.grants == 1 and len(c.journal.rows) == 1
    assert completed[0]["observation_id"] in c.journal.rows


def test_backward_host_time_consumes_ticket_without_grant_or_observation(case):
    c = case
    presented = c.route.present(**c.request)
    c.clock.now = 9
    with pytest.raises(ReviewError, match="expired or clock differs"):
        finish(c, presented)
    c.clock.now = 11
    with pytest.raises(ReviewError, match="absent, consumed or lost"):
        finish(c, presented)
    assert c.gate.grants == 0 and not c.journal.rows


@pytest.mark.parametrize("outcome", ["refused", "escalated"])
def test_uncertain_choice_retention_can_reconcile_without_grant_or_ticket_retry(case, outcome):
    c = case
    presented = c.route.present(**c.request)
    c.journal.fail = True
    with pytest.raises(CaptureUncertain) as caught:
        finish(c, presented, outcome=outcome)
    error = caught.value
    assert error.phase == "observation-retention-unconfirmed"
    assert not error.grant_returned and error.grant_result is None
    assert error.event["outcome"] == outcome
    assert error.signature is not None
    assert c.gate.grants == 0 and not c.journal.rows
    c.journal.fail = False
    # Host reconciliation retains the same signed choice. It does not repeat
    # a grant, reopen the ticket, deliver an escalation or revoke any grant.
    identifier = c.config["observations"].record(error.event, error.signature)
    assert c.journal.rows[identifier]["payload"]["event"] == error.event
    with pytest.raises(ReviewError, match="absent, consumed or lost"):
        finish(c, presented, outcome=outcome)
    assert c.gate.grants == 0 and len(c.journal.rows) == 1


def test_expired_capacity_reclamation_does_not_extend_other_tickets(case):
    c = case
    first = c.route.present(**c.request)
    c.clock.now = 60
    second = c.route.present(**c.request)
    c.clock.now = 110
    c.route.present(**c.request)
    with pytest.raises(ReviewError, match="absent, consumed or lost"):
        finish(c, first)
    # The second presentation remains bounded by its original time (60),
    # even though capacity reclamation happened later (110).
    c.clock.now = 160
    with pytest.raises(ReviewError, match="expired or clock differs"):
        finish(c, second)
    assert c.gate.grants == 0 and not c.journal.rows
