"""Released reservation histories admit one distinct, deterministic retry."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from regulated_core.budget import BudgetError, InMemoryMissionBudget, reservation_attempt_id


def exercise_released_attempts(budget):
    params = dict(reservation_id="request", units=1, limit=1)
    first = budget.reserve("tenant", "mission", **params)
    assert first.reservation_id == "request"
    with pytest.raises(BudgetError, match="reservation id already used"):
        budget.reserve("tenant", "mission", **dict(params, limit=10))
    budget.release("tenant", "mission", first.reservation_id)
    second = budget.reserve("tenant", "mission", **params)
    assert second.reservation_id == reservation_attempt_id("request", 1)
    assert second.reservation_id != first.reservation_id
    budget.release("tenant", "mission", first.reservation_id)
    with pytest.raises(BudgetError, match="reservation id already used"):
        budget.reserve("tenant", "mission", **dict(params, limit=10))
    with pytest.raises(BudgetError):
        budget.consume("tenant", "mission", first.reservation_id)
    budget.consume("tenant", "mission", second.reservation_id)
    assert budget.committed("tenant", "mission") == 1
    with pytest.raises(BudgetError, match="reservation id already used"):
        budget.reserve("tenant", "mission", **dict(params, limit=10))
    with pytest.raises(BudgetError):
        budget.consume("tenant", "mission", second.reservation_id)


def test_released_attempts_remain_separate_and_terminal():
    exercise_released_attempts(InMemoryMissionBudget())


def test_two_retries_of_released_request_admit_one_hold():
    budget = InMemoryMissionBudget()
    params = dict(reservation_id="request", units=1, limit=1)
    first = budget.reserve("tenant", "mission", **params)
    budget.release("tenant", "mission", first.reservation_id)
    start = Barrier(2)

    def reserve():
        start.wait(timeout=5)
        try:
            return budget.reserve("tenant", "mission", **params)
        except BudgetError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: reserve(), range(2)))
    held = [result for result in results if result is not None]
    assert len(held) == 1
    assert held[0].reservation_id == reservation_attempt_id("request", 1)
    budget.consume("tenant", "mission", held[0].reservation_id)
    assert budget.committed("tenant", "mission") == 1
