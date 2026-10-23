"""Observation must preserve returned data, exceptions and resource cleanup."""
from contextlib import contextmanager
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from history_work import PoolObservation, WorkCounts


def test_observation_does_not_swallow_failure_and_releases_pool():
    events = []
    failure = RuntimeError("synthetic connection failure")

    class Connection:
        def execute(self, query, parameters):
            assert parameters == ("private-value",)
            raise failure

    class Pool:
        @contextmanager
        def connection(self):
            events.append("enter")
            try:
                yield Connection()
            finally:
                events.append("exit")

    counts = WorkCounts()
    with counts.measuring(), pytest.raises(RuntimeError) as caught:
        with PoolObservation(Pool(), counts).connection() as connection:
            connection.execute("SELECT secret", ("private-value",))
    assert caught.value is failure
    assert events == ["enter", "exit"]
    assert counts.snapshot() == {"pool_checkouts": 1, "sql_statements": 1}
    assert "private-value" not in repr(counts.snapshot())


def test_mixed_fetches_count_only_consumed_rows_and_keep_identity():
    rows = [(object(),), (object(),), (object(),)]

    class Cursor:
        def __init__(self):
            self.remaining = iter(rows)

        def fetchone(self):
            return next(self.remaining, None)

        def fetchall(self):
            return list(self.remaining)

    class Connection:
        def execute(self, query):
            return Cursor()

    class Pool:
        @contextmanager
        def connection(self):
            yield Connection()

    counts = WorkCounts()
    with counts.measuring():
        with PoolObservation(Pool(), counts).connection() as connection:
            cursor = connection.execute("SELECT envelope FROM regulated_decision_evidence_v1")
            assert cursor.fetchone() is rows[0]
            assert cursor.fetchall() == rows[1:]
            assert cursor.fetchone() is None
    assert counts.snapshot()["rows_returned"] == 3
    assert counts.snapshot()["rows_returned_referencing:regulated_decision_evidence_v1"] == 3


def test_method_hook_always_calls_original_and_restores_it_on_failure():
    class Verifier:
        def verify(self, value):
            raise ValueError(value)

    verifier = Verifier()
    counts = WorkCounts()
    original = verifier.verify
    with counts.measuring(), counts.observe(verifier, "verify", "signature_checks"):
        with pytest.raises(ValueError, match="invalid"):
            verifier.verify("invalid")
    assert verifier.verify == original
    assert counts.snapshot() == {"signature_checks": 1}
    counts.add("outside_measurement")
    assert counts.snapshot() == {"signature_checks": 1}
