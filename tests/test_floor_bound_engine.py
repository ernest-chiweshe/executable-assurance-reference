"""Detached target-port contracts; no live floor, database or filesystem effect."""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from assurance_reference.floor_bound_engine import FloorBoundReferenceEngine
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.target import FilesystemTargetAdapter, Outcome, ReleaseAdmissionUnavailable, TargetResult
from test_generation_floor_admission import fixture as admission_fixture


class SyntheticEngine(FloorBoundReferenceEngine):
    def __init__(self, floor, connection):
        self._generation_floor, self.connection = floor, connection

    def _record_outcome(self, authorization, result, *, reconciled):
        assert self.connection.info.transaction_status == TransactionStatus.IDLE
        self.connection.events.append("record")
        return result


@dataclass
class SyntheticTarget(FilesystemTargetAdapter):
    connection: object = None

    def commit(self, signed, output):
        self.connection.events.append("target-enter")
        assert self.connection.info.transaction_status == TransactionStatus.INTRANS
        try:
            self.effect_check()
        except (EmissionError, ReleaseAdmissionUnavailable):
            return TargetResult(Outcome.FAILED, "synthetic final-check refusal")
        self.connection.events.append("synthetic-effect")
        return TargetResult(Outcome.COMMITTED, "synthetic effect only")


def fixture():
    floor, connection, verifier = admission_fixture()

    def current(signed, *, at_effect):
        assert at_effect
        connection.events.append("permit-margin")

    target = SyntheticTarget(Path("unused-synthetic-target"), "synthetic-tenant",
        SimpleNamespace(current=current), object(), connection=connection,
        effect_check=lambda: connection.events.append("existing-admission"))
    authorization = SimpleNamespace(authorized=True, permit=object())
    return SyntheticEngine(floor, connection), target, authorization, connection, verifier


def test_engine_preserves_existing_check_and_rechecks_margin_under_floor_lock():
    engine, target, authorization, connection, _ = fixture()
    assert engine.commit(authorization, b"synthetic", target).outcome is Outcome.COMMITTED
    assert connection.events == ["checkout", "begin", "floor", "target-enter",
        "floor", "existing-admission", "permit-margin", "synthetic-effect", "end", "return", "record"]


def test_initial_refusal_never_calls_target():
    engine, target, authorization, connection, verifier = fixture()
    verifier.refused = True
    with pytest.raises(CredentialError):
        engine.commit(authorization, b"synthetic", target)
    assert "target-enter" not in connection.events
    assert "synthetic-effect" not in connection.events


def test_existing_admission_refusal_is_preserved():
    engine, target, authorization, connection, _ = fixture()

    def refused():
        raise EmissionError("synthetic preexisting admission refuses")

    from dataclasses import replace
    result = engine.commit(authorization, b"synthetic", replace(target, effect_check=refused))
    assert result.outcome is Outcome.FAILED
    assert connection.events.count("floor") == 2
    assert "synthetic-effect" not in connection.events


def test_transaction_close_failure_records_unknown_even_after_synthetic_effect():
    engine, target, authorization, connection, _ = fixture()
    connection.close_error = True
    result = engine.commit(authorization, b"synthetic", target)
    assert result.outcome is Outcome.UNKNOWN
    assert "reconcile" in result.detail
    assert "synthetic-effect" in connection.events
    assert connection.events[-1] == "record"


def test_unsupported_target_and_missing_authority_refuse_before_floor_checkout():
    engine, target, authorization, connection, _ = fixture()
    with pytest.raises(EmissionError, match="filesystem target"):
        engine.commit(authorization, b"synthetic", object())
    with pytest.raises(EmissionError, match="no target permit"):
        engine.commit(SimpleNamespace(authorized=False, permit=None), b"synthetic", target)
    assert not connection.events
