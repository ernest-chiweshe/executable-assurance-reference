"""Offline call-boundary observations, not database rollback evidence."""
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from regulated_core.governance_transaction import GovernanceTransactionCheck, run_governance_check
from regulated_core.permit import EmissionError


def test_participant_receives_owned_connection_before_final_check():
    connection = SimpleNamespace(info=SimpleNamespace(transaction_status=TransactionStatus.INTRANS))
    observed = []
    check = GovernanceTransactionCheck(
        lambda actual: observed.append(("consume", actual)),
        lambda: observed.append(("final", None)))
    run_governance_check(check, connection)
    assert observed == [("consume", connection), ("final", None)]


def test_existing_zero_argument_check_keeps_its_contract():
    observed = []
    run_governance_check(lambda: observed.append("ordinary"), object())
    run_governance_check(None, object())
    assert observed == ["ordinary"]


def test_unsupported_callback_context_refuses_without_consumption():
    observed = []
    check = GovernanceTransactionCheck(observed.append, lambda: observed.append("final"))
    with pytest.raises(EmissionError, match="effect transaction connection"):
        check()
    assert observed == []


@pytest.mark.parametrize("status", [TransactionStatus.IDLE, TransactionStatus.INERROR])
def test_nonactive_transaction_refuses_before_participants(status):
    observed = []
    check = GovernanceTransactionCheck(observed.append, lambda: observed.append("final"))
    connection = SimpleNamespace(info=SimpleNamespace(transaction_status=status))
    with pytest.raises(EmissionError, match="active effect transaction"):
        run_governance_check(check, connection)
    assert observed == []


@pytest.mark.parametrize("phase", ["consume", "final"])
def test_participant_failure_propagates_to_transaction_owner(phase):
    observed = []
    connection = SimpleNamespace(info=SimpleNamespace(transaction_status=TransactionStatus.INTRANS))

    def consume(actual):
        assert actual is connection
        observed.append("consume")
        if phase == "consume":
            raise RuntimeError("synthetic transaction failure")

    def final():
        observed.append("final")
        if phase == "final":
            raise EmissionError("synthetic final refusal")

    with pytest.raises((RuntimeError, EmissionError), match="synthetic"):
        run_governance_check(GovernanceTransactionCheck(consume, final), connection)
    assert observed == (["consume"] if phase == "consume" else ["consume", "final"])
