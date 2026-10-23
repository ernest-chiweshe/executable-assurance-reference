"""Intact synthetic contract for transaction-owned core-permit consumption.

A statement-recording connection checks API behavior; it is not PostgreSQL
atomicity, rollback, privilege, concurrency or governance integration evidence.
"""
from types import SimpleNamespace
from copy import deepcopy

import pytest
from psycopg.pq import TransactionStatus

from regulated_core.budget import BudgetError
from regulated_core.persistence_pg import PostgresMissionBudget
from regulated_core.target import TargetRef
from test_reference_host_budget_contract import composition


class ObservedTransaction:
    def __init__(self, tenant, *, rows=None, isolation="read committed",
                 status=TransactionStatus.INTRANS):
        self.info = SimpleNamespace(transaction_status=status)
        self.tenant, self.isolation = tenant, isolation
        self.rows = [("reserve", 1, 1, None)] if rows is None else rows
        self.statements = []
        self.inserts = []
        self.result = None

    def execute(self, statement, parameters=None):
        self.statements.append(statement)
        if statement.startswith("SELECT current_setting"):
            self.result = (self.isolation, self.tenant)
        elif statement.startswith("SELECT kind, units"):
            self.result = self.rows
        elif statement.startswith("INSERT"):
            self.inserts.append(parameters)
        elif not statement.startswith("SELECT pg_advisory_xact_lock"):
            raise AssertionError("unexpected SQL boundary")
        return self

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


def approved(tmp_path):
    engine, request, *_ = composition(tmp_path, {"limit": 1, "units": 1})
    authorization = engine.authorize_for_target(**request, nonce="core-transaction")
    assert authorization.authorized
    return authorization.permit, dict(
        authority=engine.targets, tenant_id=request["ctx"].tenant_id,
        target=request["target"].target, operation=request["target"].operation)


def test_consumption_uses_only_owned_connection_and_signed_amount(tmp_path):
    signed, binding = approved(tmp_path)
    transaction = ObservedTransaction(binding["tenant_id"])
    # A None pool guarantees this method cannot borrow another connection.
    PostgresMissionBudget(pool=None).consume_permit_on(transaction, signed, **binding)
    assert transaction.inserts == [
        (binding["tenant_id"], "synthetic:mission", "core-transaction", 1, 1)]
    assert len(transaction.statements) == 4
    assert transaction.statements[1].startswith("SELECT pg_advisory_xact_lock")


@pytest.mark.parametrize("rows", [
    [], [("release", 1, 1, None)], [("consume", 1, 1, None)],
    [("reserve", 2, 2, None)], [("reserve", 1, 0, None)],
    [("reserve", 1, 1, "a" * 64)],
    [("reserve", 1, 1, None), ("release", 1, 0, None)],
    [("reserve", 1, 1, None), ("consume", 1, 1, None)],
])
def test_nonmatching_or_settled_reservation_has_no_consumption(tmp_path, rows):
    signed, binding = approved(tmp_path)
    transaction = ObservedTransaction(binding["tenant_id"], rows=rows)
    with pytest.raises(BudgetError, match="matching live core reservation"):
        PostgresMissionBudget(pool=None).consume_permit_on(transaction, signed, **binding)
    assert not transaction.inserts


@pytest.mark.parametrize("configuration", [
    {"status": TransactionStatus.IDLE},
    {"isolation": "serializable"},
    {"tenant": "other-synthetic-tenant"},
])
def test_transaction_configuration_refuses_before_mission_lock(tmp_path, configuration):
    signed, binding = approved(tmp_path)
    options = {"tenant": binding["tenant_id"], **configuration}
    transaction = ObservedTransaction(**options)
    with pytest.raises(BudgetError):
        PostgresMissionBudget(pool=None).consume_permit_on(transaction, signed, **binding)
    assert not transaction.inserts
    assert not any("pg_advisory" in statement for statement in transaction.statements)


@pytest.mark.parametrize("override", [{"units": 2}, {"reservation_id": "other"}])
def test_callers_cannot_override_signed_budget_fields(tmp_path, override):
    signed, binding = approved(tmp_path)
    transaction = ObservedTransaction(binding["tenant_id"])
    with pytest.raises(TypeError, match="unexpected keyword"):
        PostgresMissionBudget(pool=None).consume_permit_on(
            transaction, signed, **binding, **override)
    assert transaction.statements == []


@pytest.mark.parametrize("context", ["independent-authority", "target", "operation", "tenant"])
def test_permit_authentication_refuses_untrusted_or_mismatched_context(tmp_path, context):
    signed, binding = approved(tmp_path / "issuer")
    transaction = ObservedTransaction(binding["tenant_id"])
    original_rows = deepcopy(transaction.rows)
    if context == "independent-authority":
        # Another independently generated synthetic authority does not trust
        # this issuer's key. Both fixtures use their normal signed permits.
        _, other = approved(tmp_path / "receiver")
        binding["authority"] = other["authority"]
    elif context == "target":
        binding["target"] = TargetRef("file", "different-synthetic-target")
    elif context == "operation":
        binding["operation"] = "synthetic:other-operation"
    else:
        binding["tenant_id"] = "another-synthetic-tenant"
    with pytest.raises(BudgetError):
        PostgresMissionBudget(pool=None).consume_permit_on(transaction, signed, **binding)
    assert transaction.statements == []
    assert transaction.inserts == []
    assert transaction.rows == original_rows
