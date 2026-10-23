"""Synthetic scope-restoration observations; actual lifecycle PG work remains separate."""
import pytest

from regulated_core.governance_targets import FinalCheckRefused
from regulated_core.governance_transaction import PostgresGovernanceBudget, run_governance_check
from regulated_core.persistence_pg import PostgresMissionBudget
from test_core_budget_transaction_contract import ObservedTransaction, approved


class ScopedTransaction(ObservedTransaction):
    def execute(self, statement, parameters=None):
        if statement == "SELECT current_setting('app.tenant', true)":
            self.statements.append(statement)
            self.result = (self.tenant,)
            return self
        if statement.startswith("SELECT set_config"):
            self.statements.append(statement)
            self.tenant = parameters[0]
            self.result = (self.tenant,)
            return self
        return super().execute(statement, parameters)


@pytest.mark.parametrize("prior", [None, "pin-target-tenant", "installation-tenant"])
def test_scope_is_restored_before_final_authority_check(prior, tmp_path):
    signed, binding = approved(tmp_path)
    connection = ScopedTransaction(prior)
    finals = []
    budget = PostgresGovernanceBudget(PostgresMissionBudget(pool=None))
    participant = budget.participant(
        signed, **binding, final_check=lambda: finals.append(connection.tenant))
    run_governance_check(participant, connection)
    assert connection.tenant == (prior or "")
    assert finals == [prior or ""]
    assert connection.inserts == [
        (signed.permit.tenant_id, signed.permit.mission, signed.permit.budget_reservation, 1, 1)]


def test_definite_budget_refusal_restores_scope_and_does_not_run_final_check(tmp_path):
    signed, binding = approved(tmp_path)
    connection = ScopedTransaction("pin-target", rows=[])
    finals = []
    participant = PostgresGovernanceBudget(PostgresMissionBudget(pool=None)).participant(
        signed, **binding, final_check=lambda: finals.append("final"))
    with pytest.raises(FinalCheckRefused, match="matching live core reservation"):
        run_governance_check(participant, connection)
    assert connection.tenant == "pin-target"
    assert not connection.inserts and not finals


@pytest.mark.parametrize("budget", [None, object()])
def test_durable_governance_budget_binding_is_required(budget):
    with pytest.raises(TypeError, match="explicit durable budget"):
        PostgresGovernanceBudget(budget)
