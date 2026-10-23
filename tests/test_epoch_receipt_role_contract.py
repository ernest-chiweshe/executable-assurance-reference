"""Exact fixed receipt duties in both supported local storage profiles."""
import pytest

from assurance_reference.role_contract import (
    CORE_TABLES, RLS_TABLES, ROLES, SCOPE_REVIEW, expected_privileges,
)


@pytest.mark.parametrize("partitioned", [False, True])
def test_epoch_receipt_is_tenant_scoped_and_only_governor_can_read_and_append(partitioned):
    table = "reference_epoch_withdrawal_receipts_v1"
    assert table in CORE_TABLES and table in RLS_TABLES and table not in SCOPE_REVIEW
    for role in ROLES:
        duties = {"SELECT", "INSERT"} if role == "governor" else set()
        assert expected_privileges(role, table, partitioned_lifecycle=partitioned) == duties
        for column in ("tenant", "epoch", "operation", "nonce", "change_digest", "proof_digest", "proof"):
            assert expected_privileges(role, table, column, partitioned_lifecycle=partitioned) == duties
