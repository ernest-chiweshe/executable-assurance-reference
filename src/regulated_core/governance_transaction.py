"""Host-owned participation at a governance effect's database transaction.

The participant receives the existing connection; it must not commit or open
another one. The host writes the effect and receipt after this check returns.
This type alone is not evidence that any host meets that transaction contract.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .permit import EmissionError


@dataclass(frozen=True, slots=True)
class GovernanceTransactionCheck:
    """Consume in the host transaction, then recheck authority after locking."""

    consume_on: Callable[[Any], None]
    final_check: Callable[[], None]

    def __post_init__(self) -> None:
        if not callable(self.consume_on) or not callable(self.final_check):
            raise TypeError("governance transaction participants must be callable")

    def __call__(self) -> None:
        # A memory/external callback cannot silently lose the transaction.
        raise EmissionError("governance budget requires the effect transaction connection")

    def on_connection(self, connection: Any) -> None:
        from psycopg.pq import TransactionStatus

        if connection.info.transaction_status != TransactionStatus.INTRANS:
            raise EmissionError("governance budget requires an active effect transaction")
        self.consume_on(connection)
        # Budget locking can block: freshness/approval must be last.
        self.final_check()


def run_governance_check(check: Callable[[], None] | None, connection: Any) -> None:
    """Dispatch the explicit participant; retain existing zero-argument checks."""
    if isinstance(check, GovernanceTransactionCheck):
        check.on_connection(connection)
    elif check is not None:
        check()


@dataclass(frozen=True, slots=True)
class PostgresGovernanceBudget:
    """Host-owned budget binding for a concrete PostgreSQL governance adapter."""

    budget: Any

    def __post_init__(self) -> None:
        from .persistence_pg import PostgresMissionBudget

        if not isinstance(self.budget, PostgresMissionBudget):
            raise TypeError("PostgreSQL governance requires an explicit durable budget service")

    def participant(self, signed: Any, *, authority: Any, tenant_id: str,
                    target: Any, operation: str, final_check: Callable[[], None]) -> GovernanceTransactionCheck:
        # Authenticate before any transaction scope can be changed.
        authority.authenticate(signed, tenant_id=tenant_id, target=target, operation=operation)

        def consume(connection: Any) -> None:
            from psycopg.pq import TransactionStatus
            from .budget import BudgetError
            from .governance_targets import FinalCheckRefused

            previous = connection.execute("SELECT current_setting('app.tenant', true)").fetchone()[0]
            try:
                connection.execute("SELECT set_config('app.tenant', %s, true)", (signed.permit.tenant_id,))
                try:
                    self.budget.consume_permit_on(
                        connection, signed, authority=authority, tenant_id=tenant_id,
                        target=target, operation=operation)
                except BudgetError as refused:
                    raise FinalCheckRefused(str(refused)) from None
            finally:
                # A SQL error aborts the owned transaction; its owner rolls back.
                # Do not mask that error with another statement on an aborted connection.
                if connection.info.transaction_status == TransactionStatus.INTRANS:
                    connection.execute("SELECT set_config('app.tenant', %s, true)", (previous or "",))

        return GovernanceTransactionCheck(consume, final_check)

    def release(self, signed: Any, *, authority: Any, tenant_id: str,
                target: Any, operation: str) -> None:
        """Release only after the host has proved this authenticated effect did not commit.

        UNKNOWN outcomes must never call this method. Authentication deliberately
        does not require freshness: an expired permit may still need settlement.
        """
        authority.authenticate(signed, tenant_id=tenant_id, target=target, operation=operation)
        p = signed.permit
        self.budget.release(p.tenant_id, p.mission, p.budget_reservation)
