"""Guarded writer construction and refusal before any database access."""
import pytest

from assurance_reference.clock_floor import DurableClock
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused

from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger


class NoConnections:
    def connection(self):
        raise AssertionError("database access is forbidden in this construction contract")


class ConstructionClockSource:
    domain = "synthetic:epoch-construction"
    def read(self):
        raise AssertionError("clock I/O is forbidden")
    def read_on(self, connection):
        raise AssertionError("clock I/O is forbidden")
    def now_us(self):
        raise AssertionError("clock I/O is forbidden")


def ledger():
    pool = NoConnections()
    clock = DurableClock(ConstructionClockSource(), floor_pool=pool)
    return GuardedPostgresRevocationLedger(pool=pool, clock=clock, guard=GovernanceGuard())


def test_constructs_without_io_and_preserves_durable_reader_type():
    from regulated_core.persistence_pg import PostgresRevocationLedger
    store = ledger()
    assert isinstance(store, PostgresRevocationLedger)
    assert type(store).epoch is PostgresRevocationLedger.epoch
    assert store.durable is True
    with pytest.raises(AssertionError, match="database access is forbidden"):
        store.epoch("tenant")


@pytest.mark.parametrize("actor", ["ordinary-user", "governance-supervisor"])
def test_legacy_direct_revoke_refuses_even_a_supervisor_named_string(actor):
    with pytest.raises(GovernanceRefused, match="registered supervisor governance target"):
        ledger().revoke("tenant", actor=actor, reason="withdraw", now_us=0)


def test_unbound_writer_refuses_without_io():
    with pytest.raises(GovernanceRefused, match="not been composed"):
        ledger().apply(None)


def test_unbound_receipt_read_refuses_without_io():
    with pytest.raises(GovernanceRefused, match="not been composed"):
        ledger().receipt("tenant", "governance:withdraw-tenant-epoch", "nonce", "digest")


def test_arbitrary_loader_and_authority_cannot_bind_writer():
    with pytest.raises(TypeError, match="exact review loader"):
        ledger().bind_writer(loader=object(), authority=object(), log=object())


def test_owned_epoch_read_scope_clears_after_exception_and_next_read_borrows():
    from types import SimpleNamespace
    from psycopg.pq import TransactionStatus

    class SyntheticConnection:
        info = SimpleNamespace(transaction_status=TransactionStatus.INTRANS)
        def execute(self, sql, parameters=None):
            value = "tenant" if "current_setting" in sql else 7
            return SimpleNamespace(fetchone=lambda: (value,))

    store = ledger()
    with pytest.raises(RuntimeError, match="synthetic observation ended"):
        with store._epoch_read_scope(SyntheticConnection(), "tenant"):
            assert store.governance_epoch("tenant") == 7
            # Even inside an owned writer scope, application reads remain original.
            with pytest.raises(AssertionError, match="database access is forbidden"):
                store.epoch("tenant")
            raise RuntimeError("synthetic observation ended")
    assert getattr(store._epoch_reader, "active", None) is None
    # NoConnections proves the next ordinary read requests a fresh checkout,
    # rather than retaining the preceding synthetic connection.
    with pytest.raises(AssertionError, match="database access is forbidden"):
        store.epoch("tenant")
