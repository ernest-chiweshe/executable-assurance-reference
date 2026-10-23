"""Synthetic connection ownership; no database or weakened authority guards."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from regulated_core.governance_targets import GovernanceLog
from regulated_core.permit import InMemoryPermitUseStore
from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresPermitUseStore


class SyntheticPool:
    def __init__(self, name, events):
        self.name, self.events = name, events
        self.held, self.claimed = False, False

    @contextmanager
    def connection(self):
        assert not self.held, "a second checkout from this bounded synthetic pool"
        self.held = True
        self.events.append((self.name, "borrow"))
        try:
            yield SyntheticConnection(self)
        finally:
            self.held = False
            self.events.append((self.name, "return"))


class SyntheticConnection:
    def __init__(self, pool):
        self.pool = pool

    @contextmanager
    def transaction(self):
        yield self

    def execute(self, sql, parameters=None):
        if "SELECT 1 FROM regulated_permit_uses_v1" in sql:
            self.pool.events.append((self.pool.name, "claim"))
            value = (1,) if self.pool.claimed else None
        elif "pg_advisory_unlock" in sql:
            value = (True,)
        else:
            value = None
        return SimpleNamespace(fetchone=lambda: value)

    def commit(self):
        pass

    def close(self):
        self.pool.events.append((self.pool.name, "close"))


def test_distinct_claim_connection_is_reserved_first_but_read_inside_governing():
    events = []
    receiver, governor = SyntheticPool("receiver", events), SyntheticPool("governor", events)
    uses, log = PostgresPermitUseStore(pool=receiver), PostgresGovernanceLog(pool=governor)
    with log.observing_permit_claims(uses):
        assert events == [("receiver", "borrow")]
        with log.governing("synthetic-scope"):
            # A fresh observation occurs now; entry never cached a claim value.
            receiver.claimed = True
            assert log.permit_claimed(uses, "synthetic-tenant", "signed-nonce")
            assert events[:3] == [("receiver", "borrow"), ("governor", "borrow"), ("receiver", "claim")]
    assert events[-2:] == [("governor", "return"), ("receiver", "return")]
    assert getattr(log._claim_observation, "active", None) is None


def test_shared_pool_keeps_one_checkout():
    events = []
    pool = SyntheticPool("shared", events)
    uses, log = PostgresPermitUseStore(pool=pool), PostgresGovernanceLog(pool=pool)
    with log.observing_permit_claims(uses):
        assert not events
        with log.governing("synthetic-scope"):
            assert not log.permit_claimed(uses, "synthetic-tenant", "signed-nonce")
    assert events == [("shared", "borrow"), ("shared", "claim"), ("shared", "return")]


def test_claim_binding_clears_after_exception_and_a_new_scope_can_observe():
    events = []
    receiver, governor = SyntheticPool("receiver", events), SyntheticPool("governor", events)
    uses, log = PostgresPermitUseStore(pool=receiver), PostgresGovernanceLog(pool=governor)
    with pytest.raises(RuntimeError, match="synthetic caller stopped"):
        with log.observing_permit_claims(uses), log.governing("synthetic-scope"):
            assert not log.permit_claimed(uses, "synthetic-tenant", "signed-nonce")
            raise RuntimeError("synthetic caller stopped")
    assert not receiver.held and not governor.held
    assert getattr(log._claim_observation, "active", None) is None
    with log.observing_permit_claims(uses), log.governing("synthetic-scope"):
        receiver.claimed = True
        assert log.permit_claimed(uses, "synthetic-tenant", "signed-nonce")


def test_observation_rejects_another_store_and_nested_observation():
    events = []
    receiver, governor = SyntheticPool("receiver", events), SyntheticPool("governor", events)
    uses, log = PostgresPermitUseStore(pool=receiver), PostgresGovernanceLog(pool=governor)
    with log.observing_permit_claims(uses):
        with pytest.raises(RuntimeError, match="nested"):
            with log.observing_permit_claims(uses):
                pytest.fail("nested context entered")
        with log.governing("synthetic-scope"):
            with pytest.raises(RuntimeError, match="configured permit-use store"):
                log.permit_claimed(PostgresPermitUseStore(pool=receiver), "synthetic-tenant", "nonce")
    assert not any(action == "claim" for _, action in events)


def test_observation_must_precede_governor_checkout():
    events = []
    receiver, governor = SyntheticPool("receiver", events), SyntheticPool("governor", events)
    uses, log = PostgresPermitUseStore(pool=receiver), PostgresGovernanceLog(pool=governor)
    with log.governing("synthetic-scope"):
        with pytest.raises(RuntimeError, match="precede"):
            with log.observing_permit_claims(uses):
                pytest.fail("late resource context entered")
    assert ("receiver", "borrow") not in events


def test_memory_log_keeps_fresh_existing_claim_semantics():
    log, uses = GovernanceLog(), InMemoryPermitUseStore()
    with log.observing_permit_claims(uses), log.governing("synthetic-scope"):
        assert not log.permit_claimed(uses, "synthetic-tenant", "nonce")
        uses.consume("synthetic-tenant", "nonce")
        assert log.permit_claimed(uses, "synthetic-tenant", "nonce")
