"""Shared host constructs the guarded reader before authority exists; no I/O."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.host_runtime import compose_reference_stores, compose_reference_host
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger
from regulated_core.persistence_pg import PostgresRevocationLedger
from test_epoch_withdrawal_target import composition


class NamedNoConnections:
    def __init__(self, role):
        self.role = role
    def connection(self):
        raise AssertionError("host construction must not access a database")


def stores():
    app = composition()
    roles = SimpleNamespace(**{name: NamedNoConnections("synthetic:" + name)
        for name in ("receiver", "allocator", "recorder", "governor", "delegation_issuer")})
    configured = compose_reference_stores(roles, evidence_signer=app.keys["evidence"],
        trust=app.trust, clock=app.store.clock)
    return app, roles, configured


def test_shared_host_stores_construct_guarded_ledger_without_io():
    app, roles, configured = stores()
    assert isinstance(configured.revocation, GuardedPostgresRevocationLedger)
    assert configured.revocation.clock is app.store.clock
    assert type(configured.revocation).epoch is PostgresRevocationLedger.epoch
    assert configured.revocation._writers == {}


def test_host_rejects_plain_ledger_configuration_before_other_services_or_io():
    app, roles, configured = stores()
    plain = replace(configured, revocation=PostgresRevocationLedger(pool=roles.receiver))
    with pytest.raises(TypeError, match="guarded epoch ledger"):
        compose_reference_host(plain, SimpleNamespace(clock=app.store.clock),
            alerts=None, qualifications=None, floor_not_used_reason="synthetic construction test")
