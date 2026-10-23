"""Reference factory composition contracts, without database execution."""
from types import SimpleNamespace

import pytest

from assurance_reference.governance_targets import (
    pack_activation_target, pack_pin_target, pack_rollback_target, pack_revocation_target, roster_target,
)
from factory.packs.lifecycle import ActivationLedger
from factory.packs.lifecycle_pg import PostgresActivationLedger
from factory.packs.registry import PackRegistry
from regulated_core.governance_targets import GovernanceLog
from regulated_core.persistence_pg import PostgresMissionBudget, PostgresRosterStore
from roster_verifier_fixture import verified_store
from regulated_core.signing import TrustDirectory


def options():
    return dict(tenant_id="fixture", authority=None, uses=None, log=GovernanceLog())


@pytest.mark.parametrize("factory,args", [
    (pack_activation_target, ("course@1#digest",)),
    (pack_pin_target, ("course@1#digest", "fixture")),
    (pack_rollback_target, ("course@1", "course@1#digest")),
    (pack_revocation_target, ("course@1#digest",)),
])
def test_pack_factories_require_supported_host_and_durable_budget(factory, args):
    with pytest.raises(TypeError, match="PostgreSQL lifecycle"):
        factory(SimpleNamespace(ledger=ActivationLedger()), *args,
                budget=PostgresMissionBudget(pool=None), **options())
    registry = PackRegistry(trust=TrustDirectory(), activation=PostgresActivationLedger("", pool=None))
    with pytest.raises(TypeError, match="explicit durable budget"):
        factory(registry, *args, budget=None, **options())
    with pytest.raises(ValueError, match="host-owned"):
        factory(registry, *args, budget=PostgresMissionBudget(pool=None), budget_transaction=False, **options())
    target = factory(registry, *args, budget=PostgresMissionBudget(pool=None), **options())
    assert target._budget_binding is not None
    assert callable(target._transact) and callable(target._receipt)


def test_roster_factory_requires_supported_host_and_durable_budget():
    with pytest.raises(TypeError, match="PostgreSQL roster"):
        roster_target(object(), "fixture", budget=PostgresMissionBudget(pool=None), **options())
    store, _ = verified_store()
    with pytest.raises(TypeError, match="explicit durable budget"):
        roster_target(store, "fixture", budget=None, **options())
    with pytest.raises(TypeError, match="persisted authority verification"):
        roster_target(store, "fixture", budget=PostgresMissionBudget(pool=None), **options())
    store, _ = verified_store()
    configured = {**options(), "authority": store._proof_verifier.authority}
    target = roster_target(store, "fixture", budget=PostgresMissionBudget(pool=None), **configured)
    assert target._budget_binding is not None
    assert callable(target._transact) and callable(target._receipt)


@pytest.mark.parametrize("key", ["budget_binding", "budget_transaction", "transact", "receipt"])
def test_roster_factory_keeps_transaction_wiring_host_owned(key):
    store, _ = verified_store()
    with pytest.raises(ValueError, match="host-owned"):
        roster_target(store, "fixture", budget=PostgresMissionBudget(pool=None),
                      **{key: None}, **options())


def test_postgres_roster_store_requires_signed_authority_verifier_at_construction():
    with pytest.raises(TypeError, match="explicit signed authority verifier"):
        PostgresRosterStore(pool=None)
