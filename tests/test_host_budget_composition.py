"""Offline host-default composition contracts; no PostgreSQL application claim."""
from dataclasses import replace

import pytest

from factory.domain_host import DomainHost
from regulated_core.host_runtime import compose_regulated_host
from test_host_contract import contract as contract, compose
from test_reference_domain_host import host, bind, pack


def test_authorities_snapshot_and_validate_explicit_terms(contract):
    supplied = {"limit": 2, "units": 1}
    authorities = replace(contract.authorities, default_mission_budget=supplied)
    supplied["limit"] = 100
    assert dict(authorities.default_mission_budget) == {"limit": 2, "units": 1}
    with pytest.raises(TypeError):
        authorities.default_mission_budget["limit"] = 100
    with pytest.raises(ValueError, match="host budget"):
        replace(authorities, default_mission_budget={"limit": True, "units": 1})


@pytest.mark.parametrize("reference", [False, True])
def test_host_composition_retains_configured_default(contract, reference):
    authorities = replace(contract.authorities, default_mission_budget={"limit": 2, "units": 1})
    composed = (compose(contract, authorities=authorities) if reference else
                compose_regulated_host(contract.stores, authorities))
    assert dict(composed.factory.engine._default_mission_budget) == {"limit": 2, "units": 1}
    assert composed.factory.engine.budget is contract.stores.budget


def test_reference_domain_composition_retains_shared_default(contract):
    authorities = replace(contract.authorities, default_mission_budget={"limit": 2, "units": 1})
    shared = host(contract, authorities=authorities)
    bind(shared, contract)
    composed = shared.compose_for(pack(), None, None)
    assert dict(composed.factory.engine._default_mission_budget) == {"limit": 2, "units": 1}
    assert dict(shared._default_mission_budget) == {"limit": 2, "units": 1}


def test_base_domain_snapshots_explicit_default(contract):
    supplied = {"limit": 2, "units": 1}
    shared = DomainHost(stores=contract.stores, trust=contract.authorities.trust,
        signer=contract.keys["emission"], worm=contract.authorities.worm,
        clock=contract.authorities.clock, default_mission_budget=supplied)
    supplied["limit"] = 100
    assert dict(shared._default_mission_budget) == {"limit": 2, "units": 1}
