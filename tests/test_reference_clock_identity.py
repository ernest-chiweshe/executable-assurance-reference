"""X-21 startup clock identity contracts against the actual reference engine."""

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.engine import ReferenceEngine
from regulated_core.clock_pg import DbClock
from test_host_contract import NoIOPool, compose, contract as contract


def construct_with_clock(config, engine, clock):
    return ReferenceEngine(
        alerts=config.alerts,
        registry=engine._registry,
        recorder=engine._recorder,
        verification_trust=engine._vtrust,
        approvals=engine._approvals,
        emission=engine._emission,
        preflight=engine._preflight,
        targets=engine.targets,
        budget=engine._budget,
        revocation=engine._revocation,
        clock=clock,
    )


def test_same_clock_instance_constructs_without_io(contract):
    engine = compose(contract).factory.engine
    sibling = construct_with_clock(contract, engine, engine.targets.clock)
    assert sibling.targets is engine.targets
    assert sibling.targets.clock is contract.authorities.clock


@pytest.mark.parametrize("domain", ["pg:123", "pg:456"])
def test_distinct_engine_clock_refuses_before_io(contract, domain):
    engine = compose(contract).factory.engine
    other_clock = DurableClock(
        DbClock(NoIOPool("other-receiver"), domain),
        floor_pool=NoIOPool("other-clock-floor"),
    )
    assert other_clock is not engine.targets.clock
    with pytest.raises(ValueError, match="engine and target require the same configured clock"):
        construct_with_clock(contract, engine, other_clock)
