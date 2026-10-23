"""Offline composition contracts; no construction-time database or signing."""
from types import SimpleNamespace

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.host_runtime import compose_reference_stores
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
from factory.packs.lifecycle_pg import PostgresActivationLedger
from regulated_core.clock_pg import DbClock
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_host_contract import NoIOPool


def arguments():
    roles = SimpleNamespace(**{name: NoIOPool(name) for name in ("receiver", "allocator", "recorder", "clock")})
    return roles, {"evidence_signer": Ed25519Signer("fixture:partitioned-composition"),
                   "trust": TrustDirectory(),
                   "clock": DurableClock(DbClock(roles.receiver, "pg:123"), floor_pool=roles.clock)}


@pytest.mark.parametrize("partitioned", [False, True])
def test_explicit_storage_selection_preserves_receiver_session_and_guard_without_io(partitioned):
    roles, kwargs = arguments()
    stores = compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)
    assert type(stores.activation) is (PartitionedActivationLedger if partitioned else PostgresActivationLedger)
    assert stores.activation._pool is stores.pool
    assert stores.pool._pool is roles.receiver
    assert isinstance(stores.activation.governance_guard, GovernanceGuard)
    with pytest.raises(GovernanceRefused):
        stores.activation.unpin("synthetic-school", "education")


@pytest.mark.parametrize("selection", ["true", 1, None])
def test_storage_selection_is_not_inferred_from_truthy_strings_or_environment(selection):
    roles, kwargs = arguments()
    with pytest.raises(TypeError, match="explicit boolean"):
        compose_reference_stores(roles, **kwargs, partitioned_lifecycle=selection)


@pytest.mark.parametrize("duration", [0, -1, True, "600000000", 600_000_001])
def test_restore_fixture_cannot_select_unbounded_or_implicit_evidence_validity(duration, tmp_path):
    from assurance_reference.local_fixture_host import configuration
    from assurance_reference.scoped_education_fixture import compose_scoped_fixture
    with pytest.raises(ValueError, match="at most ten minutes"):
        configuration(None, tmp_path, fixture_validity_us=duration)
    with pytest.raises(ValueError, match="at most ten minutes"):
        compose_scoped_fixture(None, authorities=None, keys=None, registry=None, pack=None,
            alerts=None, qualifications=None, signer_factory=None, fixture_validity_us=duration)
