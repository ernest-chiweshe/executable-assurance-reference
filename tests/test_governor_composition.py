"""Missing or shared governor logins refuse before startup I/O."""
import pytest

from assurance_reference.host_runtime import compose_reference_stores
from test_partitioned_composition import arguments


@pytest.mark.parametrize("missing", [True, False])
@pytest.mark.parametrize("partitioned", [True])  # legacy profile refused since candidate 060
def test_absent_governor_is_an_explicit_configuration_error(missing, partitioned):
    roles, kwargs = arguments()
    if missing:
        del roles.governor
    else:
        roles.governor = None
    with pytest.raises(ValueError, match="explicit governor login"):
        compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)


@pytest.mark.parametrize("partitioned", [True])  # legacy profile refused since candidate 060
def test_governor_stays_separate_from_receiving_login(partitioned):
    roles, kwargs = arguments()
    stores = compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)
    assert stores.revocation._pool._pool is roles.governor
    assert roles.governor is not roles.receiver
    roles.governor = roles.receiver
    with pytest.raises(ValueError, match="governor login must be distinct"):
        compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)
