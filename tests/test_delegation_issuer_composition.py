"""Offline composition refuses an absent issuer before any database or signing."""
import pytest

from assurance_reference.host_runtime import compose_reference_stores
from test_partitioned_composition import arguments


@pytest.mark.parametrize("missing", [True, False])
@pytest.mark.parametrize("partitioned", [True])  # legacy profile refused since candidate 060
def test_missing_or_none_issuer_refuses_explicitly(missing, partitioned):
    roles, kwargs = arguments()
    if missing:
        del roles.delegation_issuer
    else:
        roles.delegation_issuer = None
    with pytest.raises(ValueError, match="explicit delegation_issuer login"):
        compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)


@pytest.mark.parametrize("partitioned", [True])  # legacy profile refused since candidate 060
def test_distinct_issuer_is_bound_without_receiver_fallback(partitioned):
    roles, kwargs = arguments()
    stores = compose_reference_stores(roles, **kwargs, partitioned_lifecycle=partitioned)
    assert stores.grants._pool._pool is roles.delegation_issuer
    assert stores.grants._pool._pool is not roles.receiver
