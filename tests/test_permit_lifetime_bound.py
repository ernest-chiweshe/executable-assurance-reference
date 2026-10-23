"""R-2b stage 2: receivers refuse permits that live longer than their clock's configured maximum.

The bound is enforced at receive time, so it binds permits issued before it was configured; the recovery
quarantine relies on it (once the bound has elapsed after a hold, every permit issued before the hold has expired).
"""
import os

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock import ClockError, ClockReading, SystemClock, require_bounded_lifetime
from regulated_core.clock_pg import DbClock
from regulated_core.permit import ClockedEmissionPermit, EmissionAuthority, EmissionError
from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import FilesystemTargetAdapter, Outcome
from test_a19_permit_expiry_isolated_pg import _short_lived_permit


class _BoundedClock(SystemClock):
    domain = "test:bounded"

    def __init__(self, now_us, bound):
        self.now, self.max_permit_lifetime_us = now_us, bound

    def read(self):
        return ClockReading(self.domain, self.now)


def _emission_permit(issued, expires):
    return ClockedEmissionPermit("tenant", "decision", "0" * 64, "", "assertion", "action", "0" * 64, expires,
                                 "nonce", "test:bounded", issued)


def test_bound_helper_refuses_only_longer_lifetimes():
    clock = _BoundedClock(0, 1_000)
    require_bounded_lifetime(clock, issued_at_us=10, expires_at_us=1_010)
    with pytest.raises(ClockError, match="lifetime"):
        require_bounded_lifetime(clock, issued_at_us=10, expires_at_us=1_011)
    require_bounded_lifetime(object(), issued_at_us=0, expires_at_us=10**15)  # no bound configured: none imposed


def test_emission_receiver_refuses_a_permit_longer_than_its_bound():
    signer = Ed25519Signer("emission-bound")
    trust = TrustDirectory()
    trust.register_signer(signer)
    authority = EmissionAuthority(signer, trust, uses=None, clock=_BoundedClock(500, 1_000))
    authority._require_live(_emission_permit(100, 1_100))  # exactly the bound: accepted
    with pytest.raises(EmissionError):
        authority._require_live(_emission_permit(100, 1_101))


def test_durable_clock_requires_a_positive_bound():
    for bad in (0, -1, 1.5, "60"):
        with pytest.raises(ValueError, match="positive"):
            DurableClock(DbClock(None, "pg:1"), floor_pool=None, max_permit_lifetime_us=bad)


def test_filesystem_receiver_refuses_a_permit_issued_before_a_shorter_bound(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    signed, target, body = _short_lived_permit(host, tmp_path)  # a 4 s permit, issued with no bound configured
    permit = signed.permit
    receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                        PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation,
                                        budget=target.budget)
    clock = receiving.authority.clock
    assert isinstance(clock, DurableClock)
    clock.max_permit_lifetime_us = (permit.expires_at_us - permit.issued_at_us) - 1  # the receiver now bounds it
    result = receiving.commit(signed, body)
    assert result.outcome is Outcome.FAILED, result
    assert not receiving.path.exists() and not stores.permits.used(permit.tenant_id, permit.nonce)
    clock.max_permit_lifetime_us = permit.expires_at_us - permit.issued_at_us  # control: exactly the bound
    assert receiving.commit(signed, body).outcome is Outcome.COMMITTED
