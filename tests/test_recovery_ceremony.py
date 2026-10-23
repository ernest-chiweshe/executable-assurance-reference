"""R-2b stage 6: the resumption ceremony clears a recovery hold only under every stated condition.

A real head is signed with the clock under test and acknowledged by a durable witness on its own clock; the local
log here is that head. A rollback is emulated as rows written without firing triggers, then detected.
"""
import os
import time

import psycopg
import pytest
from psycopg import sql

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.recovery_ceremony import (EPOCH_JUMP, CeremonyRefused, ResumptionAuthority,
                                                   provision_recovery_login, sign_ceremony)
from regulated_core.clock import ClockError
from regulated_core.clock_pg import DbClock
from regulated_core.evidence_arming import WitnessArming
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_recovery_arming import _witnessed

LIFETIME_US = 3_000_000


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def make_held(tmp_path, seed=None):
    """A held cluster ready for a ceremony; ``seed(admin, roles)`` writes rows before the hold, as a backup holds them."""
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    if seed is not None:
        with _admin(roles) as admin:
            seed(admin, roles)
    head, members, witness_trust, witness, policy = _witnessed(roles, tmp_path)
    arming = WitnessArming(members=members, witness_trust=witness_trust, endpoints={"w": witness}, policies=(policy,))
    with roles.receiver.connection() as connection, connection.transaction():
        connection.execute("SELECT set_config('app.tenant', 'tenant-a', true)")
        connection.execute("INSERT INTO regulated_permit_uses_v1 (tenant, nonce) VALUES ('tenant-a', 'n1')")
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         max_permit_lifetime_us=LIFETIME_US)
    early = clock.read()
    clock.read()
    with _admin(roles) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (early.now_us - 1, roles.domain))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
    owner = _owner(roles)
    recovery = provision_recovery_login(owner, os.environ["FACTORY_TEST_DB_URL"])
    ceremony_signer, trust = Ed25519Signer("resume-ceremony"), TrustDirectory()
    trust.register_signer(ceremony_signer)
    head_at = lambda scope, size: head if (scope, size) == ("tenant-a", head.tree_size) else None  # noqa: E731
    authority = ResumptionAuthority(recovery_pool=recovery, clock=clock, trust=trust,
                                    ceremony_key_id=ceremony_signer.key_id, arming=arming, head_at=head_at)
    with _admin(roles) as admin:
        hold_at = admin.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                                (roles.domain,)).fetchone()[0]
    witnessed = arming.require_local_matches(roles.domain, head_at)
    return (roles, clock, authority, ceremony_signer, arming, hold_at, witnessed, head_at), (recovery, owner)


@pytest.fixture
def held(tmp_path):
    state, pools = make_held(tmp_path)
    yield state
    for pool in pools:
        pool.close()


def _owner(roles):
    from assurance_reference.local_roles import LocalPool
    return LocalPool(os.environ["FACTORY_TEST_DB_URL"], roles.schema, "ceremony-owner")


def _ceremony(signer, roles, hold_at, witnessed):
    return sign_ceremony(signer, domain=roles.domain, hold_at_us=hold_at, witnessed=witnessed,
                         issued_at_us=hold_at)


def _wait_out_quarantine(hold_at, clock):
    while clock._read_for_ceremony().now_us < hold_at + LIFETIME_US:
        time.sleep(0.2)


def test_a_valid_ceremony_after_quarantine_resumes_with_every_reset(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    summary = authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    assert "tenant-a" in summary["tenants"]
    assert clock.read().now_us > hold_at  # the hold is cleared
    with _admin(roles) as admin:
        epoch = admin.execute("SELECT MAX(epoch) FROM regulated_revocation_events_v1 WHERE tenant = 'tenant-a'"
                              ).fetchone()[0]
        assert epoch == EPOCH_JUMP  # no earlier revocation: 0 + 2^32; every outstanding permit is refused
        assert admin.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                             (roles.domain,)).fetchone()[0] is None


def test_the_ceremony_waits_out_the_quarantine(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    assert clock._read_for_ceremony().now_us < hold_at + LIFETIME_US, "setup outlasted the 3 s quarantine window"
    with pytest.raises(CeremonyRefused, match="quarantine"):
        authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_a_forged_ceremony_is_refused(held):
    roles, clock, authority, _, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    with pytest.raises(CeremonyRefused, match="signature"):
        authority.resume(_ceremony(Ed25519Signer("not-the-ceremony-key"), roles, hold_at, witnessed))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_a_ceremony_for_another_hold_is_refused(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    with pytest.raises(CeremonyRefused, match="current hold"):
        authority.resume(_ceremony(signer, roles, hold_at - 1, witnessed))


def test_a_lost_witnessed_tail_stays_on_hold(held):
    roles, clock, authority, signer, arming, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    authority._head_at = lambda scope, size: None  # the restored log lacks the witnessed head
    with pytest.raises(ClockError, match="missing or different locally"):
        authority.resume(_ceremony(signer, roles, hold_at, witnessed))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_a_used_ceremony_cannot_be_replayed(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    ceremony = _ceremony(signer, roles, hold_at, witnessed)
    authority.resume(ceremony)
    with pytest.raises(CeremonyRefused):
        authority.resume(ceremony)


def test_no_lifetime_bound_means_no_resumption(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    clock.max_permit_lifetime_us = None
    with pytest.raises(CeremonyRefused, match="maximum permit lifetime"):
        authority.resume(_ceremony(signer, roles, hold_at, witnessed))


def test_only_the_recovery_login_can_clear_the_hold(held):
    roles, *_ = held
    # The clock login holds UPDATE on the floor value only; the hold columns are not its to write at all.
    with roles.clock.connection() as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connection.transaction():
                connection.execute("UPDATE reference_clock_floor_v1 SET hold_at_us = NULL, hold_reason = NULL")
    # The owner can write the columns, but the guard refuses to clear a hold for anyone but the recovery login.
    with _admin(roles) as admin:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="cannot be changed"):
            admin.execute("UPDATE reference_clock_floor_v1 SET hold_at_us = NULL, hold_reason = NULL")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="never deleted"):
            admin.execute("DELETE FROM reference_clock_floor_v1")


def test_a_ceremony_altered_after_signing_is_refused(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    ceremony = _ceremony(signer, roles, hold_at, witnessed)
    from assurance_reference.recovery_ceremony import SignedCeremony
    altered = SignedCeremony({**ceremony.body, "issued_at_us": ceremony.body["issued_at_us"] + 1}, ceremony.signature)
    with pytest.raises(CeremonyRefused, match="signature"):
        authority.resume(altered)
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()


def test_a_ceremony_naming_other_witnessed_checkpoints_is_refused(held):
    roles, clock, authority, signer, _, hold_at, witnessed, _ = held
    _wait_out_quarantine(hold_at, clock)
    other = [("tenant-a", 99, "0" * 64)]
    with pytest.raises(CeremonyRefused, match="witnessed checkpoints differ"):
        authority.resume(_ceremony(signer, roles, hold_at, other))
    with pytest.raises(ClockError, match="recovery hold"):
        clock.read()
