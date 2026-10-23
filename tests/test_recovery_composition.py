"""R-2b in the composed reference host, not only in the library (code review B1).

The host is composed with the full rollback-recovery profile: witness arming, a maximum permit lifetime, a sentinel
file and a running heartbeat. The composed receivers enforce the lifetime bound; the composed host's own heartbeat
detects a rollback and holds the cluster; a host without the profile must name its non-use or it is refused.
"""
import os
import secrets
import time

import psycopg
import pytest
from psycopg import sql

import assurance_reference.clock_floor as clock_floor
from assurance_reference.clock_floor import DurableClock
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.clock import ClockError, SystemClock
from regulated_core.clock_pg import DbClock
from regulated_core.evidence import GENESIS
from regulated_core.evidence_arming import WitnessArming
from regulated_core.evidence_map import EMPTY
from regulated_core.evidence_service import sign_head
from regulated_core.evidence_witness import HeadPolicy, WitnessAck, WitnessRequest, WitnessScope, WitnessSet
from regulated_core.evidence_witness_store import DurableWitness
from regulated_core.merkle import EMPTY_ROOT
from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import FilesystemTargetAdapter, Outcome
from test_a19_permit_expiry_isolated_pg import _short_lived_permit

HOST = "Synthetic local fixture; generation retirement is not qualified"


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def _witness(roles, tmp_path):
    head_signer, trust = Ed25519Signer("composed-head"), TrustDirectory()
    trust.register_signer(head_signer)
    scope = WitnessScope("tenant", "synthetic-host", "evidence")
    policy = HeadPolicy(scope, roles.domain, frozenset({head_signer.key_id}), trust)
    witness_signer, witness_trust = Ed25519Signer("composed-witness"), TrustDirectory()
    witness_trust.register_signer(witness_signer)
    witness = DurableWitness(tmp_path / "witness.db", create=True, witness_id="w", signer=witness_signer,
                             trust=witness_trust, clock=SystemClock(), policies={scope: policy})
    arming = WitnessArming(members=WitnessSet((("w", witness_signer.key_id),), 0, 0, 1),
                           witness_trust=witness_trust, endpoints={"w": witness}, policies=(policy,))
    return arming, witness, head_signer, trust, scope


def _composed(roles, tmp_path, *, lifetime_us):
    arming, witness, head_signer, trust, scope = _witness(roles, tmp_path)
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path, recovery=dict(
        arming=arming, max_permit_lifetime_us=lifetime_us, sentinel_file=tmp_path / "sentinel.json",
        heartbeat_s=0.2))
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
                                  floor_not_used_reason=HOST)
    assert authorities.clock.recovery_configured
    return host, authorities.clock, arming, witness, head_signer, trust, scope


def test_the_composed_host_refuses_permits_longer_than_the_bound(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    host, clock, *_ = _composed(roles, tmp_path, lifetime_us=2_000_000)  # shorter than the fixture's 4 s permits
    try:
        # The bound is checked wherever the clock reads a permit's window: the composed issuer refuses to sign
        # it (receivers refuse it too: tests/test_permit_lifetime_bound.py).
        with pytest.raises(AssertionError, match="absolute window refused"):
            _short_lived_permit(host, tmp_path)
    finally:
        clock.stop_heartbeat()


def test_the_composed_host_issues_and_receives_within_the_bound(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    host, clock, *_ = _composed(roles, tmp_path, lifetime_us=60_000_000)
    try:
        signed, target, body = _short_lived_permit(host, tmp_path)
        receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                            PostgresPermitUseStore(pool=roles.receiver),
                                            operation_name=target.operation, budget=target.budget)
        assert receiving.commit(signed, body).outcome is Outcome.COMMITTED
    finally:
        clock.stop_heartbeat()


def test_the_composed_hosts_heartbeat_holds_the_cluster_after_a_rollback(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    host, clock, arming, witness, head_signer, trust, scope = _composed(roles, tmp_path, lifetime_us=60_000_000)
    try:
        head = sign_head(tenant="synthetic-host", tree_size=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0],
                         last_entry_hash=GENESIS, previous=None, signer=head_signer, clock=clock, trust=trust,
                         signing_keys=frozenset({head_signer.key_id}), historical_keys={})
        assert type(witness.request(WitnessRequest(secrets.token_hex(16), scope, None, head, ()))) is WitnessAck
        _short_lived_permit(host, tmp_path)  # ordinary authority work after the witnessed head
        with _admin(roles) as admin:
            admin.execute("SET session_replication_role = replica")
            admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                          (head.issued_at_us - 1, roles.domain))
        deadline = time.monotonic() + 10
        while True:
            with _admin(roles) as admin:
                hold = admin.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                                     (roles.domain,)).fetchone()[0]
            if hold is not None:
                break
            assert time.monotonic() < deadline, "the composed host's heartbeat did not hold the cluster"
            time.sleep(0.1)
        assert hold >= head.issued_at_us  # the server-computed hold is never before the lost timeline's head
        with pytest.raises(ClockError, match="recovery hold"):
            clock.read()
        # A fresh process armed against the same witness is refused too.
        with clock_floor._SENTINEL_LOCK:
            clock_floor._HIGHWATER.clear()
        fresh = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock, arming=arming)
        with pytest.raises(ClockError, match="recovery hold"):
            fresh.read()
    finally:
        clock.stop_heartbeat()


def test_composition_refuses_a_clock_without_recovery_or_a_stated_non_use(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    authorities.clock.recovery_not_used_reason = None  # neither the profile nor a stated non-use
    with pytest.raises(ValueError, match="rollback recovery"):
        compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
                               floor_not_used_reason=HOST)
