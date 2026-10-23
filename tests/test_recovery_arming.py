"""R-2b stage 5: a process arms against the witnesses before it may act.

A head is signed with the floor-protected clock under test and acknowledged by a durable witness that keeps its own
clock. A fresh process (empty memory) restored below that head's time is held; a witness outage leaves the process
unarmed (it refuses) without holding the cluster. A restore is emulated as rows written without firing triggers.
"""
import os
import secrets

import psycopg
import pytest
from psycopg import sql

import assurance_reference.clock_floor as clock_floor
from assurance_reference.clock_floor import WITNESS_REASON, DurableClock
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
from regulated_core.signing import Ed25519Signer, TrustDirectory


def _admin(roles):
    connection = psycopg.connect(os.environ["FACTORY_TEST_DB_URL"], autocommit=True, connect_timeout=5)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
    return connection


def _forget_process_memory():
    with clock_floor._SENTINEL_LOCK:
        clock_floor._HIGHWATER.clear()


def _witnessed(roles, tmp_path):
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    head_signer, trust = Ed25519Signer("arming-head"), TrustDirectory()
    trust.register_signer(head_signer)
    keys = frozenset({head_signer.key_id})
    scope = WitnessScope("tenant", "tenant-a", "evidence")
    policy = HeadPolicy(scope, roles.domain, keys, trust)
    head = sign_head(tenant="tenant-a", tree_size=0, tree_root=EMPTY_ROOT, map_root=EMPTY[0], last_entry_hash=GENESIS,
                     previous=None, signer=head_signer, clock=clock, trust=trust, signing_keys=keys, historical_keys={})
    witness_signer, witness_trust = Ed25519Signer("arming-witness"), TrustDirectory()
    witness_trust.register_signer(witness_signer)
    witness = DurableWitness(tmp_path / "witness.db", create=True, witness_id="w", signer=witness_signer,
                             trust=witness_trust, clock=SystemClock(), policies={scope: policy})
    assert type(witness.request(WitnessRequest(secrets.token_hex(16), scope, None, head, ()))) is WitnessAck
    members = WitnessSet((("w", witness_signer.key_id),), 0, 0, 1)
    return head, members, witness_trust, witness, policy


def _arming(members, witness_trust, endpoint, policy):
    return WitnessArming(members=members, witness_trust=witness_trust, endpoints={"w": endpoint}, policies=(policy,))


def test_an_armed_fresh_process_reads_when_the_floor_covers_the_witnessed_head(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    head, members, witness_trust, witness, policy = _witnessed(roles, tmp_path)
    _forget_process_memory()
    fresh = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         arming=_arming(members, witness_trust, witness, policy))
    assert fresh.read().now_us >= head.issued_at_us


def test_a_fresh_process_restored_below_the_witnessed_head_is_held(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    head, members, witness_trust, witness, policy = _witnessed(roles, tmp_path)
    with _admin(roles) as admin:
        admin.execute("SET session_replication_role = replica")
        admin.execute("UPDATE reference_clock_floor_v1 SET highwater_us = %s WHERE domain = %s",
                      (head.issued_at_us - 1, roles.domain))
    _forget_process_memory()  # a new process on another host: no memory of the later floor
    fresh = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         arming=_arming(members, witness_trust, witness, policy))
    with pytest.raises(ClockError, match="recovery hold"):
        fresh.read()
    with _admin(roles) as admin:
        assert admin.execute("SELECT hold_reason FROM reference_clock_floor_v1 WHERE domain = %s",
                             (roles.domain,)).fetchone()[0] == WITNESS_REASON


class _Unreachable:
    def latest(self, scope, nonce):
        raise ConnectionError("witness unreachable")


def test_an_unreachable_witness_leaves_the_process_unarmed_without_holding_the_cluster(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    _, members, witness_trust, _, policy = _witnessed(roles, tmp_path)
    fresh = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         arming=_arming(members, witness_trust, _Unreachable(), policy))
    with pytest.raises(ClockError, match="unarmed"):
        fresh.read()
    with _admin(roles) as admin:
        assert admin.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                             (roles.domain,)).fetchone()[0] is None


def test_arming_refuses_heads_signed_in_another_domain(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    _, members, witness_trust, witness, policy = _witnessed(roles, tmp_path)
    other = HeadPolicy(policy.scope, "pg:1", policy.allowed_keys, policy.trust)
    fresh = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock,
                         arming=_arming(members, witness_trust, witness, other))
    with pytest.raises(ClockError, match="domain"):
        fresh.read()
