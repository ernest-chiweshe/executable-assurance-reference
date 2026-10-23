"""R-2b: arming and the ceremony read witnessed heads from the real PostgreSQL evidence store.

The store signs real heads over real envelopes; a durable witness acknowledges the latest one. A lost tail is
emulated by removing the head row without firing triggers, as a restore would.
"""
import secrets
from dataclasses import replace

import psycopg
import pytest

from regulated_core.canonical import digest_hex
from regulated_core.clock import ClockError
from regulated_core.evidence_arming import WitnessArming, evidence_head_at
from regulated_core.evidence_runtime_pg import PostgresEvidenceProvider, backfill_batch_on
from regulated_core.evidence_witness import HeadPolicy, WitnessAck, WitnessRequest, WitnessScope, WitnessSet
from regulated_core.evidence_witness_store import DurableWitness
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_evidence_runtime_pg_010 import Pool
from test_evidence_service_pg_core import case, database, service, transaction  # noqa: F401


def _armed(store, provider, tmp_path):
    head = provider.current_head()
    scope = WitnessScope("tenant", store.tenant, "evidence")
    policy = HeadPolicy(scope, store.clock.domain, store.signing_keys, store.trust)
    signer, trust = Ed25519Signer("store-witness"), TrustDirectory()
    trust.register_signer(signer)
    witness = DurableWitness(tmp_path / "witness.db", create=True, witness_id="w", signer=signer, trust=trust,
                             clock=store.clock, policies={scope: policy})
    assert type(witness.request(WitnessRequest(secrets.token_hex(16), scope, None, head, ()))) is WitnessAck
    arming = WitnessArming(members=WitnessSet((("w", signer.key_id),), 0, 0, 1), witness_trust=trust,
                           endpoints={"w": witness}, policies=(policy,))
    return head, arming


def test_arming_matches_the_witnessed_head_in_the_store_and_holds_on_a_lost_tail(database, service, tmp_path):  # noqa: F811
    store, recorder, record, _ = service
    with transaction(database, store.tenant) as conn:
        for i in range(5):
            r = replace(record, record_id=str(i))
            recorder._append_on(conn, r, digest_hex(r))
        backfill_batch_on(conn, service=store, recorder=recorder, limit=5)
    provider = PostgresEvidenceProvider(store, Pool(database))
    head, arming = _armed(store, provider, tmp_path)
    head_at = evidence_head_at({store.tenant: provider})
    assert head_at(store.tenant, head.tree_size).digest() == head.digest()
    assert head_at("another-scope", head.tree_size) is None
    assert head_at(store.tenant, head.tree_size + 1) is None
    matched = arming.require_local_matches(store.clock.domain, head_at)
    assert matched == [(store.tenant, head.tree_size, head.digest())]
    with psycopg.connect(database, autocommit=True) as admin:  # the restore lost the witnessed head
        admin.execute("SET session_replication_role = replica")
        admin.execute("DELETE FROM regulated_evidence_heads_v1 WHERE tenant = %s AND tree_size = %s",
                      (store.tenant, head.tree_size))
    with pytest.raises(ClockError, match="missing or different locally"):
        arming.require_local_matches(store.clock.domain, head_at)
