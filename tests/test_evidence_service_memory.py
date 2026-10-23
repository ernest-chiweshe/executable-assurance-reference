"""Typed lookup completeness and bounded staging; no caller/permit integration."""
from dataclasses import replace
import math

import pytest

from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence import GENESIS, ClockedDecisionEnvelope
from regulated_core.evidence_map import EMPTY, MapProof
from regulated_core.evidence_service import (
    EvidenceError, KeySummary, MemoryEvidenceService, envelope_keys,
    lookup_key, occurrence_bytes, verify_lookup,
)
from regulated_core.models import Annotation
from test_evidence_service_formats import case


@pytest.fixture
def memory(case):
    clock, signer, _, trust, keys, _, _, original = case
    store = MemoryEvidenceService(tenant="tenant", signer=signer, clock=clock, trust=trust,
                                  signing_keys=keys, historical_head_keys={},
                                  envelope_keys_allowed=keys, envelope_domains=frozenset({clock.domain}))
    envs, heads = [], []
    def append(i, *, record_id="duplicate", variant=0, outcome=None):
        decision = original[0].record.decision
        if outcome is not None:
            decision = replace(decision, annotations=(Annotation("outcome-of-decision", outcome),) * 2)
        record = replace(original[0].record, record_id=record_id, assertion_id=f"variant-{variant}", decision=decision)
        env = ClockedDecisionEnvelope(record, digest_hex(record),
                                      GENESIS if not envs else envs[-1].chain_hash(), i,
                                      original[0].signature, clock.domain)
        env = replace(env, signature=signer.sign(env.signed_body()))
        head = store.append(env)
        envs.append(env); heads.append(head)
        return env, head
    args = dict(tenant="tenant", clock_domain=clock.domain, trust=trust, allowed_head_keys=keys,
                allowed_envelope_keys=keys, allowed_envelope_domains=frozenset({clock.domain}))
    return store, append, envs, heads, args


def answer(memory, kind, key, selection, *, at=-1, ordinal=None):
    store, _, _, heads, args = memory
    proof = store.lookup(head=heads[at], key_type=kind, key=key, selection=selection, ordinal=ordinal)
    return verify_lookup(proof, expected_head=heads[at], key_type=kind, key=key,
                         selection=selection, ordinal=ordinal, **args)


def test_summary_and_occurrence_wire_format_are_exact():
    value = KeySummary(2, 3, 8, "a" * 64)
    assert KeySummary.decode(value.bytes(), 9) == value
    assert occurrence_bytes(3) == b'{"schema":"regulated/evidence-key-occurrence/v1","seq":3}'
    for bad in (replace(value, count=True), replace(value, count=0), replace(value, count=7),
                replace(value, count=1), replace(value, first_seq=9), replace(value, key_root="A" * 64)):
        with pytest.raises(EvidenceError):
            KeySummary.decode(bad.bytes(), 9)
    with pytest.raises(EvidenceError):
        KeySummary.decode(b" " + value.bytes(), 9)


def test_duplicate_id_latest_matching_hash_and_historical_roots(memory):
    _, append, envs, _, _ = memory
    append(0, variant=0); append(1, variant=1); append(2, variant=0); append(3, variant=1)
    assert answer(memory, "record_id", "duplicate", "count").summary.count == 4
    assert answer(memory, "record_id", "duplicate", "first").envelope == envs[0]
    assert answer(memory, "record_id", "duplicate", "latest").envelope == envs[3]
    assert answer(memory, "record_id_hash", ("duplicate", envs[0].record_hash), "latest").envelope == envs[2]
    assert answer(memory, "record_hash", envs[0].record_hash, "latest").envelope == envs[2]
    assert answer(memory, "record_id", "duplicate", "latest", at=0).envelope == envs[0]
    assert answer(memory, "record_id", "duplicate", "count", at=1).summary.count == 2
    assert answer(memory, "record_id", "missing", "absent").summary is None
    assert answer(memory, "record_id", "duplicate", "absent").summary.count == 4
    assert answer(memory, "record_id", "duplicate", "ordinal", ordinal=2).envelope == envs[2]
    assert answer(memory, "record_id", "duplicate", "ordinal", ordinal=4).envelope is None


def test_outcome_keys_deduplicate_annotations_and_preserve_order(memory):
    _, append, envs, _, _ = memory
    append(0, outcome="a" * 64); append(1, outcome="b" * 64); append(2, outcome="a" * 64)
    assert answer(memory, "outcome_of", "a" * 64, "count").summary.count == 2
    assert answer(memory, "outcome_of", "a" * 64, "first").envelope == envs[0]
    assert answer(memory, "outcome_of", "a" * 64, "latest").envelope == envs[2]
    assert answer(memory, "outcome_of", "c" * 64, "first").envelope is None


def test_proofs_cannot_substitute_question_head_or_occurrence(memory):
    store, append, _, heads, args = memory
    append(0); append(1)
    proof = store.lookup(head=heads[-1], key_type="record_id", key="duplicate", selection="latest")
    call = dict(expected_head=heads[-1], key_type="record_id", key="duplicate", selection="latest", **args)
    for bad in (replace(proof, head=heads[0]), replace(proof, occurrence=None),
                replace(proof, map_proof=replace(proof.map_proof, value=None)),
                replace(proof, occurrence=replace(proof.occurrence, ordinal=0)),
                replace(proof, occurrence=replace(proof.occurrence, seq=0)),
                replace(proof, occurrence=replace(proof.occurrence, key_path=())),
                replace(proof, occurrence=replace(proof.occurrence, envelope=b"{}"))):
        with pytest.raises(EvidenceError):
            verify_lookup(bad, **call)
    for changed in ({"key": "different"}, {"tenant": "other"}, {"selection": "first"},
                    {"allowed_envelope_keys": frozenset({"other"})},
                    {"allowed_envelope_domains": frozenset({"other"})}):
        with pytest.raises(EvidenceError):
            verify_lookup(proof, **(call | changed))


def test_valid_map_summary_does_not_allow_wrong_key_envelope(memory):
    # Sign a test-only inconsistent head with a genuine occurrence/envelope tree:
    # inclusion alone is insufficient; the returned envelope must match the key.
    from regulated_core.evidence_map import MemorySparseMap
    store, append, _, heads, args = memory
    append(0)
    proof = store.lookup(head=heads[0], key_type="record_id", key="duplicate", selection="first")
    wrong_map = MemorySparseMap()
    digest = lookup_key("tenant", "record_id", "wrong")
    wrong_map.update(digest, proof.map_proof.value)
    head = replace(heads[0], map_root=wrong_map.root.hex())
    head = replace(head, signature=store.signer.sign(head.body()))
    bad = replace(proof, head=head, map_proof=wrong_map.prove(digest))
    with pytest.raises(EvidenceError, match="qualification"):
        verify_lookup(bad, expected_head=head, key_type="record_id", key="wrong", selection="first", **args)


def snapshot(store):
    return (store.head, len(store._tree._nodes), len(store._map._nodes),
            len(store._envelopes), len(store._occurrences),
            tuple((k, v.frontier, len(v._nodes)) for k, v in store._key_trees.items()))


def test_signer_failure_discards_only_staged_nodes_and_retry_succeeds(memory, monkeypatch):
    store, append, _, heads, _ = memory
    append(0)
    before = snapshot(store)
    original = store.signer.sign
    def fail(_):
        raise RuntimeError("injected evidence-head signer outage")
    # Make the next envelope before the signer outage, then fail only the head.
    env = replace(memory[2][0], seq=1, prev_hash=memory[2][0].chain_hash())
    env = replace(env, signature=original(env.signed_body()))
    monkeypatch.setattr(store.signer, "sign", fail)
    with pytest.raises(RuntimeError, match="outage"):
        store.append(env)
    assert snapshot(store) == before
    monkeypatch.setattr(store.signer, "sign", original)
    assert store.append(env).tree_size == 2


def test_wrong_scope_chain_signature_and_corrupt_state_fail_without_mutation(memory):
    store, append, envs, _, _ = memory
    append(0)
    before = snapshot(store)
    for bad in (envs[0], replace(envs[0], seq=1), replace(envs[0], seq=True),
                replace(envs[0], record=replace(envs[0].record, tenant_id="other"))):
        with pytest.raises(EvidenceError):
            store.append(bad)
        assert snapshot(store) == before
    store._map.root = EMPTY[0]
    with pytest.raises(EvidenceError, match="signed head"):
        store.append(envs[0])


def test_staging_and_single_answer_never_enumerate_history(memory):
    store, append, envs, heads, _ = memory
    # Verify actual node work as duplicate-key history grows, not result count.
    for i in range(513):
        append(i)
        work = store.last_append_work
        assert work["keys"] == 4
        assert work["map_nodes"] <= 4 * 257
        assert work["tree_nodes"] <= 1 + math.floor(math.log2(i + 1))
        assert work["key_nodes"] <= 4 * (1 + math.floor(math.log2(i + 1)))
    class NoScan(dict):
        def __iter__(self): raise AssertionError("history enumeration")
        def keys(self): raise AssertionError("history enumeration")
        def values(self): raise AssertionError("history enumeration")
        def items(self): raise AssertionError("history enumeration")
        def copy(self): raise AssertionError("history copy")
    store._tree._nodes = NoScan(store._tree._nodes)
    store._map._nodes = NoScan(store._map._nodes)
    store._envelopes = NoScan(store._envelopes)
    store._occurrences = NoScan(store._occurrences)
    store._heads = NoScan(store._heads)
    for tree in store._key_trees.values():
        tree._nodes = NoScan(tree._nodes)
    store._key_trees = NoScan(store._key_trees)
    append(513)
    assert answer(memory, "record_id", "duplicate", "latest").envelope == envs[-1]
    assert answer(memory, "record_id", "duplicate", "first", at=0).envelope == envs[0]


def test_concurrent_same_sequence_appends_have_exactly_one_winner(memory):
    from concurrent.futures import ThreadPoolExecutor
    store, append, envs, _, _ = memory
    append(0)
    env = replace(envs[0], seq=1, prev_hash=envs[0].chain_hash())
    env = replace(env, signature=store.signer.sign(env.signed_body()))
    def run(_):
        try:
            store.append(env)
            return "accepted"
        except EvidenceError:
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(run, range(2))) == ["accepted", "refused"]
    assert store.head.tree_size == 2


def test_invalid_lookup_types_and_ordinals_fail(memory):
    store, append, _, heads, _ = memory
    append(0)
    for kind, key in (("unknown", "x"), ("record_hash", object()), ("record_id_hash", ("id",)),
                      ("record_id_hash", ["id", "a" * 64]), ("record_id", b"x")):
        with pytest.raises(EvidenceError):
            lookup_key("tenant", kind, key)
    for selection, ordinal in (("ordinal", True), ("ordinal", -1), ("latest", 0), ("unknown", None)):
        with pytest.raises(EvidenceError):
            store.lookup(head=heads[0], key_type="record_id", key="duplicate", selection=selection, ordinal=ordinal)
