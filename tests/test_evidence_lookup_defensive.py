"""Defensive proof-completeness and untrusted-store fixtures; guards stay intact."""
from dataclasses import replace

import pytest

from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence_map import MemorySparseMap, MapProof
from regulated_core.evidence_service import (EvidenceError, KeySummary, LookupProof, OccurrenceProof,
                                            lookup_key, occurrence_bytes, verify_lookup)
from regulated_core.merkle import MemoryMerkleLog
from test_evidence_service_formats import case
from test_evidence_service_memory import memory, snapshot


def query(memory, selection="count", key="duplicate", ordinal=None):
    store, append, _, heads, args = memory
    if not heads:
        append(0); append(1)
    proof = store.lookup(head=heads[-1], key_type="record_id", key=key, selection=selection, ordinal=ordinal)
    return proof, dict(expected_head=heads[-1], key_type="record_id", key=key,
                       selection=selection, ordinal=ordinal, **args)


@pytest.mark.parametrize("damage", ["value", "sibling", "other_key", "false_absence", "false_presence"])
def test_count_and_absence_depend_on_authenticated_map_not_inclusion(memory, damage):
    store = memory[0]
    proof, args = query(memory)
    if damage == "value":
        summary = KeySummary.decode(proof.map_proof.value, proof.head.tree_size)
        changed = replace(summary, count=1, first_seq=summary.last_seq)
        bad = replace(proof, map_proof=replace(proof.map_proof, value=changed.bytes()))
    elif damage == "sibling":
        siblings = (b"x" * 32,) + proof.map_proof.siblings[1:]
        bad = replace(proof, map_proof=replace(proof.map_proof, siblings=siblings))
    elif damage in ("other_key", "false_absence"):
        other = store._map.prove(lookup_key("tenant", "record_id", "missing"))
        if damage == "other_key":
            other = replace(other, value=proof.map_proof.value)
        bad = replace(proof, map_proof=other)
    else:
        bad = proof
        args["key"] = "missing"
    assert bad.occurrence is None
    with pytest.raises(EvidenceError, match="map proof"):
        verify_lookup(bad, **args)


@pytest.mark.parametrize("damage", ["signature", "tenant", "clock_domain"])
def test_pinned_head_must_be_authenticated_even_for_count(memory, damage):
    proof, args = query(memory)
    if damage == "signature":
        head = replace(proof.head, signature=replace(proof.head.signature, value="00" * 64))
    else:
        head = replace(proof.head, **{damage: "other"})
        head = replace(head, signature=memory[0].signer.sign(head.body()))
    with pytest.raises(EvidenceError):
        verify_lookup(replace(proof, head=head), **(args | {"expected_head": head}))


@pytest.mark.parametrize("selection,key,ordinal", [("count", "duplicate", None), ("absent", "duplicate", None),
                                                   ("first", "missing", None), ("ordinal", "duplicate", 2)])
def test_occurrence_is_refused_where_summary_proves_none_requested(memory, selection, key, ordinal):
    actual, _ = query(memory, "first")
    proof, args = query(memory, selection, key, ordinal)
    assert proof.occurrence is None
    with pytest.raises(EvidenceError):
        verify_lookup(replace(proof, occurrence=actual.occurrence), **args)


def malicious_single(case, envelope, raw=None):
    clock, signer, _, trust, keys, _, heads, original = case
    if raw is None:
        raw = canonical_bytes(envelope)
    tree, occurrences, mapping = MemoryMerkleLog(), MemoryMerkleLog(), MemorySparseMap()
    tree.append(raw); occurrences.append(occurrence_bytes(0))
    key = original[0].record.record_id
    digest = lookup_key("tenant", "record_id", key)
    mapping.update(digest, KeySummary(1, 0, 0, occurrences.root().hex()).bytes())
    head = replace(heads[0], tree_root=tree.root().hex(), map_root=mapping.root.hex())
    head = replace(head, signature=signer.sign(head.body()))
    proof = LookupProof(head, mapping.prove(digest), OccurrenceProof(0, 0, raw, (), ()))
    args = dict(expected_head=head, tenant="tenant", key_type="record_id", key=key, selection="first",
                clock_domain=clock.domain, trust=trust, allowed_head_keys=keys,
                allowed_envelope_keys=keys, allowed_envelope_domains=frozenset({clock.domain}))
    return proof, args


@pytest.mark.parametrize("damage", ["sequence", "tenant", "signature", "canonical_bytes"])
def test_included_envelope_still_needs_its_own_qualification(case, damage):
    envelope = case[-1][0]
    if damage == "sequence":
        envelope = replace(envelope, seq=42)
        envelope = replace(envelope, signature=case[1].sign(envelope.signed_body()))
    elif damage == "tenant":
        record = replace(envelope.record, tenant_id="other")
        envelope = replace(envelope, record=record, record_hash=digest_hex(record))
        envelope = replace(envelope, signature=case[1].sign(envelope.signed_body()))
    elif damage == "signature":
        envelope = replace(envelope, signature=replace(envelope.signature, value="00" * 64))
    raw = canonical_bytes(envelope)
    if damage == "canonical_bytes": raw = b" " + raw
    proof, args = malicious_single(case, envelope, raw)
    with pytest.raises(EvidenceError, match="qualification"):
        verify_lookup(proof, **args)


@pytest.mark.parametrize("selection", ["first", "latest"])
def test_endpoint_metadata_must_match_included_ordinal(memory, selection):
    store, append, envs, heads, args = memory
    for i in range(4): append(i)
    sequences = (1, 2) if selection == "first" else (0, 2)
    summary_first, summary_last = (0, 2) if selection == "first" else (0, 3)
    occurrences = MemoryMerkleLog()
    for seq in sequences: occurrences.append(occurrence_bytes(seq))
    mapping = MemorySparseMap(); digest = lookup_key("tenant", "record_id", "duplicate")
    mapping.update(digest, KeySummary(2, summary_first, summary_last, occurrences.root().hex()).bytes())
    head = replace(heads[-1], map_root=mapping.root.hex())
    head = replace(head, signature=store.signer.sign(head.body()))
    ordinal = 0 if selection == "first" else 1
    seq = sequences[ordinal]
    item = OccurrenceProof(ordinal, seq, canonical_bytes(envs[seq]), occurrences.inclusion(ordinal),
                           store._tree.inclusion(seq, head.tree_size))
    proof = LookupProof(head, mapping.prove(digest), item)
    with pytest.raises(EvidenceError, match="occurrence"):
        verify_lookup(proof, expected_head=head, key_type="record_id", key="duplicate", selection=selection, **args)


def test_summary_endpoint_cannot_exceed_pinned_history():
    with pytest.raises(EvidenceError):
        KeySummary.decode(KeySummary(2, 0, 9, "a" * 64).bytes(), 9)


@pytest.mark.parametrize("damage", ["predecessor", "tenant", "signature", "key_tree"])
def test_append_signed_bad_chain_or_scope_and_corrupt_key_tree_refuse(memory, damage):
    store, append, envs, _, _ = memory
    append(0)
    envelope = replace(envs[0], seq=1, prev_hash=envs[0].chain_hash())
    if damage == "predecessor": envelope = replace(envelope, prev_hash="f" * 64)
    elif damage == "tenant":
        record = replace(envelope.record, tenant_id="other")
        envelope = replace(envelope, record=record, record_hash=digest_hex(record))
    envelope = replace(envelope, signature=store.signer.sign(envelope.signed_body()))
    if damage == "signature": envelope = replace(envelope, signature=replace(envelope.signature, value="00" * 64))
    elif damage == "key_tree":
        key = lookup_key("tenant", "record_id", "duplicate")
        corrupt = MemoryMerkleLog(); corrupt.append(occurrence_bytes(999))
        store._key_trees[key] = corrupt
    before = snapshot(store)
    with pytest.raises(EvidenceError): store.append(envelope)
    assert snapshot(store) == before


def test_valid_signed_same_key_body_absent_from_tree_is_refused(memory):
    from regulated_core.evidence import verify_envelope
    proof, args = query(memory, "first")
    original = memory[2][0]
    record = replace(original.record, assertion_id="never-appended-body")
    fork = replace(original, record=record, record_hash=digest_hex(record))
    fork = replace(fork, signature=memory[0].signer.sign(fork.signed_body()))
    assert verify_envelope(fork, memory[0].trust)
    assert fork.seq == proof.occurrence.seq and fork.record.record_id == args["key"]
    assert canonical_bytes(fork) != proof.occurrence.envelope
    substituted = replace(proof, occurrence=replace(proof.occurrence, envelope=canonical_bytes(fork)))
    with pytest.raises(EvidenceError, match="inclusion"):
        verify_lookup(substituted, **args)
