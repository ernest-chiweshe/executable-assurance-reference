"""Defensive fixtures with valid outer signatures around inconsistent evidence.

No runtime guards are removed or altered. These tests exercise each boundary
without assuming that a trusted signer guarantees internally consistent data.
"""
import json
from dataclasses import replace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_service import EvidenceDelta, EvidenceError, verify_delta, verify_head, verify_head_extension
from regulated_core.merkle import MemoryMerkleLog
from test_evidence_service_formats import case, head_args
from test_protected_head_core import store_for


@pytest.mark.parametrize("damage", ["predecessor", "signature", "canonical_bytes", "final_entry"])
def test_signed_head_does_not_excuse_invalid_retained_body(case, damage):
    clock, signer, _, trust, keys, _, heads, envelopes = case
    env = envelopes[0]
    if damage == "predecessor":
        env = replace(env, prev_hash="f" * 64)
        env = replace(env, signature=signer.sign(env.signed_body()))
    elif damage == "signature":
        env = replace(env, signature=replace(env.signature, value="00" * 64))
    raw = canonical_bytes(env)
    if damage == "canonical_bytes":
        raw = b" " + raw
    tree = MemoryMerkleLog()
    tree.append(raw)
    head = replace(heads[0], tree_root=tree.root().hex(), last_entry_hash=env.chain_hash())
    if damage == "final_entry":
        head = replace(head, last_entry_hash="f" * 64)
    head = replace(head, signature=signer.sign(head.body()))
    assert verify_head(head, **head_args(case))
    delta = EvidenceDelta("tenant", 0, 0, (raw,), None, head, (), (tree.inclusion(0),))
    with pytest.raises(EvidenceError):
        verify_delta(delta, expected_previous=None, expected_head=head, tenant="tenant",
                     clock_domain=clock.domain, trust=trust, allowed_head_keys=keys,
                     allowed_envelope_keys=keys, allowed_envelope_domains=frozenset({clock.domain}), max_entries=1)


@pytest.mark.parametrize("field,value", [("tenant", "another-tenant"), ("clock_domain", "another-clock")])
def test_valid_signature_still_requires_expected_tenant_and_clock(case, field, value):
    head = replace(case[6][0], **{field: value})
    head = replace(head, signature=case[1].sign(head.body()))
    assert case[3].verify(head.body(), head.signature)
    assert not verify_head(head, **head_args(case))


def test_independently_signed_regressed_head_time_is_refused(case):
    old, new = case[6][:2]
    new = replace(new, issued_at_us=old.issued_at_us - 1)
    new = replace(new, signature=case[1].sign(new.body()))
    assert verify_head(new, **head_args(case))
    assert not verify_head_extension(old, new, case[5].consistency(1, 2), **head_args(case))


def test_current_hash_pin_binds_an_otherwise_valid_publication(tmp_path, case):
    store = store_for(tmp_path, case)
    store.advance(None, case[6][0], ())
    pointer = json.loads((store.directory / "CURRENT").read_bytes())
    pointer["hash"] = "f" * 64
    (store.directory / "CURRENT").write_bytes(canonical_bytes(pointer))
    assert store._load(1).head == case[6][0]
    with pytest.raises(EvidenceError, match="refused"):
        store.read()
    assert (store.directory / "LATCH").exists()


def write_following(store, head, consistency=()):
    store._path(2).write_bytes(canonical_bytes({"schema": "regulated/head-publication/v1", "counter": 2,
                                             "head": head.document(),
                                             "consistency": tuple(h.hex() for h in consistency)}))


@pytest.mark.parametrize("damage", ["same_size", "smaller_size", "fork"])
def test_valid_next_publication_must_strictly_extend_current(tmp_path, case, damage):
    store = store_for(tmp_path, case)
    current = case[6][1]
    store.advance(None, current, ())
    if damage == "same_size":
        following = current  # a valid equality proof is not a new publication
    elif damage == "smaller_size":
        following = case[6][0]
    else:
        following = replace(case[6][2], tree_root="f" * 64)
        following = replace(following, signature=case[1].sign(following.body()))
    write_following(store, following)
    assert store._load(2).head == following
    with pytest.raises(EvidenceError, match="refused"):
        store.read()
    assert (store.directory / "LATCH").exists()


def test_advance_rejects_nonextending_signed_head_before_file_write(tmp_path, case):
    store = store_for(tmp_path, case)
    old, new = case[6][:2]
    store.advance(None, old, ())
    assert verify_head(new, **head_args(case))
    with pytest.raises(EvidenceError, match="unverified"):
        store.advance(old, new, ())  # missing nonempty consistency proof
    assert not store._path(2).exists()
    assert store.read() == old


def test_signed_head_over_cross_tenant_delta_body_is_refused(case):
    from regulated_core.canonical import digest_hex
    from regulated_core.evidence import verify_envelope
    clock, signer, _, trust, keys, _, heads, envelopes = case
    record = replace(envelopes[0].record, tenant_id="other-tenant")
    envelope = replace(envelopes[0], record=record, record_hash=digest_hex(record))
    envelope = replace(envelope, signature=signer.sign(envelope.signed_body()))
    assert verify_envelope(envelope, trust)
    raw = canonical_bytes(envelope)
    tree = MemoryMerkleLog(); tree.append(raw)
    head = replace(heads[0], tree_root=tree.root().hex(), last_entry_hash=envelope.chain_hash())
    head = replace(head, signature=signer.sign(head.body()))
    assert verify_head(head, **head_args(case))
    delta = EvidenceDelta("tenant", 0, 0, (raw,), None, head, (), ((),))
    with pytest.raises(EvidenceError, match="envelope verification"):
        verify_delta(delta, expected_previous=None, expected_head=head, tenant="tenant",
                     clock_domain=clock.domain, trust=trust, allowed_head_keys=keys,
                     allowed_envelope_keys=keys, allowed_envelope_domains=frozenset({clock.domain}), max_entries=1)
