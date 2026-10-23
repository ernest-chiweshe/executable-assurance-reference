"""Core head/delta contracts only; this does not activate retention or permits."""
import json
from dataclasses import replace

import pytest

from regulated_core import (Action, ActionEffect, Actor, Assertion, Decision,
                            PolicyContext, PolicyRef)
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.clock import ClockError, ClockReading
from regulated_core.evidence import DecisionRecorder
from regulated_core.evidence_map import EMPTY
from regulated_core.evidence_service import (
    EvidenceDelta, EvidenceError, TreeHead, sign_head, verify_delta,
    verify_head, verify_head_extension,
)
from regulated_core.merkle import MemoryMerkleLog
from regulated_core.signing import Ed25519Signer, TrustDirectory


class Clock:
    domain = "test:phase1-head"

    def __init__(self):
        self.value = 100
        self.calls = 0

    def read(self):
        self.calls += 1
        return ClockReading(self.domain, self.value)

    def now_us(self):
        return self.read().now_us


@pytest.fixture
def case():
    clock = Clock()
    signer = Ed25519Signer("evidence:current")
    other = Ed25519Signer("evidence:historical")
    trust = TrustDirectory()
    trust.register_signer(signer)
    trust.register_signer(other)
    keys = frozenset({signer.key_id})
    recorder = DecisionRecorder(signer, trust, clock=clock)
    tree = MemoryMerkleLog()
    heads, envelopes = [], []
    for i in range(3):
        clock.value += 10
        envelope = recorder.record(
            Assertion(f"a{i}", "tenant", "sample", "a" * 64),
            Action("sample", ActionEffect.REVERSIBLE),
            PolicyContext("tenant", Actor("actor", "tenant", frozenset()), "purpose", "mission", clock.value),
            PolicyRef("family", "policy", "1"), Decision.deny("FIXTURE", "phase1 format"),
        )
        envelopes.append(envelope)
        tree.append(canonical_bytes(envelope))
        heads.append(sign_head(tenant="tenant", tree_size=i + 1, tree_root=tree.root(),
                               map_root=EMPTY[0], last_entry_hash=envelope.chain_hash(),
                               previous=heads[-1] if heads else None, signer=signer, clock=clock,
                               trust=trust, signing_keys=keys, historical_keys={}))
    return clock, signer, other, trust, keys, tree, heads, envelopes


def head_args(case):
    clock, _, _, trust, keys, *_ = case
    return dict(tenant="tenant", clock_domain=clock.domain, trust=trust, allowed_keys=keys)


def delta_case(case):
    clock, _, _, trust, keys, tree, heads, envelopes = case
    delta = EvidenceDelta("tenant", 1, 2, tuple(canonical_bytes(e) for e in envelopes[1:]),
                          heads[0], heads[-1], tree.consistency(1, 3),
                          tuple(tree.inclusion(i, 3) for i in (1, 2)))
    args = dict(expected_previous=heads[0], expected_head=heads[-1], tenant="tenant",
                clock_domain=clock.domain, trust=trust, allowed_head_keys=keys,
                allowed_envelope_keys=keys, allowed_envelope_domains=frozenset({clock.domain}), max_entries=2)
    return delta, args


def test_head_roundtrip_explicit_body_and_fresh_signing_read(case):
    clock, signer, _, trust, keys, tree, heads, envelopes = case
    head = heads[-1]
    assert verify_head(head, **head_args(case))
    document = json.loads(canonical_bytes(head.document()))
    assert TreeHead.from_document(document) == head
    assert head.body() == {
        "schema": "regulated/evidence-sth/v2", "map_schema": "regulated/evidence-map/v2", "tenant": "tenant", "tree_size": 3,
        "tree_root": tree.root().hex(), "map_root": EMPTY[0].hex(),
        "last_entry_hash": envelopes[-1].chain_hash(), "key_id": signer.key_id,
        "clock_domain": clock.domain, "issued_at_us": 130, "previous_sth_digest": heads[-2].digest(),
    }
    calls = clock.calls
    clock.value = 200
    new = sign_head(tenant="tenant", tree_size=1, tree_root=tree.root(1), map_root=EMPTY[0],
                    last_entry_hash=envelopes[0].chain_hash(), previous=None, signer=signer,
                    clock=clock, trust=trust, signing_keys=keys, historical_keys={})
    assert new.issued_at_us == 200 and clock.calls == calls + 1


def test_head_signature_tenant_domain_and_historical_write_policy(case):
    clock, signer, other, trust, keys, tree, heads, envelopes = case
    head = heads[-1]
    for bad in (replace(head, tenant="other"), replace(head, tree_root="f" * 64),
                replace(head, map_root="f" * 64), replace(head, clock_domain="other"),
                replace(head, tree_size=True), replace(head, key_id={}),
                replace(head, signature=replace(head.signature, value="00"))):
        assert not verify_head(bad, **head_args(case))
    old = replace(head, key_id=other.key_id)
    old = replace(old, signature=other.sign(old.body()))
    assert not verify_head(old, **head_args(case))
    assert verify_head(old, **(head_args(case) | {"allowed_keys": keys | {other.key_id}}))
    with pytest.raises(EvidenceError, match="configuration"):
        sign_head(tenant="tenant", tree_size=1, tree_root=tree.root(1), map_root=EMPTY[0],
                  last_entry_hash=envelopes[0].chain_hash(), previous=None, signer=other,
                  clock=clock, trust=trust, signing_keys=keys, historical_keys={other.key_id: {"retired_after_size": 3}})


def test_head_extension_forks_rollback_and_time_regression_refuse(case):
    clock, signer, _, trust, keys, tree, heads, _ = case
    args = head_args(case)
    assert verify_head_extension(heads[0], heads[-1], tree.consistency(1, 3), **args)
    assert verify_head_extension(heads[0], heads[0], (), **args)
    assert not verify_head_extension(heads[-1], heads[0], (), **args)
    fork = replace(heads[0], map_root="f" * 64)
    fork = replace(fork, signature=signer.sign(fork.body()))
    assert not verify_head_extension(heads[0], fork, (), **args)
    wrong_previous = replace(heads[1], previous_sth_digest="f" * 64)
    wrong_previous = replace(wrong_previous, signature=signer.sign(wrong_previous.body()))
    assert not verify_head_extension(heads[0], wrong_previous, tree.consistency(1, 2), **args)
    clock.value = 0
    with pytest.raises(EvidenceError, match="time regressed"):
        sign_head(tenant="tenant", tree_size=4, tree_root=tree.root(), map_root=EMPTY[0],
                  last_entry_hash=heads[-1].last_entry_hash, previous=heads[-1], signer=signer,
                  clock=clock, trust=trust, signing_keys=keys, historical_keys={})


def test_head_document_extra_fields_and_schema_are_rejected(case):
    document = json.loads(canonical_bytes(case[6][-1].document()))
    bad = dict(document, ignored="anything")
    with pytest.raises(EvidenceError):
        TreeHead.from_document(bad)
    document["body"]["schema"] = "other"
    with pytest.raises(EvidenceError):
        TreeHead.from_document(document)


def test_delta_preserves_full_signed_envelope_bytes(case):
    delta, args = delta_case(case)
    assert verify_delta(delta, **args) == tuple(case[-1][1:])
    payload = json.loads(delta.bytes())
    assert payload["schema"] == "regulated/evidence-delta/v1"
    assert tuple(bytes.fromhex(raw) for raw in payload["envelopes"]) == delta.envelopes
    assert canonical_bytes(payload) == delta.bytes()


def test_delta_complete_range_and_pins_required(case):
    delta, args = delta_case(case)
    changes = [replace(delta, envelopes=delta.envelopes[:-1]),
               replace(delta, from_seq=0), replace(delta, to_seq=99),
               replace(delta, previous=None), replace(delta, tenant="other"),
               replace(delta, consistency=()), replace(delta, inclusion_paths=delta.inclusion_paths[:-1]),
               replace(delta, inclusion_paths=tuple(reversed(delta.inclusion_paths)))]
    for changed in changes:
        with pytest.raises(EvidenceError):
            verify_delta(changed, **args)
    with pytest.raises(EvidenceError):
        verify_delta(delta, **(args | {"max_entries": 1}))
    with pytest.raises(EvidenceError):
        verify_delta(delta, **(args | {"expected_previous": None}))


def test_valid_signature_on_substituted_body_does_not_pass_inclusion(case):
    delta, args = delta_case(case)
    signer = case[1]
    original = case[-1][1]
    record = replace(original.record, record_id="substituted")
    changed = replace(original, record=record, record_hash=digest_hex(record))
    changed = replace(changed, signature=signer.sign(changed.signed_body()))
    with pytest.raises(EvidenceError, match="envelope verification"):
        verify_delta(replace(delta, envelopes=(canonical_bytes(changed), delta.envelopes[1])), **args)


def test_delta_key_domain_and_canonical_bytes_refuse(case):
    delta, args = delta_case(case)
    with pytest.raises(EvidenceError):
        verify_delta(delta, **(args | {"allowed_envelope_keys": frozenset({"other"})}))
    with pytest.raises(EvidenceError):
        verify_delta(delta, **(args | {"allowed_envelope_domains": frozenset({"other"})}))
    with pytest.raises(EvidenceError):
        verify_delta(replace(delta, envelopes=(b" " + delta.envelopes[0], delta.envelopes[1])), **args)
