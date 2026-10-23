"""Defensive witness contracts; no network, durable-custody or latency claim."""
from dataclasses import replace

import pytest

from regulated_core.evidence_service import EvidenceError
from regulated_core.evidence_witness import (
    Checkpoint, GENESIS_ACK, HeadPolicy, HistoricalAck, WitnessAck,
    WitnessReack, WitnessRequest, WitnessScope, WitnessSet, decide_request, verify_quorum,
)
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory
from test_evidence_service_formats import case


@pytest.fixture
def protocol(case):
    clock, _, _, trust, keys, tree, heads, _ = case
    scope = WitnessScope("tenant", "tenant", "evidence")
    policy = HeadPolicy(scope, clock.domain, keys, trust)
    return scope, policy, tree, heads


def request(protocol, target=2, previous=0, nonce="a" * 32):
    scope, policy, tree, heads = protocol
    old = None if previous is None else Checkpoint.from_head(heads[previous], policy)
    return WitnessRequest(nonce, scope, old, heads[target], tree.consistency(0 if old is None else old.size, heads[target].tree_size))


def test_extension_and_reack_do_not_require_history_scan(protocol):
    _, policy, _, heads = protocol
    assert decide_request(request(protocol, previous=None), None, policy) == "ACK"
    assert decide_request(request(protocol), heads[0], policy) == "ACK"
    # Lost reply: stale previous is harmless only when the requested head IS current.
    assert decide_request(request(protocol), heads[2], policy) == "REACK"


def test_historically_accepted_checkpoint_is_not_fresh_even_with_new_request_id(protocol):
    _, policy, _, heads = protocol
    assert decide_request(request(protocol, target=0, previous=None), heads[2], policy) == "STALE"
    assert decide_request(request(protocol, target=0, previous=None, nonce="b" * 32), heads[2], policy) == "STALE"


def test_stale_previous_requires_reconciliation(protocol):
    _, policy, _, heads = protocol
    assert decide_request(request(protocol), heads[1], policy) == "STALE"
    assert decide_request(request(protocol, previous=1), heads[1], policy) == "ACK"


def test_conflicting_signed_head_at_current_size_refuses(protocol, case):
    _, policy, _, heads = protocol
    fork = replace(heads[2], map_root="1" * 64)
    fork = replace(fork, signature=case[1].sign(fork.body()))
    assert decide_request(replace(request(protocol), head=fork), heads[2], policy) == "CONFLICT"


@pytest.mark.parametrize("change", [
    {"request_id": "a" * 31}, {"request_id": "A" * 32},
    {"scope": WitnessScope("tenant", "another", "evidence")},
    {"consistency": (b"short",)}, {"consistency": (b"x" * 32,) * 66},
    {"consistency": ()},
])
def test_malformed_or_inconsistent_extension_fails(protocol, change):
    _, policy, _, heads = protocol
    with pytest.raises(EvidenceError):
        decide_request(replace(request(protocol), **change), heads[0], policy)


def test_bad_signature_cannot_receive_reack(protocol):
    _, policy, _, heads = protocol
    bad = replace(heads[2], signature=replace(heads[2].signature, value="0" * 128))
    with pytest.raises(EvidenceError):
        decide_request(replace(request(protocol), head=bad), heads[2], policy)


@pytest.fixture
def quorum_case(protocol):
    scope, policy, _, heads = protocol
    checkpoint = Checkpoint.from_head(heads[2], policy)
    signers = [Ed25519Signer(f"w{i}") for i in range(4)]
    trust = TrustDirectory()
    for signer in signers:
        trust.register_signer(signer)
    members = WitnessSet(tuple((s.key_id, s.key_id) for s in signers), 1, 1, 3)
    requests = {s.key_id: f"{i+1:032x}" for i, s in enumerate(signers)}
    acks = []
    for signer in signers:
        ack = WitnessAck(signer.key_id, requests[signer.key_id], scope, checkpoint,
                         GENESIS_ACK, 100, Signature(signer.key_id, ""))
        acks.append(replace(ack, signature=signer.sign(ack.body())))
    args = dict(requests=requests, checkpoint=checkpoint, scope=scope,
                previous_acks={s.key_id: GENESIS_ACK for s in signers}, members=members, trust=trust)
    return tuple(acks), args, signers


def test_valid_quorum_with_one_unavailable(quorum_case):
    acks, args, _ = quorum_case
    assert verify_quorum(acks[:3], **args) == acks[:3]


@pytest.mark.parametrize("kind", ["short", "duplicate", "historical", "wrong_nonce", "wrong_scope",
                                  "wrong_size", "wrong_root", "forged", "chain_gap", "unknown"])
def test_bad_quorum_refuses_as_a_whole(quorum_case, kind):
    acks, args, signers = quorum_case
    bad = acks[0]
    if kind == "short":
        responses = acks[:2]
    elif kind == "duplicate":
        responses = (bad, bad, acks[1])
    elif kind == "historical":
        responses = (HistoricalAck(bad), *acks[1:3])
    else:
        if kind == "wrong_nonce": bad = replace(bad, request_id="f" * 32)
        if kind == "wrong_scope": bad = replace(bad, scope=WitnessScope("tenant", "other", "evidence"))
        if kind == "wrong_size": bad = replace(bad, checkpoint=replace(bad.checkpoint, size=0))
        if kind == "wrong_root": bad = replace(bad, checkpoint=replace(bad.checkpoint, root="1" * 64))
        if kind == "chain_gap": bad = replace(bad, previous_ack_digest="1" * 64)
        if kind == "unknown": bad = replace(bad, witness_id="unknown")
        bad = replace(bad, signature=signers[0].sign(bad.body()))
        if kind == "forged": bad = replace(bad, signature=replace(bad.signature, value="0" * 128))
        responses = (bad, *acks[1:3])
    with pytest.raises(EvidenceError):
        verify_quorum(responses, **args)


def test_reack_binds_new_request_and_preserves_signed_original(quorum_case):
    acks, args, signers = quorum_case
    args = {**args, "requests": {**args["requests"], "w0": "f" * 32}}
    response = WitnessReack("w0", "f" * 32, acks[0], Signature("w0", ""))
    response = replace(response, signature=signers[0].sign(response.body()))
    assert verify_quorum((response, *acks[1:3]), **args) == acks[:3]
    # Idempotent retry where the local pin already holds the original ACK.
    pinned = {**args, "previous_acks": {**args["previous_acks"], "w0": acks[0].digest()}}
    assert verify_quorum((response, *acks[1:3]), **pinned) == acks[:3]
    with pytest.raises(EvidenceError):
        verify_quorum((replace(response, request_id="e" * 32), *acks[1:3]), **args)
    with pytest.raises(EvidenceError):
        verify_quorum((replace(response, signature=replace(response.signature, value="0" * 128)), *acks[1:3]), **args)


@pytest.mark.parametrize("f,m,q", [(1, 1, 2), (2, 1, 3), (-1, 0, 4), (0, True, 4), (0, 4, 4)])
def test_unsafe_quorum_configuration_refuses(quorum_case, f, m, q):
    _, args, _ = quorum_case
    with pytest.raises(EvidenceError):
        replace(args["members"], unavailable=f, malicious=m, quorum=q).validate(args["trust"])


def test_key_aliases_cannot_multiply_quorum_votes(quorum_case):
    _, args, signers = quorum_case
    args["trust"].register("alias", signers[0].public_key_bytes)
    members = WitnessSet((("w0", "w0"), ("alias", "alias")), 0, 0, 2)
    with pytest.raises(EvidenceError):
        members.validate(args["trust"])


def test_adjacent_extension_keeps_signed_predecessor_and_clock_rules(protocol, case):
    _, policy, _, heads = protocol
    for changed in (replace(heads[1], previous_sth_digest="1" * 64),
                    replace(heads[1], issued_at_us=heads[0].issued_at_us - 1)):
        changed = replace(changed, signature=case[1].sign(changed.body()))
        with pytest.raises(EvidenceError):
            decide_request(replace(request(protocol, target=1), head=changed), heads[0], policy)


def test_namespace_binding_and_current_checkpoint_share_the_contract(case):
    from regulated_core.evidence_namespace import NamespaceHead
    clock, signer, _, trust, keys, tree, _, _ = case
    scope = WitnessScope("tenant", "tenant", "roster")
    policy = HeadPolicy(scope, clock.domain, keys, trust)
    head = NamespaceHead("tenant", "tenant", "roster", 1, tree.root(1).hex(),
                         "1" * 64, "2" * 64, "0" * 64, signer.key_id,
                         clock.domain, clock.value, Signature(signer.key_id, ""))
    head = replace(head, signature=signer.sign(head.body()))
    request = WitnessRequest("c" * 32, scope, None, head, ())
    assert decide_request(request, None, policy) == "ACK"
    assert decide_request(request, head, policy) == "REACK"
    assert request.document(policy)["checkpoint"]["head"] == head.document()
    other = WitnessScope("tenant", "tenant", "budget")
    with pytest.raises(EvidenceError):
        decide_request(replace(request, scope=other), None, replace(policy, scope=other))
    with pytest.raises(EvidenceError):
        decide_request(request, None, replace(policy, clock_domain="wrong"))
