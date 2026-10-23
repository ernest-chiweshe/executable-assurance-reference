"""History flag rejection with otherwise valid authenticated surrounding proofs."""
from dataclasses import replace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_map import MemorySparseMap, verify_map_proof
from regulated_core.evidence_service import (
    EvidenceError, HistoryFlagProof, UnhashableIdFlag, unhashable_id_key,
    verify_head, verify_history_flag,
)
from test_evidence_service_formats import case


@pytest.fixture
def flag_case(case):
    clock, signer, other, trust, keys, _, heads, _ = case
    def build(raw):
        mapping = MemorySparseMap()
        key = unhashable_id_key("tenant")
        if raw is not None:
            mapping.update(key, raw)
        head = replace(heads[-1], map_root=mapping.root.hex())
        head = replace(head, signature=signer.sign(head.body()))
        proof = HistoryFlagProof(head, mapping.prove(key))
        args = dict(expected_head=head, tenant="tenant", clock_domain=clock.domain,
                    trust=trust, allowed_head_keys=keys)
        assert verify_head(head, tenant="tenant", clock_domain=clock.domain,
                           trust=trust, allowed_keys=keys)
        assert verify_map_proof(bytes.fromhex(head.map_root), key, proof.map_proof)
        return proof, args
    return build, signer, other


@pytest.mark.parametrize("seq", [None, 0, 1, 2])
def test_valid_flag_and_absence_controls(flag_case, seq):
    build, _, _ = flag_case
    proof, args = build(None if seq is None else UnhashableIdFlag(seq).bytes())
    assert verify_history_flag(proof, **args) == (None if seq is None else UnhashableIdFlag(seq))


def test_flag_rejects_distinct_valid_head_with_same_map_root(flag_case):
    build, signer, _ = flag_case
    proof, args = build(UnhashableIdFlag(0).bytes())
    alternate = replace(proof.head, issued_at_us=proof.head.issued_at_us + 1)
    alternate = replace(alternate, signature=signer.sign(alternate.body()))
    assert verify_head(alternate, tenant=args["tenant"], clock_domain=args["clock_domain"],
                       trust=args["trust"], allowed_keys=args["allowed_head_keys"])
    assert alternate.map_root == proof.head.map_root and alternate != args["expected_head"]
    with pytest.raises(EvidenceError, match="history flag head or proof failed"):
        verify_history_flag(replace(proof, head=alternate), **args)


@pytest.mark.parametrize("fault", ["signature", "tenant", "domain", "unallowed-key"])
def test_flag_rejects_invalid_pinned_head_even_with_valid_map_proof(flag_case, fault):
    build, signer, other = flag_case
    proof, args = build(UnhashableIdFlag(0).bytes())
    head = proof.head
    if fault == "signature":
        head = replace(head, signature=replace(head.signature, value="00" * 64))
    elif fault == "tenant":
        head = replace(head, tenant="other-tenant")
        head = replace(head, signature=signer.sign(head.body()))
    elif fault == "domain":
        head = replace(head, clock_domain="test:other-domain")
        head = replace(head, signature=signer.sign(head.body()))
    else:
        head = replace(head, key_id=other.key_id)
        head = replace(head, signature=other.sign(head.body()))
    args["expected_head"] = head
    assert verify_map_proof(bytes.fromhex(head.map_root), unhashable_id_key(args["tenant"]), proof.map_proof)
    with pytest.raises(EvidenceError, match="history flag head or proof failed"):
        verify_history_flag(replace(proof, head=head), **args)


@pytest.mark.parametrize("raw", [
    canonical_bytes({"schema": "wrong", "first_seq": 0}),
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": -1}),
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": True}),
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": "0"}),
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": 3}),
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": 4}),
    b" " + UnhashableIdFlag(0).bytes(),
    b'{"schema":"regulated/evidence-flag/v1","first_seq":0}',
    canonical_bytes({"schema": "regulated/evidence-flag/v1", "first_seq": 0, "extra": 1}),
])
def test_flag_rejects_bad_body_under_valid_signed_head_and_map_proof(flag_case, raw):
    build, _, _ = flag_case
    proof, args = build(raw)
    with pytest.raises(EvidenceError, match="invalid authenticated history flag"):
        verify_history_flag(proof, **args)
