"""Authenticated membership/absence, tenant separation and persistent roots."""
from dataclasses import replace
from hashlib import sha256

import pytest

from regulated_core.evidence_map import (
    DEPTH, EMPTY, MapNode, MapProof, MemorySparseMap, key_digest, verify_map_proof,
)


def test_canonical_key_encoding_separates_tenant_type_and_embedded_nuls():
    triples = [("a\0b", "c", "d"), ("a", "b\0c", "d"), ("a", "b", "c\0d"),
               ("a", "b", ["c", "d"]), ("a", "b", "[c,d]"),
               ("other", "b", "c\0d")]
    assert len({key_digest(*fields) for fields in triples}) == len(triples)
    assert key_digest("a", "state", {"x": 1, "y": 2}) == key_digest("a", "state", {"y": 2, "x": 1})


def test_empty_nonmembership_and_empty_present_value_are_distinct():
    tree = MemorySparseMap()
    key = key_digest("tenant", "id", "one")
    absent = tree.prove(key)
    assert absent.value is None
    assert verify_map_proof(EMPTY[0], key, absent)
    tree.update(key, b"")
    present = tree.prove(key)
    assert present.value == b""
    assert verify_map_proof(tree.root, key, present)
    assert not verify_map_proof(tree.root, key, absent)
    assert not verify_map_proof(tree.root, key, replace(present, value=None))


def test_persistent_roots_and_exactly_bounded_updates():
    tree = MemorySparseMap()
    checkpoints = []
    for i in range(256):
        key = sha256(str(i).encode()).digest()
        value = str(i).encode()
        before = len(tree._nodes)
        tree.update(key, value)
        assert len(tree._nodes) - before <= DEPTH + 1
        proof = tree.prove(key)
        assert len(proof.siblings) <= DEPTH
        if i == 0: assert len(proof.siblings) == 0
        assert verify_map_proof(tree.root, key, proof)
        if i in (0, 1, 127, 255):
            checkpoints.append((tree.root, key, value))
    for root, key, value in checkpoints:
        proof = tree.prove(key, root)
        assert proof.value == value
        assert verify_map_proof(root, key, proof)
        absent = tree.prove(b"\xff" * 32, root)
        assert absent.value is None
        assert verify_map_proof(root, b"\xff" * 32, absent)
    old_root, key, old = checkpoints[0]
    tree.update(key, b"changed state")
    assert tree.prove(key).value == b"changed state"
    assert tree.prove(key, old_root).value == old


def test_key_value_sibling_root_and_path_length_tampering_refused():
    tree = MemorySparseMap()
    key = key_digest("a", "record_id", "same")
    tree.update(key, b"retained canonical value")
    for i in range(20): tree.update(sha256(str(i).encode()).digest(), str(i).encode())
    proof = tree.prove(key)
    assert len(proof.siblings)>1 and proof.siblings!=tuple(reversed(proof.siblings))
    bad_proofs = [replace(proof, value=b"other"), replace(proof, key=b"z" * 32),
                  replace(proof, siblings=proof.siblings[:-1]),
                  replace(proof, siblings=proof.siblings + (b"x" * 32,)),
                  replace(proof, siblings=(b"x" * 32,) + proof.siblings[1:]),
                  replace(proof, siblings=tuple(reversed(proof.siblings)))]
    assert all(not verify_map_proof(tree.root, key, p) for p in bad_proofs)
    assert not verify_map_proof(b"x" * 32, key, proof)
    assert not verify_map_proof(tree.root, key_digest("b", "record_id", "same"), proof)
    assert not verify_map_proof(tree.root, key, replace(proof, value=None))


def test_neighboring_keys_membership_and_absence():
    tree = MemorySparseMap()
    for key, value in [(bytes(32), b"zero"), ((1).to_bytes(32, "big"), b"one"),
                       (b"\xff" * 32, b"last")]:
        tree.update(key, value)
    for i in (0, 1, 2, (1 << 256) - 1):
        key = i.to_bytes(32, "big")
        proof = tree.prove(key)
        assert verify_map_proof(tree.root, key, proof)
        assert (proof.value is None) == (i == 2)


def test_corrupt_stored_node_is_not_reported_as_absence():
    tree = MemorySparseMap()
    key = sha256(b"key").digest()
    tree.update(key, b"value")
    tree._nodes[tree.root] = MapNode(left=EMPTY[1], right=EMPTY[1])
    with pytest.raises(ValueError, match="corrupt"):
        tree.prove(key)


@pytest.mark.parametrize("key", [b"short", "x" * 32, None, bytearray(32)])
def test_invalid_keys_and_values_rejected(key):
    tree = MemorySparseMap()
    with pytest.raises(ValueError):
        tree.update(key, b"value")
    assert not verify_map_proof(tree.root, key, MapProof(key, None, ()))
    with pytest.raises(ValueError):
        tree.update(bytes(32), None)
