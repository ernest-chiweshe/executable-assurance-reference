"""RFC shape examples, independent full-tree oracle and malformed-proof checks.

Reference shape examples: https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.5
The recursive oracle is test-only; production proof generation uses node addresses.
"""
from hashlib import sha256

import pytest

from regulated_core.merkle import (
    EMPTY_ROOT, MAX_SIZE, Frontier, MemoryMerkleLog, consistency_proof,
    inclusion_proof, leaf_hash, node_hash, verify_consistency, verify_inclusion,
)


def oracle(items):
    if not items:
        return sha256(b"").digest()
    if len(items) == 1:
        return sha256(b"\0" + items[0]).digest()
    split = 1
    while split * 2 < len(items):
        split *= 2
    return sha256(b"\1" + oracle(items[:split]) + oracle(items[split:])).digest()


def build(n):
    data = [str(i).encode() for i in range(n)]
    tree = MemoryMerkleLog()
    for i, item in enumerate(data):
        assert tree.append(item) == i
    return tree, data


def test_empty_and_single_leaf_known_sha256_vectors():
    assert EMPTY_ROOT.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert leaf_hash(b"").hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert leaf_hash(b"a").hex() == "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c"
    tree, _ = build(0)
    assert tree.root() == EMPTY_ROOT
    assert verify_consistency(0, 0, EMPTY_ROOT, EMPTY_ROOT, ())
    assert not verify_consistency(0, 0, b"x" * 32, b"x" * 32, ())


def test_rfc_seven_leaf_inclusion_and_consistency_examples():
    tree, data = build(7)
    a, b, c, d, e, f, j = [leaf_hash(x) for x in data]
    g, h, i = node_hash(a, b), node_hash(c, d), node_hash(e, f)
    k, l = node_hash(g, h), node_hash(i, j)
    assert tree.root() == node_hash(k, l)
    for index, expected in [(0, (b, h, l)), (3, (c, g, l)), (4, (f, j, k)), (6, (i, k))]:
        assert tree.inclusion(index) == expected
        assert verify_inclusion(data[index], index, 7, expected, tree.root())
    for size, expected in [(3, (c, d, g, l)), (4, (l,)), (6, (i, j, k))]:
        assert tree.consistency(size) == expected
        assert verify_consistency(size, 7, oracle(data[:size]), oracle(data), expected)


def test_all_small_tree_shapes_and_prefixes_against_full_tree_oracle():
    tree, data = build(97)
    for size in range(98):
        root = oracle(data[:size])
        assert tree.root(size) == root
        for index in range(size):
            path = tree.inclusion(index, size)
            assert verify_inclusion(data[index], index, size, path, root)
        for first in range(size + 1):
            path = tree.consistency(first, size)
            assert verify_consistency(first, size, oracle(data[:first]), root, path)


def test_append_frontier_and_proof_work_at_large_histories():
    tree = MemoryMerkleLog()
    roots = {0: EMPTY_ROOT}
    for size in range(1, 10001):
        before = tree.frontier
        after, completed = before.append(str(size - 1).encode())
        assert len(completed) <= size.bit_length()
        assert len(after.slots) == size.bit_length()
        tree.append(str(size - 1).encode())
        assert tree.frontier == after
        if size in (1, 999, 1000, 1001, 8192, 9999, 10000):
            roots[size] = tree.root()
    for size in (1000, 10000):
        calls = []
        def read(level, index):
            calls.append((level, index))
            return tree.read_node(level, index)
        for index in (0, 1, size // 2, size - 1):
            calls.clear()
            path = inclusion_proof(read, index, size)
            assert len(path) <= size.bit_length()
            assert len(calls) <= 2 * size.bit_length()
            assert verify_inclusion(str(index).encode(), index, size, path, roots[size])
        for first in (1, size // 3, size - 1):
            calls.clear()
            path = consistency_proof(read, first, size)
            assert len(calls) <= 2 * size.bit_length()
            assert len(path) <= size.bit_length() + 1
            assert verify_consistency(first, size, tree.root(first), roots[size], path)


def test_historical_roots_and_proofs_survive_future_appends():
    tree, data = build(7)
    root = tree.root()
    path = tree.inclusion(2)
    tree.append(b"later")
    assert tree.root(7) == root
    assert tree.inclusion(2, 7) == path
    assert verify_inclusion(data[2], 2, 7, path, root)
    assert not verify_inclusion(data[2], 2, 8, path, tree.root())


def test_changed_missing_extra_and_reordered_inclusion_proofs_refuse():
    tree, data = build(7)
    path = tree.inclusion(3)
    for bad in (path[:-1], path + (b"x" * 32,), tuple(reversed(path)),
                (b"x" * 32,) + path[1:], (b"short",) + path[1:]):
        assert not verify_inclusion(data[3], 3, 7, bad, tree.root())
    assert not verify_inclusion(b"edited", 3, 7, path, tree.root())
    assert not verify_inclusion(data[3], 2, 7, path, tree.root())
    assert not verify_inclusion(data[3], 3, 7, path, b"x" * 32)


def test_changed_missing_extra_and_forked_consistency_proofs_refuse():
    tree, _ = build(7)
    path = tree.consistency(3)
    for bad in ((), path[:-1], path + (b"x" * 32,), tuple(reversed(path)),
                (b"x" * 32,) + path[1:], (b"short",) + path[1:]):
        assert not verify_consistency(3, 7, tree.root(3), tree.root(), bad)
    assert not verify_consistency(3, 7, b"x" * 32, tree.root(), path)
    assert not verify_consistency(3, 7, tree.root(3), b"x" * 32, path)
    assert not verify_consistency(7, 7, tree.root(), b"x" * 32, ())
    assert not verify_consistency(0, 7, b"x" * 32, tree.root(), ())
    assert not verify_consistency(0, 7, EMPTY_ROOT, tree.root(), path)


@pytest.mark.parametrize("size", [-1, True, 1.0, MAX_SIZE + 1, "7"])
def test_invalid_sizes_fail_closed(size):
    tree, data = build(7)
    assert not verify_inclusion(data[0], 0, size, (), tree.root())
    assert not verify_consistency(size, 7, tree.root(), tree.root(), ())
    with pytest.raises(ValueError):
        Frontier(size)
    with pytest.raises(ValueError):
        tree.root(size)


def test_invalid_frontier_and_indices_refuse():
    for size, slots in [(0, (None,)), (1, (None,)), (2, (b"x" * 32, b"x" * 32)),
                        (1, (b"short",))]:
        with pytest.raises(ValueError):
            Frontier(size, slots)
    tree, _ = build(1)
    for index in (-1, True, 1, 1.0):
        with pytest.raises(ValueError):
            tree.inclusion(index)
    with pytest.raises(ValueError):
        tree.root(2)
    with pytest.raises(ValueError):
        tree.consistency(2, 1)
    full = Frontier(MAX_SIZE, (b"x" * 32,) * 64)
    with pytest.raises(ValueError):
        full.append(b"overflow")


def test_published_certificate_transparency_root_and_consistency_vectors():
    # Factual test vectors from Google's public CT implementation, retrieved
    # independently of reference's verifier:
    # https://github.com/google/certificate-transparency/blob/master/python/ct/crypto/merkle_test.py
    leaves = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
              "606162636465666768696a6b6c6d6e6f"]
    roots = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]
    tree = MemoryMerkleLog()
    for value, expected in zip(leaves, roots):
        tree.append(bytes.fromhex(value))
        assert tree.root().hex() == expected
    paths = {
        (1, 8): ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                 "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                 "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
        (6, 8): ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                 "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                 "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"],
        (2, 5): ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                 "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"],
    }
    for (first, second), expected in paths.items():
        path = tuple(bytes.fromhex(x) for x in expected)
        assert tree.consistency(first, second) == path
        assert verify_consistency(first, second, bytes.fromhex(roots[first - 1]),
                                  bytes.fromhex(roots[second - 1]), path)
