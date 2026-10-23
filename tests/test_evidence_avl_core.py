"""AVL worst-order height, exact selection and authenticated proof checks."""
import math
import random
from dataclasses import replace

import pytest

from regulated_core import evidence_avl as avl
from regulated_core.evidence_avl import (
    Candidate, EvidenceAVL, Report, verify_candidates, verify_current,
)


def report(seq, expiry, qualified=None):
    return Report(seq, seq if qualified is None else qualified, expiry, f"{seq:064x}")


def audit(node):
    if node is None:
        return [], 0
    left, lh = audit(node.left)
    right, rh = audit(node.right)
    assert abs(lh - rh) <= 1
    assert node.header.descriptor() == node.descriptor
    records = left + [node.record] + right
    if isinstance(node.record, Report):
        assert [(r.expires_at_us, r.seq) for r in records] == sorted((r.expires_at_us, r.seq) for r in records)
        assert node.descriptor.best == (max((r.qualified_at_us, -r.seq) for r in records),)
    else:
        assert [r.ordinal for r in records] == sorted(r.ordinal for r in records)
        assert node.descriptor.best == tuple(sorted(((r.ordinal, r.version) for r in records), reverse=True)[:3])
    assert node.descriptor.height == 1 + max(lh, rh)
    return records, 1 + max(lh, rh)


@pytest.mark.parametrize("order", ["ascending", "descending", "alternating", "same_expiry"])
def test_ten_thousand_reports_worst_order_balance_and_proof_bound(order):
    count = 10000
    indices = list(range(count))
    if order == "descending":
        indices.reverse()
    elif order == "alternating":
        indices = [i for pair in zip(range(count // 2), reversed(range(count // 2, count))) for i in pair]
    tree = EvidenceAVL("qualification")
    records = []
    for seq in indices:
        row = report(seq, 5000 if order == "same_expiry" else seq + 1, seq % 97)
        records.append(row)
        tree = tree.insert(row)
    assert tree.height <= math.ceil(1.45 * math.log2(count + 2))
    audit(tree.node)
    for now in (0, 1, 4999, 5000, 5001, 9999, 10000, 10001):
        live = [r for r in records if now < r.expires_at_us]
        expected = max(live, key=lambda r: (r.qualified_at_us, -r.seq)).seq if live else None
        proof = tree.current_proof(now)
        assert len(proof) <= tree.height
        assert verify_current(tree.root, now, proof) == expected


def test_generated_reports_match_full_scan_with_ties_and_strict_expiry():
    rng = random.Random(20261018)
    tree = EvidenceAVL("qualification")
    records = []
    snapshots = []
    for seq in range(300):
        row = report(seq, rng.randrange(1, 101), rng.randrange(30))
        records.append(row)
        tree = tree.insert(row)
        if seq in (0, 10, 100, 299):
            snapshots.append((tree, tuple(records)))
    for snapshot, rows in snapshots:
        for now in range(102):
            live = [r for r in rows if now < r.expires_at_us]
            expected = max(live, key=lambda r: (r.qualified_at_us, -r.seq)).seq if live else None
            assert verify_current(snapshot.root, now, snapshot.current_proof(now)) == expected


def test_candidate_insert_delete_and_historical_roots():
    rng = random.Random(42)
    tree = EvidenceAVL("candidate")
    keys = list(range(1000))
    rng.shuffle(keys)
    for key in keys:
        tree = tree.insert(Candidate(key, f"v{key}"))
    snapshot = tree
    active = set(keys)
    for key in keys:
        tree = tree.remove_candidate(key)
        active.remove(key)
        expected = tuple((i, f"v{i}") for i in sorted(active, reverse=True)[:3])
        assert verify_candidates(tree.root, tree.candidates_proof()) == expected
        if len(active) % 100 == 0:
            audit(tree.node)
    assert tree.node is None
    assert verify_candidates(snapshot.root, snapshot.candidates_proof()) == ((999, "v999"), (998, "v998"), (997, "v997"))


def test_updates_have_logarithmic_hash_work(monkeypatch):
    real_hash = avl.sha256
    calls = []
    def counted(value):
        calls.append(len(value))
        return real_hash(value)
    tree = EvidenceAVL("candidate")
    for i in range(10000):
        tree = tree.insert(Candidate(i, str(i)))
    monkeypatch.setattr(avl, "sha256", counted)
    for i in (1, 5000, 9999):
        calls.clear()
        tree = tree.remove_candidate(i)
        assert len(calls) <= 6 * math.ceil(math.log2(10002))
        calls.clear()
        tree = tree.insert(Candidate(i, str(i)))
        assert len(calls) <= 6 * math.ceil(math.log2(10002))


def test_qualification_proof_tampering_refused():
    tree = EvidenceAVL("qualification")
    for i in range(31):
        tree = tree.insert(report(i, i + 1))
    proof = tree.current_proof(10)
    head = proof[0]
    bad = [proof[:-1], proof + (proof[-1],), tuple(reversed(proof)),
           (replace(head, height=head.height + 1),) + proof[1:],
           (replace(head, record=replace(head.record, qualified_at_us=999)),) + proof[1:],
           (replace(head, left=head.right, right=head.left),) + proof[1:],
           (replace(head, left=replace(head.left, best=((999, -1),))),) + proof[1:],
           (replace(head, left=replace(head.left, height=head.left.height + 1)),) + proof[1:]]
    for changed in bad:
        with pytest.raises(ValueError):
            verify_current(tree.root, 10, changed)
    with pytest.raises(ValueError):
        verify_current(b"x" * 32, 10, proof)
    with pytest.raises(ValueError):
        verify_current(tree.root, 25, proof)


def test_child_descriptor_aggregate_and_balance_checked_even_for_pinned_root():
    tree = EvidenceAVL("qualification")
    for i in range(7):
        tree = tree.insert(report(i, i + 1))
    proof = tree.current_proof(0)
    head = proof[0]
    # A matching parent hash cannot excuse a child's inconsistent aggregate.
    forged_child = replace(head.left, best=((999, -1),))
    forged_header = replace(head, left=forged_child)
    forged_root = forged_header.descriptor().hash
    with pytest.raises(ValueError, match="commitment"):
        verify_current(forged_root, 0, (forged_header,) + proof[1:])
    with pytest.raises(ValueError, match="balance"):
        replace(head, left=replace(head.left, height=1), height=head.height + 4).descriptor()


def test_candidate_aggregate_tampering_and_absence_refused():
    tree = EvidenceAVL("candidate")
    for i in range(7):
        tree = tree.insert(Candidate(i, f"v{i}"))
    proof = tree.candidates_proof()
    head = proof[0]
    with pytest.raises(ValueError):
        verify_candidates(tree.root, (replace(head, right=replace(head.right, best=((999, "v999"),))),))
    with pytest.raises(ValueError):
        verify_candidates(tree.root, ())
    with pytest.raises(ValueError):
        verify_candidates(tree.root, proof + proof)


def test_invalid_record_duplicate_key_and_modes_refuse():
    tree = EvidenceAVL("qualification").insert(report(1, 10))
    with pytest.raises(ValueError):
        tree.insert(report(1, 10, 5))
    with pytest.raises(ValueError):
        tree.insert(Candidate(1, "version"))
    with pytest.raises(ValueError):
        tree.remove_candidate(1)
    with pytest.raises(ValueError):
        Report(True, 1, 1, "a" * 64)
    with pytest.raises(ValueError):
        Report(1, 1, 1, "not a hash")
    with pytest.raises(ValueError):
        Candidate(-1, "v")
    with pytest.raises(KeyError):
        EvidenceAVL("candidate").remove_candidate(1)
    empty = EvidenceAVL("qualification")
    assert verify_current(empty.root, 0, ()) is None
