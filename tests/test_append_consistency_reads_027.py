"""Append overlay proof equivalence and malformed old-node refusal, intact guards."""
import pytest
from regulated_core.merkle import Frontier, MemoryMerkleLog, consistency_proof, verify_consistency
from regulated_core.evidence_service import EvidenceError
from test_batched_merkle_reads_025 import ReadConnection, store

@pytest.mark.parametrize("size", [0,1,2,3,7,8,9,31,32,33,127,128,129,511,512,513,2039])
def test_append_overlay_matches_authenticated_scalar_proof(size):
    tree, frontier = MemoryMerkleLog(), Frontier()
    for i in range(size):
        raw = f"old-leaf-{i}".encode()
        tree.append(raw)
        frontier, _ = frontier.append(raw)
    old_root = frontier.root
    frontier, completed = frontier.append(b"new-leaf")
    overlay = {(n.level,n.index): n.digest for n in completed}
    old_addresses = []
    def old_reader(level,index):
        assert (level,index) not in overlay, "new nodes must not be read from old storage"
        old_addresses.append((level,index))
        return tree.read_node(level,index)
    conn = ReadConnection(old_reader)
    actual = store()._append_consistency_on(conn,size,overlay)
    tree.append(b"new-leaf")
    assert actual == tree.consistency(size)
    assert verify_consistency(size,size+1,old_root,frontier.root,actual)
    assert old_addresses == [address for batch in conn.batches for address in batch]
    assert all(len(batch)<=128 for batch in conn.batches)
    if size == 0:
        assert not conn.batches

@pytest.mark.parametrize("value", [None,b"",b"x"*31,b"x"*33])
def test_append_missing_or_malformed_old_node_refuses(value):
    with pytest.raises(EvidenceError,match="missing or malformed"):
        store()._append_consistency_on(ReadConnection(lambda level,index:value),3,{})

def test_append_maximum_admitted_shape_matches_scalar():
    from hashlib import sha256
    size=(1<<63)-2
    overlay={(0,size):sha256(b"new").digest()}
    def old_reader(level,index):
        assert (level,index) not in overlay
        return sha256(f"{level}:{index}".encode()).digest()
    def scalar(level,index):
        return overlay[(level,index)] if (level,index) in overlay else old_reader(level,index)
    conn=ReadConnection(old_reader)
    assert store()._append_consistency_on(conn,size,overlay)==consistency_proof(scalar,size,size+1)
    assert all(len(batch)<=128 for batch in conn.batches)
