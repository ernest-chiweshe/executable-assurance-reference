"""Proof-byte equivalence against the scalar Merkle reader; no guard mutation."""
from contextlib import contextmanager
import pytest
from regulated_core.evidence_service_pg import PostgresEvidenceService, TREE_NODE_SQL
from regulated_core.evidence_service import EvidenceError
from regulated_core.merkle import MemoryMerkleLog, inclusion_proof, consistency_proof

class ReadConnection:
    def __init__(self, reader):
        self.reader = reader
        self.active = False
        self.batches = []
    @contextmanager
    def pipeline(self):
        assert not self.active
        self.active = True
        self.batches.append([])
        try:
            yield
        finally:
            self.active = False
    def execute(self, query, params):
        assert query == TREE_NODE_SQL and params[0] == "tenant-proof"
        assert self.active
        address = params[1:]
        self.batches[-1].append(address)
        outer = self
        class Cursor:
            def fetchone(self):
                assert not outer.active, "results must be drained before validation"
                value = outer.reader(*address)
                return None if value is None else (value,)
        return Cursor()

def store():
    result = object.__new__(PostgresEvidenceService)
    result.tenant = "tenant-proof"
    return result

@pytest.mark.parametrize("size", [1,2,3,7,8,9,31,32,33,127,128,129])
def test_pipelined_proof_bytes_match_scalar_reader(size):
    tree = MemoryMerkleLog()
    for i in range(size):
        tree.append(("leaf-" + str(i)).encode())
    service = store()
    for index in range(size):
        conn = ReadConnection(tree.read_node)
        actual = service._tree_proof_on(conn, lambda read: inclusion_proof(read,index,size))
        assert actual == tree.inclusion(index)
        assert all(len(batch) <= 128 for batch in conn.batches)
    for first in range(size+1):
        conn = ReadConnection(tree.read_node)
        actual = service._tree_proof_on(conn, lambda read: consistency_proof(read,first,size))
        assert actual == tree.consistency(first)
        assert all(len(batch) <= 128 for batch in conn.batches)

@pytest.mark.parametrize("value", [None,b"",b"x"*31,b"x"*33])
def test_missing_or_malformed_subtree_refuses(value):
    with pytest.raises(EvidenceError, match="missing or malformed"):
        store()._tree_proof_on(ReadConnection(lambda level,index:value),
                              lambda read: inclusion_proof(read,0,2))

def test_maximum_postgres_tree_shape_matches_scalar_reader():
    size = (1 << 63) - 1
    def reader(level,index):
        from hashlib import sha256
        return sha256(f"{level}:{index}".encode()).digest()
    for first in (1,2,3,1<<31,(1<<62)-1,1<<62,size-1,size):
        conn=ReadConnection(reader)
        actual=store()._tree_proof_on(conn,lambda read:consistency_proof(read,first,size))
        assert actual==consistency_proof(reader,first,size)
        assert all(len(batch)<=128 for batch in conn.batches)
