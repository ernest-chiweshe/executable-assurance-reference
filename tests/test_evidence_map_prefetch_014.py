"""Bounded pipelining retains node, path, tenant and append lifetime checks."""
from contextlib import contextmanager
from hashlib import sha256
import pytest
from regulated_core import evidence_service_pg as pg
from regulated_core.evidence_map import MemorySparseMap,MapNode,node_digest,EMPTY,verify_map_proof
from regulated_core.evidence_service import EvidenceError

class Connection:
    def __init__(self,nodes):self.nodes=nodes;self.in_pipeline=False;self.rounds=[];self.reads=[];self.fault=None
    @contextmanager
    def pipeline(self):
        assert not self.in_pipeline
        self.in_pipeline=True;self.rounds.append(0)
        try:yield
        finally:self.in_pipeline=False
    def execute(self,sql,params):
        assert sql==pg.MAP_PROOF_SQL
        self.reads.append(params)
        if self.in_pipeline:self.rounds[-1]+=1
        node=self.nodes[params[1]];connection=self
        class Reply:
            def fetchone(self):
                assert not connection.in_pipeline
                if connection.fault=='missing':return None
                if connection.fault=='shape':return ('bad',None,None,None,None)
                if connection.fault=='hash':return ('leaf',None,None,b'z'*32,b'bad')
                return ('leaf',None,None,node.key,node.value) if node.key is not None else ('node',node.left,node.right,None,None)
        return Reply()

def fixture_tree():
    tree=MemorySparseMap()
    keys=[sha256(str(i).encode()).digest() for i in range(64)]
    for i,key in enumerate(keys):tree.update(key,str(i).encode())
    return tree,keys

def test_prefetch_proofs_match_complete_verified_paths_with_bounded_rounds():
    tree,keys=fixture_tree();wanted=tuple(keys[:6]+[b'x'*32,b'y'*32]);c=Connection(tree._nodes)
    with pg._map_read_scope(c,'a'):
        pg._prefetch_map_paths_on(c,'a',tree.root,wanted)
        before=len(c.reads);local=MemorySparseMap(reader=pg._map_reader(c,'a'));local.root=tree.root
        for key in wanted:
            proof=local.prove(key)
            assert proof==tree.prove(key) and verify_map_proof(tree.root,key,proof)
        assert len(c.reads)==before
        assert len(c.rounds)<=257 and max(c.rounds)<=8 and len(c.reads)<=8*257
        assert len(c.reads)==len(set(c.reads))
    assert pg._MAP_READ_SCOPE.get() is None

@pytest.mark.parametrize('scope',['absent','tenant','connection'])
def test_prefetch_refuses_wrong_scope_without_database_read(scope):
    tree,keys=fixture_tree();c=Connection(tree._nodes);other=Connection(tree._nodes)
    if scope=='absent':
        with pytest.raises(EvidenceError):pg._prefetch_map_paths_on(c,'a',tree.root,tuple(keys[:2]))
    else:
        with pg._map_read_scope(c,'a'):
            with pytest.raises(EvidenceError):pg._prefetch_map_paths_on(other if scope=='connection' else c,'b' if scope=='tenant' else 'a',tree.root,tuple(keys[:2]))
    assert not c.reads and not other.reads

@pytest.mark.parametrize('fault',['missing','shape','hash'])
def test_bad_prefetch_reply_never_survives_failed_append(fault):
    tree,keys=fixture_tree();c=Connection(tree._nodes);c.fault=fault
    with pytest.raises((EvidenceError,ValueError)):
        with pg._map_read_scope(c,'a'):pg._prefetch_map_paths_on(c,'a',tree.root,tuple(keys[:2]))
    assert pg._MAP_READ_SCOPE.get() is None
    c.fault=None
    with pg._map_read_scope(c,'a'):
        pg._prefetch_map_paths_on(c,'a',tree.root,tuple(keys[:2]))
        assert pg._map_reader(c,'a')(tree.root)==tree._nodes[tree.root]

def test_prefetch_rejects_oversized_batch_before_reading():
    tree,keys=fixture_tree();c=Connection(tree._nodes)
    with pg._map_read_scope(c,'a'):
        with pytest.raises(EvidenceError):pg._prefetch_map_paths_on(c,'a',tree.root,tuple(keys[:9]))
    assert not c.reads

def test_prefetch_rejects_branch_beyond_depth_256():
    nodes={};leaf=MapNode(key=b'\x00'*32,value=b'x');digest=node_digest(leaf);nodes[digest]=leaf
    for _ in range(257):
        n=MapNode(left=digest,right=EMPTY[0]);digest=node_digest(n);nodes[digest]=n
    c=Connection(nodes)
    with pytest.raises(EvidenceError):
        with pg._map_read_scope(c,'a'):pg._prefetch_map_paths_on(c,'a',digest,(b'\x00'*32,))
    assert len(c.rounds)==257 and len(c.reads)==257
