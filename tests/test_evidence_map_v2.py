from hashlib import sha256
from dataclasses import replace
import random
import pytest
from regulated_core.evidence_map import MemorySparseMap,MapProof,MapNode,EMPTY_LEAF,verify_map_proof

def reference(items,depth=0):
    if not items:return sha256(b"regulated/evidence-map/v2:empty").digest()
    if len(items)==1:
        k,v=next(iter(items.items()))
        return sha256(b"regulated/evidence-map/v2:leaf\x00"+k+sha256(v).digest()).digest()
    left={k:v for k,v in items.items() if not (int.from_bytes(k,"big")>>(255-depth))&1}
    right={k:v for k,v in items.items() if (int.from_bytes(k,"big")>>(255-depth))&1}
    return sha256(b"regulated/evidence-map/v2:node\x00"+reference(left,depth+1)+reference(right,depth+1)).digest()

def test_random_roots_membership_absence_and_historical_proofs():
    rng=random.Random(1041);t=MemorySparseMap();values={};old=[]
    for i in range(160):
        k=sha256(str(rng.randrange(90)).encode()).digest();v=str(i).encode();values[k]=v;t.update(k,v)
        assert t.root==reference(values)
        p=t.prove(k);assert p.value==v and verify_map_proof(t.root,k,p)
        assert MapProof.from_bytes(p.bytes())==p
        old.append((t.root,k,p))
        absent=sha256(('missing'+str(i)).encode()).digest();q=t.prove(absent)
        assert q.value is None and verify_map_proof(t.root,absent,q)
        assert MapProof.from_bytes(q.bytes())==q
        assert not verify_map_proof(t.root,k,replace(p,value=b'bad'))
    for root,k,p in old:assert t.prove(k,root)==p

def test_full_depth_collision_and_singleton_collapse():
    t=MemorySparseMap();a=bytes(32);b=(1).to_bytes(32,'big')
    t.update(a,b'a');assert t.prove(a).siblings==()
    t.update(b,b'b');assert len(t.prove(a).siblings)==256
    assert t.root==reference({a:b'a',b:b'b'})
    assert verify_map_proof(t.root,b,t.prove(b))
    t.update(a,b'new');assert t.root==reference({a:b'new',b:b'b'})

def test_proof_shape_corruption_and_noncanonical_wire():
    t=MemorySparseMap();k=bytes(32);t.update(k,b'v');p=t.prove(k)
    for raw in (b' '+p.bytes(),p.bytes().replace(b'"depth":0',b'"depth":true')):
        with pytest.raises(ValueError):MapProof.from_bytes(raw)
    assert not verify_map_proof(t.root,k,replace(p,siblings=(EMPTY_LEAF,)))
    with pytest.raises(ValueError):t.update(k,b'x'*513)
    t._nodes[t.root]=MapNode(key=k,value=b'changed')
    with pytest.raises(ValueError):t.prove(k)

def test_nul_and_depth_limits():
    from regulated_core.evidence_encoding import canonical_bytes,reject_nul,RepresentationError
    with pytest.raises(RepresentationError):reject_nul({'nested':[{'bad\x00':1}]})
    v=0
    for _ in range(64):v=[v]
    canonical_bytes(v)
    with pytest.raises(RepresentationError):canonical_bytes([v])
    cycle=[];cycle.append(cycle)
    with pytest.raises(RepresentationError):canonical_bytes(cycle)
