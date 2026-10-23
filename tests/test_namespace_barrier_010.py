from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
import pytest
from regulated_core.evidence_namespace import Transition,advance_chain,sign_namespace_head
from regulated_core.evidence_audit import NamespaceAuditor
from regulated_core.evidence_map import MemorySparseMap
from regulated_core.evidence import GENESIS
from regulated_core.evidence_service import EvidenceError
from regulated_core.evidence_publication import PublicationJournal,Dependency,DependencyBarrier,RetryRequired
from regulated_core.evidence_witness import WitnessScope,HeadPolicy
from regulated_core.merkle import MemoryMerkleLog
from test_evidence_service_formats import case

@pytest.fixture
def namespace(case,tmp_path):
    clock,signer,_,trust,keys,*_=case;scope=WitnessScope('tenant','tenant','budget')
    tree=MemoryMerkleLog();mapping=MemorySparseMap();chain=GENESIS;heads=[];rows=[]
    for i in range(3):
        raw=f'signed-source-{i}'.encode();t=Transition('tenant','tenant','budget',sha256(str(i).encode()).hexdigest(),i,'a'*64,sha256(raw).hexdigest())
        tree.append(t.bytes());mapping.update(bytes.fromhex(t.key),t.state_value().bytes());chain=advance_chain(chain,t);rows.append((t.bytes(),raw))
        heads.append(sign_namespace_head(**scope.fields(),version=i+1,tree_root=tree.root(),map_root=mapping.root,chain=chain,previous=heads[-1] if heads else None,consistency=tree.consistency(i,i+1),signer=signer,clock=clock,trust=trust,signing_keys=keys,historical_keys={}))
    policy=HeadPolicy(scope,clock.domain,keys,trust);journal=PublicationJournal(tmp_path/'audit.db')
    auditor=NamespaceAuditor(policy=policy,envelope_keys_allowed=keys,envelope_domains=frozenset({clock.domain}),journal=journal,clock=clock,signer=signer,trust=trust,fetch_batch=lambda start,n:rows[start:start+n],verify_source=lambda t,s:s.startswith(b'signed-source-'))
    return scope,tree,heads,rows,policy,journal,auditor

def test_full_namespace_audit_verifies_source_chain_state_and_progress(namespace):
    scope,tree,heads,rows,policy,journal,auditor=namespace
    auditor.begin(heads[-1]);assert not auditor.step(1)
    with pytest.raises(EvidenceError):auditor.check()
    assert auditor.step(2);auditor.check()
    with pytest.raises(EvidenceError):auditor.step()

@pytest.mark.parametrize('damage',['source','tree','state','chain'])
def test_namespace_corruption_latches(namespace,damage):
    scope,tree,heads,rows,policy,journal,auditor=namespace;head=heads[-1]
    if damage=='source':rows[0]=(rows[0][0],b'changed')
    else:
        field={'tree':'tree_root','state':'map_root','chain':'chain'}[damage]
        head=replace(head,**{field:'f'*64});head=replace(head,signature=auditor.signer.sign(head.body()))
    auditor.begin(head)
    with pytest.raises(EvidenceError):auditor.step()
    with pytest.raises(EvidenceError):journal.check()

def test_dependency_exact_roots_sealed_version_and_extension(namespace):
    scope,tree,heads,rows,policy,journal,auditor=namespace;published=[]
    pub=SimpleNamespace(policy=policy,journal=journal,head_at=lambda n:heads[n-1] if n<=3 else None,consistency=tree.consistency,publish=published.append)
    barrier=DependencyBarrier({scope:pub},lambda s:heads[-1]);h=heads[0]
    dep=Dependency(scope,1,bytes.fromhex(h.tree_root),bytes.fromhex(h.map_root),'read')
    barrier(None,(dep,));assert published==[heads[-1]]
    with pytest.raises(RetryRequired):barrier(None,(replace(dep,version=4),))
    journal.check()
    with pytest.raises(EvidenceError):barrier(None,(replace(dep,state_root=b'x'*32),))
    with pytest.raises(EvidenceError):journal.check()
