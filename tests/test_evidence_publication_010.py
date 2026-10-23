from dataclasses import replace
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
import pytest
from regulated_core.canonical import canonical_bytes
from regulated_core.signing import Ed25519Signer,TrustDirectory
from regulated_core.evidence_service import EvidenceError
from regulated_core.evidence_witness import HeadPolicy,WitnessScope,WitnessSet,WitnessAck,WitnessReack,WitnessRequest,Checkpoint
from regulated_core.evidence_witness_store import DurableWitness
from regulated_core.evidence_publication import PublicationJournal,WitnessPublisher,PermitGate,Dependency,RetryRequired
from regulated_core.worm import LocalWormStore
from assurance_reference.protected_head import FileProtectedHeadStore
from test_evidence_service_formats import case

@pytest.fixture
def runtime(case,tmp_path):
    clock,signer,_,trust,keys,tree,heads,envs=case
    scope=WitnessScope('tenant','tenant','evidence');policy=HeadPolicy(scope,clock.domain,keys,trust)
    ws=Ed25519Signer('witness');wt=TrustDirectory();wt.register_signer(ws)
    kw=dict(witness_id='w',signer=ws,trust=wt,clock=clock,policies={scope:policy})
    endpoint=DurableWitness(tmp_path/'witness.db',create=True,**kw)
    journal=PublicationJournal(tmp_path/'journal.db')
    protected=FileProtectedHeadStore(tmp_path/'protected',tenant='tenant',clock_domain=clock.domain,trust=trust,existing_heads={},advancing_heads=keys)
    pub=WitnessPublisher(policy=policy,members=WitnessSet((('w','witness'),),0,0,1),witness_trust=wt,endpoints={'w':endpoint},journal=journal,protected=protected,clock=clock,head_at=lambda n:heads[n-1] if 0<n<=len(heads) else None,consistency=tree.consistency,audit_check=lambda:None)
    return pub,endpoint,kw,tree,heads,envs,clock

def retain(runtime,seq):
    pub,_,_,tree,heads,envs,_=runtime
    return pub.retain(seq=seq,raw=canonical_bytes(envs[seq]),head=heads[-1],inclusion=tree.inclusion(seq,3),worm=LocalWormStore(),retain_us=100000)

def test_out_of_order_retention_never_publishes_gap_and_reopen(runtime):
    pub,w,kw,tree,heads,_,_=runtime
    retain(runtime,2)
    with pytest.raises(EvidenceError):pub.publish(heads[-1])
    retain(runtime,0)
    assert pub.publish(heads[0])==heads[0]
    retain(runtime,1)
    assert pub.publish(heads[-1])==heads[-1]
    reopened=DurableWitness(w.path,**kw)
    req=WitnessRequest('a'*32,pub.policy.scope,None,heads[-1],())
    assert type(reopened.request(req)) is WitnessReack
    assert len(reopened.ack_range(pub.policy.scope,'0'*64))==2
    assert pub.protected.read()==heads[-1]

def test_lost_ack_reply_reconciles_and_old_request_does_not_latch(runtime):
    pub,w,_,tree,heads,_,_=runtime
    for seq in range(3):retain(runtime,seq)
    w.request(WitnessRequest('a'*32,pub.policy.scope,None,heads[-1],tree.consistency(0,3)))
    with pytest.raises(RetryRequired):pub.publish(heads[0])
    pub.journal.check()
    assert pub.publish(heads[-1])==heads[-1]

def test_local_rollback_latches_persistently(runtime):
    pub,w,_,tree,heads,_,_=runtime
    for seq in range(3):retain(runtime,seq)
    pub.publish(heads[-1]);pub.head_at=lambda n:heads[0] if n==1 else None
    with pytest.raises(EvidenceError):pub.publish(heads[0])
    with pytest.raises(EvidenceError):PublicationJournal(pub.journal.path).check()

def test_witness_concurrent_identical_requests_commit_once(runtime):
    pub,w,_,tree,heads,_,_=runtime
    def send(i):return w.request(WitnessRequest(f'{i:032x}',pub.policy.scope,None,heads[-1],tree.consistency(0,3)))
    with ThreadPoolExecutor(max_workers=8) as pool:responses=list(pool.map(send,range(8)))
    assert sum(type(x) is WitnessAck for x in responses)==1
    assert sum(type(x) is WitnessReack for x in responses)==7
    assert len(w.ack_range(pub.policy.scope,'0'*64))==1

def test_lost_witness_file_is_not_silently_enrolled(runtime,tmp_path):
    _,_,kw,*_=runtime
    with pytest.raises(EvidenceError):DurableWitness(tmp_path/'absent.db',**kw)

def test_replayed_latest_refuses_without_permit(runtime):
    pub,w,*_=runtime
    for seq in range(3):retain(runtime,seq)
    old=w.latest(pub.policy.scope,'a'*32)
    w.latest=lambda scope,nonce:old
    with pytest.raises(EvidenceError):pub.publish(runtime[4][-1])
    assert pub.protected.read() is None

def test_final_dependency_invalidation_and_fresh_clock(runtime):
    clock=runtime[-1];scope=runtime[0].policy.scope;dep=Dependency(scope,1,b'a'*32,b'b'*32,'read');other=replace(dep,version=2)
    events=[]
    def cover(op,deps):events.append('cover');clock.value+=50
    gate=PermitGate(clock=clock,cover=cover,locks=lambda op:nullcontext(),final_checks=lambda op,now:(other,),release=lambda op:events.append('release'))
    with pytest.raises(RetryRequired):gate.issue('op',(dep,),deadline_us=10000,sign=lambda now:events.append('signed'))
    assert events==['cover','release']
    gate.final_checks=lambda op,now:(dep,)
    before=clock.value
    assert gate.issue('op',(dep,),deadline_us=10000,sign=lambda now:now.now_us)==before+50

def test_expiry_during_witness_wait_refuses(runtime):
    clock=runtime[-1];events=[]
    gate=PermitGate(clock=clock,cover=lambda *args:setattr(clock,'value',1000),locks=lambda op:nullcontext(),final_checks=lambda *args:(),release=lambda op:events.append('release'))
    with pytest.raises(EvidenceError):gate.issue('op',(),deadline_us=900,sign=lambda now:events.append('signed'))
    assert events==['release']
