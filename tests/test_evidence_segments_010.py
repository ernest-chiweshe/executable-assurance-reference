import base64
from types import SimpleNamespace
import pytest
from regulated_core.evidence_segments import SegmentCompactor
from regulated_core.evidence_encoding import loads,canonical_bytes
from regulated_core.evidence_service import EvidenceError
from assurance_reference.local_retention import LocalRetentionStore
from test_evidence_publication_010 import runtime
from test_evidence_service_formats import case

@pytest.fixture
def segment(runtime,tmp_path):
    pub,_,_,tree,heads,envs,clock=runtime;worm=LocalRetentionStore(tmp_path/"segments-worm")
    for seq,env in enumerate(envs):pub.retain(seq=seq,raw=canonical_bytes(env),head=heads[-1],inclusion=tree.inclusion(seq,3),worm=worm,retain_us=100000)
    provider=SimpleNamespace(head_at=lambda n:heads[n-1],inclusion=tree.inclusion)
    return SegmentCompactor(journal=pub.journal,provider=provider,policy=pub.policy,worm=worm,clock=clock,retain_us=100000,segment_size=2),envs,clock

def test_segments_preserve_exact_full_bodies_and_renew_without_removing_originals(segment):
    worker,envs,clock=segment;first=worker.step();assert worker.step() is None
    body=loads(worker.worm.fetch('tenant',first.object_ref))
    assert [base64.b64decode(x) for x in body['envelopes']]==[canonical_bytes(e) for e in envs[:2]]
    assert worker.step(include_partial=True) is not None
    clock.value+=1;new=worker.renew(0,2);assert new.content_digest==first.content_digest and new.retained_until_us>first.retained_until_us
    clock.value+=1
    assert worker.renew_batch(0,1)==(2,False)
    assert worker.renew_batch(2,1)==(3,True)
    with worker.journal.connect() as c:assert c.execute('SELECT count(*) FROM retained').fetchone()[0]==3

def test_segment_invalid_inclusion_refuses_without_advancing(segment):
    worker,_,_=segment;worker.provider.inclusion=lambda *a:()
    with pytest.raises(EvidenceError):worker.step()
    with worker.journal.connect() as c:assert c.execute('SELECT count(*) FROM segments').fetchone()[0]==0

def test_segment_byte_cap_and_expired_renewal_refuse(segment):
    worker,_,clock=segment;worker.max_bytes=1024
    with pytest.raises(EvidenceError):worker.step()
    worker.max_bytes=67108864;receipt=worker.step();clock.value=receipt.retained_until_us
    with pytest.raises(EvidenceError):worker.renew(0,2)
