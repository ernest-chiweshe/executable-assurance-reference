from dataclasses import replace
import pytest
from test_evidence_service_formats import case
from regulated_core.evidence_service import MemoryEvidenceService,EvidenceError
from regulated_core.evidence_witness import HeadPolicy,WitnessScope
from regulated_core.evidence_publication import PublicationJournal
from regulated_core.evidence_audit import EvidenceAuditor
from regulated_core.evidence_encoding import canonical_bytes

@pytest.fixture
def auditor(case,tmp_path):
    clock,signer,_,trust,keys,_,_,envs=case
    service=MemoryEvidenceService(tenant='tenant',signer=signer,clock=clock,trust=trust,signing_keys=keys,historical_head_keys={},envelope_keys_allowed=keys,envelope_domains=frozenset({clock.domain}))
    heads=[service.append(e) for e in envs];raw=[canonical_bytes(e) for e in envs]
    policy=HeadPolicy(WitnessScope('tenant','tenant','evidence'),clock.domain,keys,trust)
    journal=PublicationJournal(tmp_path/'audit.db')
    a=EvidenceAuditor(policy=policy,envelope_keys_allowed=keys,envelope_domains=frozenset({clock.domain}),journal=journal,clock=clock,signer=signer,trust=trust,fetch_batch=lambda start,n:raw[start:start+n],heartbeat_us=100,sweep_us=1000)
    return a,heads[-1],raw,clock

def test_complete_sweep_then_progress_and_completion_deadlines(auditor):
    a,head,raw,clock=auditor
    with pytest.raises(EvidenceError):a.check()
    a.begin(head);assert not a.step(1)
    with pytest.raises(EvidenceError):a.check()
    assert a.step(2);a.check()
    clock.value+=101
    with pytest.raises(EvidenceError):a.check()
    a.begin(head);assert a.step(3);a.check()

def test_missing_and_modified_history_latches(auditor):
    a,head,raw,_=auditor;a.begin(head)
    raw[0]=raw[0].replace(b'FIXTURE',b'CHANGED')
    with pytest.raises(EvidenceError):a.step()
    with pytest.raises(EvidenceError):a.journal.check()

def test_same_prefix_tree_with_wrong_state_root_refuses(auditor):
    a,head,raw,_=auditor
    from regulated_core.evidence_service import sign_head
    wrong=replace(head,map_root=(b'x'*32).hex())
    wrong=replace(wrong,signature=a.signer.sign(wrong.body()))
    a.begin(wrong)
    with pytest.raises(EvidenceError):a.step()

def test_progress_restart_never_counts_partial_sweep_as_complete(auditor):
    a,head,_,_=auditor;a.begin(head);a.step(1)
    with pytest.raises(EvidenceError):a.check()
    a.begin(head);assert a.step();a.check()


def test_completed_sweep_cannot_refresh_deadline_without_replaying(auditor):
    a,head,_,clock=auditor;a.begin(head);assert a.step()
    clock.value+=101
    with pytest.raises(EvidenceError):a.step()
    with pytest.raises(EvidenceError):a.check()
