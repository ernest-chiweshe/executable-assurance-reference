"""Preventive issuance ordering with synthetic local authorities and retention."""

import hashlib

import pytest

from assurance_reference.local_retention import LocalRetentionStore
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, CoursePolicy,
    Ed25519Signer, EmissionAuthority, IdentityVerifier, IntendedUse,
    IntendedUseRegistry, PolicyContext, PolicyRegistry, PreflightAuthority,
    TrustDirectory, VerificationTrustStore,
)
from regulated_core.clock import ClockReading
from regulated_core.engine import RegulatedEngine, RetentionRequired
from regulated_core.evidence import DecisionRecorder
from regulated_core.permit import InMemoryPermitUseStore,EmissionError
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, effect_destination
from regulated_core.worm import WormUnavailable, anchor_evidence_chain
from test_education_record_outage import CountingSigner


class FixtureClock:
    domain = "fixture:retention-order"

    def read(self):
        return ClockReading(self.domain, 100)

    def now_us(self):
        return 100


class BudgetedCoursePolicy(CoursePolicy):
    def mission_budget(self, action_id):
        return {"limit": 1, "units": 1}



from contextlib import nullcontext
from dataclasses import replace
from assurance_reference.shared_evidence_engine import SharedEvidenceIssuance
from assurance_reference.protected_head import FileProtectedHeadStore
from regulated_core.evidence_service import MemoryEvidenceService,sign_head,EvidenceError
from regulated_core.evidence_witness import WitnessScope,HeadPolicy,WitnessSet
from regulated_core.evidence_witness_store import DurableWitness
from regulated_core.evidence_publication import PublicationJournal,WitnessPublisher,DependencyBarrier,RetryRequired
from regulated_core.evidence_audit import EvidenceAuditor
from regulated_core.evidence_runtime import SharedEvidenceRuntime
from regulated_core.evidence_map import EMPTY
from regulated_core.evidence import GENESIS
from regulated_core.merkle import EMPTY_ROOT
from regulated_core.evidence_dependencies import observe
from regulated_core.evidence_namespace_pg import NamespaceSnapshot

class MutablePolicy(BudgetedCoursePolicy):
    deny_now=False
    def evaluate(self,*args):
        if self.deny_now:
            from regulated_core import Decision
            return Decision.deny('CHANGED','policy changed')
        return super().evaluate(*args)

class MutableClock(FixtureClock):
    value=100
    def read(self):return ClockReading(self.domain,self.value)
    def now_us(self):return self.value

class IndexedRecorder(DecisionRecorder):
    def append(self,record,record_hash):
        e=super().append(record,record_hash);self.service.append(e);return e

class TestEngine(SharedEvidenceIssuance,RegulatedEngine):
    __test__=False

@pytest.fixture
def composed(tmp_path):
    clock, trust = MutableClock(), TrustDirectory()
    keys = {role: Ed25519Signer("fixture:" + role) for role in
            ("evidence", "approval", "identity", "preflight")}
    emission = CountingSigner("fixture:emission")
    for key in (*keys.values(), emission):
        trust.register_signer(key)
    recorder = IndexedRecorder(keys["evidence"], trust, clock=clock)
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(MutablePolicy())
    operation, tenant = "course:render-lesson", "synthetic-retention"
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(keys["preflight"], intended, trust)
    uses = InMemoryPermitUseStore()
    scope=WitnessScope('tenant',tenant,'evidence')
    allowed=frozenset({keys['evidence'].key_id})
    service=MemoryEvidenceService(tenant=tenant,signer=keys['evidence'],clock=clock,trust=trust,signing_keys=allowed,historical_head_keys={},envelope_keys_allowed=allowed,envelope_domains=frozenset({clock.domain}))
    recorder.service=service
    policy=HeadPolicy(scope,clock.domain,allowed,trust)
    ws=Ed25519Signer('witness');wt=TrustDirectory();wt.register_signer(ws)
    witness=DurableWitness(tmp_path/'w.db',create=True,witness_id='w',signer=ws,trust=wt,clock=clock,policies={scope:policy})
    journal=PublicationJournal(tmp_path/'journal.db')
    protected=FileProtectedHeadStore(tmp_path/'protected',tenant=tenant,clock_domain=clock.domain,trust=trust,existing_heads={},advancing_heads=allowed)
    audit=EvidenceAuditor(policy=policy,envelope_keys_allowed=allowed,envelope_domains=frozenset({clock.domain}),journal=journal,clock=clock,signer=keys['evidence'],trust=trust,fetch_batch=lambda start,n:[service._envelopes[i] for i in range(start,start+n)])
    empty=sign_head(tenant=tenant,tree_size=0,tree_root=EMPTY_ROOT,map_root=EMPTY[0],last_entry_hash=GENESIS,previous=None,signer=keys['evidence'],clock=clock,trust=trust,signing_keys=allowed,historical_keys={})
    audit.begin(empty);assert audit.step()
    pub=WitnessPublisher(policy=policy,members=WitnessSet((('w','witness'),),0,0,1),witness_trust=wt,endpoints={'w':witness},journal=journal,protected=protected,clock=clock,head_at=lambda n:service._heads.get(n),consistency=service._tree.consistency,audit_check=audit.check)
    class Provider:
        def head_at(self,n):return service._heads.get(n)
        def leaf(self,e):return service._envelopes[e.seq],service.head,service._tree.inclusion(e.seq,service.head.tree_size)
    events=[];hooks=[]
    def final_checks(engine,prepared):
        events.append('final')
        for hook in hooks:hook()
    runtime=SharedEvidenceRuntime(publisher_for=lambda t:pub,provider_for=lambda t:Provider(),worm=LocalRetentionStore(tmp_path/'retained'),retain_us=1000000,dependency_barrier=DependencyBarrier({},lambda scope:None),final_locks=lambda p:nullcontext(),final_checks=final_checks,batch_size=1)
    engine = TestEngine(shared_evidence=runtime,registry=registry, recorder=recorder,
        verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, keys["approval"], IdentityVerifier(trust, keys["identity"].key_id)),
        emission=EmissionAuthority(emission, trust, uses), preflight=preflight, clock=clock)
    target = FilesystemTargetAdapter(path=tmp_path / "draft.txt", tenant_id=tenant,
        authority=engine.targets, uses=uses, operation_name=operation)
    body = b"Synthetic reversible draft."
    digest = hashlib.sha256(body).hexdigest()
    capability = preflight.authorize(tenant_id=tenant, vertical="course", action_id=operation,
        risk_tier=1, correlation_id="draft", now_us=100, ttl_us=1000, nonce="cap")
    parameters = dict(vertical="course", capability=capability,
        assertion=Assertion("draft", tenant, "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination({},
            BoundEffect(digest, target.target, target.current_state(), mission="fixture:mission"))),
        ctx=PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft", "draft", 100),
        output=body, target=target, permit_ttl_us=1000)
    return engine,parameters,emission,clock,pub,witness,service,events,hooks


def test_real_issuer_waits_for_durable_witness_and_full_retention(composed):
    engine,p,signer,clock,pub,w,service,events,_=composed
    original=w.request
    def delayed(request):
        assert signer.calls==0
        assert service.head is not None and pub.journal.watermark()[0]==1
        clock.value+=25;events.append('witness');return original(request)
    w.request=delayed
    result=engine.authorize_for_target(**p,nonce='allowed')
    assert result.authorized and signer.calls==1
    assert events==['witness','final'] and result.permit.permit.issued_at_us==125
    assert pub.protected.read()==service.head
    assert engine.shared_evidence.receipt_for(p['ctx'].tenant_id,0).content_digest
    pub.close()

@pytest.mark.parametrize('change',['deadline','policy','new_dependency','target','nonce','audit'])
def test_final_changes_never_reach_real_signer(composed,change):
    engine,p,signer,clock,pub,w,service,events,hooks=composed
    original=w.request
    def delayed(request):
        reply=original(request)
        if change=='deadline':clock.value=2000
        if change=='policy':engine._registry.resolve('course:lesson').deny_now=True
        if change=='new_dependency':hooks.append(lambda:observe(WitnessScope('tenant','other','budget'),NamespaceSnapshot(1,b'a'*32,b'b'*32,'0'*64)))
        if change=='target':p['target'].path.write_bytes(b'concurrent writer')
        if change=='nonce':engine._emission.uses.consume(p['ctx'].tenant_id,'changed')
        if change=='audit':pub.audit_check=lambda:(_ for _ in ()).throw(EvidenceError('audit stale'))
        return reply
    w.request=delayed
    try:
        result=engine.authorize_for_target(**p,nonce='changed')
        assert not result.authorized
    except (EvidenceError,RetentionRequired,EmissionError):pass
    assert signer.calls==0
    pub.close()


def test_target_authority_late_dependency_cannot_reach_signer(composed):
    engine,p,signer,clock,pub,w,service,events,hooks=composed
    original=engine.targets._epoch;calls=[]
    def epoch(tenant):
        calls.append(tenant)
        if len(calls)>=3:observe(WitnessScope('tenant',tenant,'budget'),NamespaceSnapshot(1,b'a'*32,b'b'*32,'0'*64))
        return original(tenant)
    engine.targets._epoch=epoch
    with pytest.raises(RetryRequired):engine.authorize_for_target(**p,nonce='late')
    assert signer.calls==0
    pub.close()
