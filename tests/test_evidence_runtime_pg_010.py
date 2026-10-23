from dataclasses import replace
from contextlib import contextmanager
from hashlib import sha256
import pytest
from regulated_core.canonical import digest_hex,canonical_bytes
from regulated_core.evidence_runtime_pg import backfill_batch_on,PostgresEvidenceProvider
from regulated_core.evidence_service import EvidenceError
from assurance_reference.evidence_recorder import SharedEvidenceRecorder
from test_evidence_service_pg_core import database,service,transaction,case

class Pool:
    def __init__(self,dsn):self.dsn=dsn
    @contextmanager
    def connection(self):
        import psycopg
        with psycopg.connect(self.dsn) as conn:yield conn

def test_backfill_is_bounded_idempotent_and_preserves_all_signed_bytes(database,service):
    store,recorder,record,kwargs=service;original=[]
    with transaction(database,store.tenant) as conn:
        for i in range(7):
            r=replace(record,record_id=str(i));original.append(recorder._append_on(conn,r,digest_hex(r)))
        before=conn.execute('SELECT envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s ORDER BY seq',(store.tenant,)).fetchall()
        head,count=backfill_batch_on(conn,service=store,recorder=recorder,limit=3)
        assert count==3 and head.tree_size==3
        head,count=backfill_batch_on(conn,service=store,recorder=recorder,limit=3)
        assert count==3 and head.tree_size==6
        head,count=backfill_batch_on(conn,service=store,recorder=recorder,limit=3)
        assert count==1 and head.tree_size==7
        assert backfill_batch_on(conn,service=store,recorder=recorder,limit=3)[1]==0
        after=conn.execute('SELECT envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s ORDER BY seq',(store.tenant,)).fetchall()
        assert before==after
    provider=PostgresEvidenceProvider(store,Pool(database))
    for env in original:
        raw,head,path=provider.leaf(env)
        assert raw==canonical_bytes(env) and head.tree_size==7
    assert provider.consistency(3,7)

def test_reference_recorder_keeps_age_checks_and_companion_atomicity(database,service):
    store,recorder,record,kwargs=service
    shared=SharedEvidenceRecorder(recorder._signer,recorder._trust,pool=Pool(database),clock=store.clock,service_for=lambda tenant:store,max_record_age_us=100)
    with transaction(database,store.tenant) as conn:
        r=replace(record,decided_at_us=store.clock.value)
        env=shared._append_on(conn,r,digest_hex(r));assert store.head_on(conn).tree_size==1
        from regulated_core.clock import ClockError
        stale=replace(r,record_id='stale',decided_at_us=0)
        with pytest.raises(ClockError):shared._append_on(conn,stale,digest_hex(stale))
        assert store.head_on(conn).tree_size==1
    assert PostgresEvidenceProvider(store,Pool(database)).leaf(env)[0]==canonical_bytes(env)


def test_oversized_new_body_refuses_atomically_and_delta_checks_bounds(database,service):
    store,recorder,record,kwargs=service
    huge=replace(record,record_id='x'*1048576)
    with transaction(database,store.tenant) as conn:
        with pytest.raises(EvidenceError):store.append_record_on(conn,recorder,huge,digest_hex(huge))
        assert store.head_on(conn) is None
        assert conn.execute('SELECT count(*) FROM regulated_decision_evidence_v1 WHERE tenant=%s',(store.tenant,)).fetchone()[0]==0
        env,head=store.append_record_on(conn,recorder,record,digest_hex(record))
    provider=PostgresEvidenceProvider(store,Pool(database))
    assert provider.delta(0,1)[0][1]==canonical_bytes(env)
    for start,end,limit in [(0,257,256),(0,1,True),(-1,0,1),(0,2,1)]:
        with pytest.raises(EvidenceError):provider.delta(start,end,limit=limit)


def test_existing_history_backfill_audit_retention_witness_and_restart(database,service,tmp_path):
    from regulated_core.evidence_publication import PublicationJournal,WitnessPublisher
    from regulated_core.evidence_witness import WitnessScope,HeadPolicy,WitnessSet
    from regulated_core.evidence_witness_store import DurableWitness
    from regulated_core.evidence_audit import EvidenceAuditor
    from regulated_core.evidence_segments import SegmentCompactor
    from regulated_core.signing import Ed25519Signer,TrustDirectory
    from assurance_reference.local_retention import LocalRetentionStore
    from assurance_reference.protected_head import FileProtectedHeadStore
    store,recorder,record,kwargs=service
    with transaction(database,store.tenant) as conn:
        for i in range(7):
            r=replace(record,record_id=str(i));recorder._append_on(conn,r,digest_hex(r))
        originals=conn.execute('SELECT envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s ORDER BY seq',(store.tenant,)).fetchall()
        for n in (3,3,1):assert backfill_batch_on(conn,service=store,recorder=recorder,limit=3)[1]==n
    provider=PostgresEvidenceProvider(store,Pool(database));head=provider.current_head()
    policy=HeadPolicy(WitnessScope('tenant',store.tenant,'evidence'),store.clock.domain,store.signing_keys,store.trust)
    journal=PublicationJournal(tmp_path/'bootstrap.db');worm=LocalRetentionStore(tmp_path/'bootstrap-worm')
    audit=EvidenceAuditor(policy=policy,envelope_keys_allowed=store.envelope_keys_allowed,envelope_domains=store.envelope_domains,journal=journal,clock=store.clock,signer=store.signer,trust=store.trust,fetch_batch=provider.audit_batch)
    protected=FileProtectedHeadStore(tmp_path/'protected',tenant=store.tenant,clock_domain=store.clock.domain,trust=store.trust,existing_heads={},advancing_heads=store.signing_keys)
    ws=Ed25519Signer('bootstrap-w');wt=TrustDirectory();wt.register_signer(ws)
    witness=DurableWitness(tmp_path/'witness.db',create=True,witness_id='w',signer=ws,trust=wt,clock=store.clock,policies={policy.scope:policy})
    pub=WitnessPublisher(policy=policy,members=WitnessSet((('w',ws.key_id),),0,0,1),witness_trust=wt,endpoints={'w':witness},journal=journal,protected=protected,clock=store.clock,head_at=provider.head_at,consistency=provider.consistency,audit_check=audit.check)
    try:
        with pytest.raises(EvidenceError):pub.publish(head)
        audit.begin(head)
        while not audit.step(3):pass
        for seq,raw,h,path in provider.delta(0,7):pub.retain(seq=seq,raw=raw,head=h,inclusion=path,worm=worm,retain_us=1000000)
        segment=SegmentCompactor(journal=journal,provider=provider,policy=policy,worm=worm,clock=store.clock,retain_us=1000000)
        assert segment.step(include_partial=True) is not None
        assert pub.publish(head)==head
        assert FileProtectedHeadStore(tmp_path/'protected',tenant=store.tenant,clock_domain=store.clock.domain,trust=store.trust,existing_heads={},advancing_heads=store.signing_keys).read()==head
        assert PublicationJournal(journal.path).watermark()[0]==7
        with transaction(database,store.tenant) as conn:
            assert conn.execute('SELECT envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s ORDER BY seq',(store.tenant,)).fetchall()==originals
    finally:pub.close()
