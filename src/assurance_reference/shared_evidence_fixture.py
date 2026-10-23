"""Explicit local protocol fixture for the unchanged governed-action benchmark.

One local witness demonstrates protocol and persistence, not independent custody.
This fixture covers the tenant evidence log; nine namespace adapters require
separate host composition and qualification. It cannot activate production.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import threading
import atexit
from regulated_core.signing import Ed25519Signer,TrustDirectory
from regulated_core.evidence_service_pg import PostgresEvidenceService
from regulated_core.evidence_runtime_pg import PostgresEvidenceProvider
from regulated_core.evidence_runtime import SharedEvidenceRuntime
from regulated_core.evidence_publication import PublicationJournal,WitnessPublisher,DependencyBarrier
from regulated_core.evidence_witness import WitnessScope,HeadPolicy,WitnessSet
from regulated_core.evidence_witness_store import DurableWitness
from regulated_core.evidence_audit import EvidenceAuditor,AuditRunner
from regulated_core.evidence_segments import SegmentCompactor
from regulated_core.evidence_renewal import RetentionRenewal
from regulated_core.evidence_service import sign_head,EvidenceError
from regulated_core.evidence_map import EMPTY
from regulated_core.merkle import EMPTY_ROOT
from regulated_core.evidence import GENESIS
from assurance_reference.evidence_recorder import SharedEvidenceRecorder
from assurance_reference.protected_head import FileProtectedHeadStore


def configure_shared_fixture(stores,authorities,roles,directory,*,register_cleanup=None):
    """Register fixture cleanup with its owner; process lifetime remains the default."""
    if register_cleanup is not None and not callable(register_cleanup):
        raise ValueError("fixture cleanup registrar must be callable")
    clock=authorities.clock;trust=authorities.trust;old=stores.recorder;pool=old._pool
    head_signer=Ed25519Signer('fixture:shared-head');audit_signer=Ed25519Signer('fixture:shared-audit')
    trust.register_signer(head_signer);trust.register_signer(audit_signer)
    witness_signer=Ed25519Signer('fixture:shared-witness');wt=TrustDirectory();wt.register_signer(witness_signer)
    keys=frozenset({head_signer.key_id});envelope_keys=frozenset({old._signer.key_id});services={};providers={};publishers={};runners={};maintenance={}
    lock=threading.RLock();stop=threading.Event();local=ContextVar('shared_fixture_final_connection',default=None)
    def service_for(tenant):
        with lock:
            if tenant not in services:
                if len(services)>=64:raise EvidenceError('fixture tenant bound')
                services[tenant]=PostgresEvidenceService(tenant=tenant,signer=head_signer,clock=clock,trust=trust,signing_keys=keys,historical_head_keys={},envelope_keys_allowed=envelope_keys,envelope_domains=frozenset({clock.domain}))
                providers[tenant]=PostgresEvidenceProvider(services[tenant],pool)
            return services[tenant]
    def provider_for(tenant):service_for(tenant);return providers[tenant]
    def publisher_for(tenant):
        with lock:
            if tenant in publishers:return publishers[tenant]
            provider=provider_for(tenant);scope=WitnessScope('tenant',tenant,'evidence');policy=HeadPolicy(scope,clock.domain,keys,trust)
            root=Path(directory)/'shared-evidence'/sha256(tenant.encode()).hexdigest();fresh=not root.exists();journal=PublicationJournal(root/'journal.db')
            witness=DurableWitness(root/'witness.db',create=fresh,witness_id='fixture-w',signer=witness_signer,trust=wt,clock=clock,policies={scope:policy})
            protected=FileProtectedHeadStore(root/'protected',tenant=tenant,clock_domain=clock.domain,trust=trust,existing_heads={},advancing_heads=keys)
            auditor=EvidenceAuditor(policy=policy,envelope_keys_allowed=envelope_keys,envelope_domains=frozenset({clock.domain}),journal=journal,clock=clock,signer=audit_signer,trust=trust,fetch_batch=provider.audit_batch)
            empty=sign_head(tenant=tenant,tree_size=0,tree_root=EMPTY_ROOT,map_root=EMPTY[0],last_entry_hash=GENESIS,previous=None,signer=head_signer,clock=clock,trust=trust,signing_keys=keys,historical_keys={})
            # Explicit fresh fixture bootstrap. Existing histories require full
            # backfill/audit before this fixture is constructed.
            current=provider.current_head()
            if current is not None and current.tree_size>1:raise EvidenceError('fixture bootstrap requires empty history')
            auditor.begin(empty);auditor.step()
            runners[tenant]=AuditRunner(auditor,lambda:provider.current_head() or empty)
            pub=WitnessPublisher(policy=policy,members=WitnessSet((('fixture-w',witness_signer.key_id),),0,0,1),witness_trust=wt,endpoints={'fixture-w':witness},journal=journal,protected=protected,clock=clock,head_at=provider.head_at,consistency=provider.consistency,audit_check=auditor.check)
            publishers[tenant]=pub
            maintenance[tenant]=(SegmentCompactor(journal=journal,provider=provider,policy=policy,worm=authorities.worm,clock=clock,retain_us=7*365*86400000000),RetentionRenewal(journal=journal,worm=authorities.worm,tenant=tenant,clock=clock,retain_us=7*365*86400000000),[clock.read().now_us,None])
            return pub
    @contextmanager
    def final_locks(prepared):
        with roles.receiver.connection() as conn,conn.transaction():
            tenant=prepared.ctx.tenant_id
            conn.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
            # Authority before mission, matching the existing receiving order.
            for key in ('regulated-revocation:'+tenant,'regulated-mission-budget:'+tenant+'\x1f'+prepared.mission):
                conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(key,))
            token=local.set(conn)
            try:yield
            finally:local.reset(token)
    def final_checks(engine,prepared):
        conn=local.get()
        if conn is None:raise EvidenceError('final checks require owned locks')
        rows=conn.execute('SELECT kind,units FROM regulated_mission_budget_events_v1 WHERE tenant=%s AND mission=%s AND reservation_id=%s',(prepared.ctx.tenant_id,prepared.mission,prepared.reservation)).fetchall()
        if rows!=[('reserve',prepared.units)]:raise EvidenceError('reservation no longer live')
    runtime=SharedEvidenceRuntime(publisher_for=publisher_for,provider_for=provider_for,worm=authorities.worm,retain_us=7*365*86400000000,dependency_barrier=DependencyBarrier({},lambda scope:None),final_locks=final_locks,final_checks=final_checks)
    recorder=SharedEvidenceRecorder(old._signer,trust,pool=pool,clock=clock,service_for=service_for,max_record_age_us=old.max_record_age_us)
    recorder.shared_evidence_runtime=runtime
    def audit_worker():
        while not stop.wait(1):
            with lock:batch=list(runners.items())
            for tenant,runner in batch:
                try:
                    completed=runner.tick(256)
                    segment,renew,state=maintenance[tenant]
                    if completed:segment.step()
                    now=clock.read().now_us
                    if state[1] is None and now-state[0]>=21600000000:state[1]=('leaves',0)
                    if state[1] is not None:
                        phase,cursor=state[1]
                        if phase=='leaves':
                            cursor,size=renew.batch(cursor);state[1]=('leaves',cursor)
                            if cursor>=size:renew.finish();state[1]=('segments',0)
                        else:
                            cursor,complete=segment.renew_batch(cursor);state[1]=('segments',cursor)
                            if complete:state[:]=[now,None]
                except Exception:pass # Existing signed heartbeat expires; integrity errors latch.
    thread=threading.Thread(target=audit_worker,daemon=True);thread.start()
    def close():
        stop.set();thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("shared fixture audit worker did not stop")
        for pub in publishers.values():pub.close()
    (atexit.register if register_cleanup is None else register_cleanup)(close)
    return replace(stores,recorder=recorder)
