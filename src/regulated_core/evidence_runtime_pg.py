"""Host-composed durable evidence recorder and bounded historical indexing.

Existing signed rows are never rewritten. New append keeps recorder signing and
independent clock-floor commits inside the caller's existing transaction.
"""
from .persistence_pg import PostgresDecisionRecorder,_tenant
from .evidence_service import EvidenceError
from .evidence_encoding import canonical_bytes,envelope_bytes,check_numeric_domain
from .evidence_service_pg import _transaction,ENVELOPE_SQL

class PostgresEvidenceRecorder(PostgresDecisionRecorder):
    def __init__(self,*args,service_for,**kwargs):
        super().__init__(*args,**kwargs)
        self._raw_recorder=PostgresDecisionRecorder(*args,**kwargs)
        self.service_for=service_for
    def bind_clock(self,clock):
        super().bind_clock(clock)
        if hasattr(self,'_raw_recorder'):self._raw_recorder.bind_clock(clock)
    def _append_on(self,conn,record,record_hash):
        env,_=self.service_for(record.tenant_id).append_record_on(conn,self._raw_recorder,record,record_hash)
        return env

class _HistoricalRecorder(PostgresDecisionRecorder):
    def _append_on(self,conn,record,record_hash):
        # Only the backfill driver sets this verified exact existing envelope.
        if self.existing.record!=record or self.existing.record_hash!=record_hash:raise EvidenceError("backfill record substitution")
        return self.existing

def backfill_batch_on(conn,*,service,recorder,limit=256):
    _transaction(conn,service.tenant)
    if type(limit) is not int or type(limit) is not int or not 1<=limit<=256:raise EvidenceError("backfill batch bound")
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",('regulated-evidence-v1:'+service.tenant,))
    head=service.head_on(conn);start=0 if head is None else head.tree_size
    rows=conn.execute("SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s AND seq BETWEEN %s::bigint AND %s::bigint ORDER BY seq",(service.tenant,start,start+limit-1)).fetchall()
    proxy=object.__new__(_HistoricalRecorder)
    for expected,row in enumerate(rows,start):
        env=recorder._checked(row,service.tenant)
        if env.seq!=expected:raise EvidenceError("historical sequence gap")
        check_numeric_domain(env);envelope_bytes(env) # refuse out-of-domain/deep history; never skip or rewrite
        proxy.existing=env
        _,head=service.append_record_on(conn,proxy,env.record,env.record_hash)
    return head,len(rows)


class PostgresEvidenceProvider:
    """Verified logarithmic proof reads using short owned transactions."""
    def __init__(self,service,pool):self.service=service;self.pool=pool
    def _call(self,fn):
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)",(self.service.tenant,))
                return fn(conn)
    def head_at(self,size):return self._call(lambda conn:self.service.head_on(conn,size))
    def current_head(self):return self._call(self.service.head_on)
    def consistency(self,old,new):
        return self._call(lambda conn:self.service.consistency_on(conn,None if old==0 else self.service.head_on(conn,old),self.service.head_on(conn,new)))
    def inclusion(self,seq,size):
        from .merkle import inclusion_proof
        return self._call(lambda conn:self.service._tree_proof_on(conn,lambda read:inclusion_proof(read,seq,size)))
    def leaf(self,envelope):
        from .merkle import inclusion_proof,verify_inclusion
        from .evidence import verify_envelope
        from .persistence_pg import decode_envelope
        def read(conn):
            head=self.service.head_on(conn)
            if head is None or envelope.record.tenant_id!=self.service.tenant or not 0<=envelope.seq<head.tree_size:raise EvidenceError('action outside signed history')
            row=conn.execute(ENVELOPE_SQL,(self.service.tenant,envelope.seq)).fetchone()
            if row is None:raise EvidenceError('action evidence missing')
            raw=envelope_bytes(row[2]);stored=decode_envelope(row[2])
            path=self.service._tree_proof_on(conn,lambda read:inclusion_proof(read,envelope.seq,head.tree_size))
            if (canonical_bytes(envelope)!=raw or row[1]!=envelope.chain_hash()
                or stored.signature.key_id not in self.service.envelope_keys_allowed or stored.clock_domain not in self.service.envelope_domains
                or not verify_envelope(stored,self.service.trust)
                or not verify_inclusion(raw,envelope.seq,head.tree_size,path,bytes.fromhex(head.tree_root))):raise EvidenceError('action membership failed')
            return raw,head,path
        return self._call(read)

    def delta(self,start,end,*,limit=256):
        from .merkle import inclusion_proof
        from .persistence_pg import decode_envelope
        if type(start) is not int or type(end) is not int or not 0<=start<=end or type(limit) is not int or not 1<=limit<=256 or end-start>limit:raise EvidenceError('retention delta bound')
        def read(conn):
            head=self.service.head_on(conn)
            if head is None or end>head.tree_size:raise EvidenceError('delta exceeds head')
            rows=conn.execute('SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s AND seq BETWEEN %s::bigint AND %s::bigint ORDER BY seq',(self.service.tenant,start,end-1)).fetchall()
            if len(rows)!=end-start:raise EvidenceError('retention delta gap')
            result=[]
            from .evidence import verify_envelope
            for seq,row in enumerate(rows,start):
                env=decode_envelope(row[2]);raw=envelope_bytes(row[2])
                if row[0]!=seq or env.seq!=seq or row[1]!=env.chain_hash() or env.signature.key_id not in self.service.envelope_keys_allowed or env.clock_domain not in self.service.envelope_domains or not verify_envelope(env,self.service.trust):raise EvidenceError('delta envelope invalid')
                result.append((seq,raw,head,self.service._tree_proof_on(conn,lambda read:inclusion_proof(read,seq,head.tree_size))))
            return tuple(result)
        return self._call(read)
    def audit_batch(self,start,count):
        if type(count) is not int or not 0<=count<=1024:raise EvidenceError('audit fetch bound')
        return self._call(lambda conn:tuple(envelope_bytes(row[0]) for row in conn.execute('SELECT envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s AND seq BETWEEN %s::bigint AND %s::bigint ORDER BY seq',(self.service.tenant,start,start+count-1)).fetchall()))
