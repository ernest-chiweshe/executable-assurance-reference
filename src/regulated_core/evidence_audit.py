"""Off-path complete evidence audit with signed progress and freshness checks.

A sweep is linear in history and encoded body bytes. It is deliberately outside
permit handling. No sampling or successful query count substitutes for a sweep.
"""
from dataclasses import replace
from time import sleep as _yield_cpu
from .clock import read_clock
from .evidence_encoding import canonical_bytes,loads
from .evidence import GENESIS,verify_envelope
from .evidence_map import MemorySparseMap
from .evidence_service import EvidenceError,KeySummary,UnhashableIdFlag,envelope_keys,unhashable_id_key,occurrence_bytes
from .merkle import MemoryMerkleLog
from .persistence_pg import decode_envelope,PersistenceError
from .signing import Signature

class EvidenceAuditor:
    def __init__(self,*,policy,envelope_keys_allowed,envelope_domains,journal,clock,signer,trust,
                 fetch_batch,heartbeat_us=60000000,sweep_us=86400000000,max_body_bytes=1048576):
        if not 0<heartbeat_us<sweep_us or not trust.matches_signer(signer):raise EvidenceError("audit configuration")
        self.policy=policy;self.envelope_keys=envelope_keys_allowed;self.domains=envelope_domains
        self.journal=journal;self.clock=clock;self.signer=signer;self.trust=trust;self.fetch_batch=fetch_batch
        self.heartbeat_us=heartbeat_us;self.sweep_us=sweep_us;self.max_body=max_body_bytes;self.target=None
        with journal.connect() as c:c.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY CHECK(id=1),document BLOB NOT NULL)")
    def _status(self):
        with self.journal.connect() as c:r=c.execute("SELECT document FROM audit WHERE id=1").fetchone()
        if r is None:return None
        try:
            d=loads(bytes(r[0]));b=d['body'];sig=Signature(**d['signature'])
            if sig.key_id!=self.signer.key_id or not self.trust.verify(b,sig) or b['scope']!=self.policy.scope.fields() or b['clock_domain']!=self.clock.domain:raise EvidenceError("invalid audit progress")
            return b
        except (KeyError,TypeError,ValueError) as e:raise EvidenceError("invalid audit record") from e
    def _save(self,completed):
        now=read_clock(self.clock).now_us;old=self._status();last=now if completed else (None if old is None else old['completed_at_us'])
        b={'schema':'regulated/evidence-audit/v1','scope':self.policy.scope.fields(),'clock_domain':self.clock.domain,
           'progress_at_us':now,'completed_at_us':last,'through':self.tree.frontier.size,'target':self.target.digest()}
        with self.journal.connect() as c:c.execute("INSERT INTO audit VALUES(1,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",(canonical_bytes({'body':b,'signature':self.signer.sign(b)}),))
    def check(self):
        self.journal.check();b=self._status();now=read_clock(self.clock).now_us
        if b is None or b['completed_at_us'] is None or not 0<=now-b['progress_at_us']<=self.heartbeat_us or not 0<=now-b['completed_at_us']<=self.sweep_us:raise EvidenceError("audit deadline missed")
    def begin(self,head):
        if not self.policy.verify(head):raise EvidenceError("unverified audit target")
        self.journal.check();self.target=head;self.tree=MemoryMerkleLog();self.map=MemorySparseMap()
        self.keys={};self.previous=GENESIS;self.started=read_clock(self.clock).now_us
    def step(self,limit=256):
        if self.target is None or type(limit) is not int or not 1<=limit<=1024:raise EvidenceError("audit batch configuration")
        start=self.tree.frontier.size;count=min(limit,self.target.tree_size-start)
        try:
            rows=self.fetch_batch(start,count)
            if len(rows)!=count:raise EvidenceError("audit source gap")
            for raw in rows:
                if type(raw) is not bytes or len(raw)>self.max_body:raise EvidenceError("audit body bound")
                env=decode_envelope(loads(raw));seq=self.tree.frontier.size
                if (canonical_bytes(env)!=raw or env.seq!=seq or env.prev_hash!=self.previous or env.record.tenant_id!=self.policy.scope.scope_id
                    or env.signature.key_id not in self.envelope_keys or env.clock_domain not in self.domains or not verify_envelope(env,self.policy.trust)):
                    raise EvidenceError("audit envelope integrity")
                self.tree.append(raw)
                for digest in envelope_keys(env):
                    tree,first=self.keys.setdefault(digest,(MemoryMerkleLog(),seq));ordinal=tree.append(occurrence_bytes(seq))
                    self.map.update(digest,KeySummary(ordinal+1,first,seq,tree.root().hex()).bytes())
                if type(env.record.record_id) is list or type(env.record.record_id) is dict:
                    key=unhashable_id_key(env.record.tenant_id)
                    if self.map.prove(key).value is None:self.map.update(key,UnhashableIdFlag(seq).bytes())
                self.previous=env.chain_hash()
                # Give receiving threads a scheduling opportunity after a fully
                # verified record. Full replay, root and deadline checks remain.
                _yield_cpu(0.001)
            complete=self.tree.frontier.size==self.target.tree_size
            if complete:
                if (self.tree.root().hex()!=self.target.tree_root or self.map.root.hex()!=self.target.map_root or self.previous!=self.target.last_entry_hash):raise EvidenceError("audit reconstructed root mismatch")
                elapsed=read_clock(self.clock).now_us-self.started
                if elapsed<0 or 2*elapsed>=self.sweep_us:raise EvidenceError("audit sweep configuration cannot sustain deadline")
            self._save(complete)
            if complete:self.target=None
            return complete
        except (ValueError,TypeError,KeyError,PersistenceError) as e:self.journal.latch('audit integrity failure: '+str(e))


class NamespaceAuditor(EvidenceAuditor):
    """Complete off-path namespace replay, including exact source verification."""
    def __init__(self,*,verify_source,**kwargs):
        self.verify_source=verify_source
        super().__init__(**kwargs)
    def step(self,limit=256):
        from .evidence_namespace import Transition,advance_chain
        from hashlib import sha256
        if self.target is None or type(limit) is not int or not 1<=limit<=1024:raise EvidenceError('namespace audit batch bound')
        start=self.tree.frontier.size;count=min(limit,self.target.tree_size-start)
        try:
            rows=self.fetch_batch(start,count)
            if len(rows)!=count:raise EvidenceError('namespace audit gap')
            for raw,source in rows:
                if type(raw) is not bytes or type(source) is not bytes or len(raw)>self.max_body or len(source)>self.max_body:raise EvidenceError('namespace audit bytes')
                t=Transition.from_bytes(raw)
                if (t.scope_type,t.scope_id,t.namespace)!=(self.policy.scope.scope_type,self.policy.scope.scope_id,self.policy.scope.namespace):raise EvidenceError('namespace audit scope')
                if sha256(source).hexdigest()!=t.content_digest or self.verify_source(t,source) is not True:raise EvidenceError('namespace audit source')
                self.tree.append(raw);self.map.update(bytes.fromhex(t.key),t.state_value().bytes());self.previous=advance_chain(self.previous,t)
                _yield_cpu(0.001)
            complete=self.tree.frontier.size==self.target.tree_size
            if complete:
                if self.tree.root().hex()!=self.target.tree_root or self.map.root.hex()!=self.target.map_root or self.previous!=self.target.chain:raise EvidenceError('namespace audit roots')
                elapsed=read_clock(self.clock).now_us-self.started
                if elapsed<0 or 2*elapsed>=self.sweep_us:raise EvidenceError('namespace audit deadline configuration')
            self._save(complete)
            if complete:self.target=None
            return complete
        except (ValueError,TypeError,KeyError) as e:self.journal.latch('namespace audit integrity failure: '+str(e))


class AuditRunner:
    """One scheduler tick; a completed sweep always starts again at a fresh head."""
    def __init__(self,auditor,current_head):self.auditor=auditor;self.current_head=current_head
    def tick(self,limit=256):
        if self.auditor.target is None:self.auditor.begin(self.current_head())
        return self.auditor.step(limit)
