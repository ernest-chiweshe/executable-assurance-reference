"""Transactional namespace projections and separate retention-gated sealer.

One transition changes one state key. Writers carry no signer. Per-step work
includes <=256 map levels, <=63 tree levels, and an explicitly bounded source.
Sealing checks at most256 transitions from its authenticated previous head.
"""
from dataclasses import dataclass
from hashlib import sha256
from .evidence_encoding import canonical_bytes,loads
from .evidence_namespace import Transition,NamespaceHead,advance_chain,sign_namespace_head,verify_namespace_head
from .evidence_service import EvidenceError
from .evidence_map import MemorySparseMap,EMPTY_LEAF,node_digest
from .evidence_service_pg import _transaction,_map_reader,frontier_document,decode_frontier
from .merkle import Frontier,EMPTY_ROOT,consistency_proof
from .evidence import GENESIS

NAMESPACE_SCHEMA="""
CREATE TABLE IF NOT EXISTS regulated_ns_transition_v2(
 tenant TEXT NOT NULL,scope_type TEXT NOT NULL,namespace TEXT NOT NULL,version BIGINT NOT NULL CHECK(version>0),
 operation_id TEXT NOT NULL,transition BYTEA NOT NULL,source BYTEA NOT NULL CHECK(octet_length(source)<=1048576),
 frontier JSONB NOT NULL,tree_root BYTEA NOT NULL,map_root BYTEA NOT NULL,chain TEXT NOT NULL,
 PRIMARY KEY(tenant,scope_type,namespace,version),UNIQUE(operation_id,tenant,scope_type,namespace));
CREATE TABLE IF NOT EXISTS regulated_ns_tree_v2(
 tenant TEXT NOT NULL,scope_type TEXT NOT NULL,namespace TEXT NOT NULL,level SMALLINT NOT NULL,idx BIGINT NOT NULL,hash BYTEA NOT NULL,
 PRIMARY KEY(tenant,scope_type,namespace,level,idx));
CREATE TABLE IF NOT EXISTS regulated_ns_seal_v2(
 tenant TEXT NOT NULL,scope_type TEXT NOT NULL,namespace TEXT NOT NULL,version BIGINT NOT NULL,head JSONB NOT NULL,
 PRIMARY KEY(tenant,scope_type,namespace,version));
"""
for _table in ('regulated_ns_transition_v2','regulated_ns_tree_v2','regulated_ns_seal_v2'):
    NAMESPACE_SCHEMA+=f"""
ALTER TABLE {_table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {_table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON {_table};
CREATE POLICY tenant_scope ON {_table} USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON {_table};
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON {_table} FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON {_table};
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON {_table} FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""

@dataclass(frozen=True)
class NamespaceSnapshot:
    version:int
    tree_root:bytes
    state_root:bytes
    chain:str

class PostgresNamespaceWriter:
    def __init__(self,scope):self.scope=scope
    def _args(self):return (self.scope.scope_id,self.scope.scope_type,self.scope.namespace)
    def _read_tree(self,conn):
        def read(level,index):
            row=conn.execute("SELECT hash FROM regulated_ns_tree_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s AND level=%s::smallint AND idx=%s::bigint",self._args()+(level,index)).fetchone()
            if row is None:raise EvidenceError("missing namespace tree node")
            return bytes(row[0])
        return read
    def snapshot_on(self,conn,version):
        _transaction(conn,self.scope.scope_id)
        row=conn.execute("SELECT tree_root,map_root,chain FROM regulated_ns_transition_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s AND version=%s::bigint",self._args()+(version,)).fetchone()
        snapshot=None if row is None else NamespaceSnapshot(version,bytes(row[0]),bytes(row[1]),row[2])
        if snapshot is not None:
            from .evidence_dependencies import observe
            observe(self.scope,snapshot)
        return snapshot
    def append_on(self,conn,*,operation_id,transition,source):
        _transaction(conn,self.scope.scope_id)
        if type(operation_id) is not str or not operation_id or len(operation_id)>256 or type(transition) is not Transition or type(source) is not bytes or len(source)>1048576:raise EvidenceError("namespace append bounds")
        if (transition.scope_type,transition.scope_id,transition.namespace)!=(self.scope.scope_type,self.scope.scope_id,self.scope.namespace):raise EvidenceError("namespace scope mismatch")
        raw=transition.bytes()
        if sha256(source).hexdigest()!=transition.content_digest:raise EvidenceError("namespace source digest mismatch")
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",('regulated-ns:'+self.scope.namespace+':'+self.scope.scope_id,))
            old=conn.execute("SELECT version,transition,source FROM regulated_ns_transition_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s AND operation_id=%s",self._args()+(operation_id,)).fetchone()
            if old is not None:
                if bytes(old[1])!=raw or bytes(old[2])!=source:raise EvidenceError("operation identity reused with different transition")
                return self.snapshot_on(conn,old[0])
            row=conn.execute("SELECT version,frontier,tree_root,map_root,chain FROM regulated_ns_transition_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s ORDER BY version DESC LIMIT 1",self._args()).fetchone()
            if row is None:frontier=Frontier();root=EMPTY_LEAF;chain=GENESIS
            else:frontier=decode_frontier(row[1],size=row[0],root=bytes(row[2]));root=bytes(row[3]);chain=row[4]
            frontier,nodes=frontier.append(raw);version=frontier.size
            mapping=MemorySparseMap(reader=_map_reader(conn,self.scope.scope_id));mapping.root=root
            mapping.update(bytes.fromhex(transition.key),transition.state_value().bytes());chain=advance_chain(chain,transition)
            for digest,node in mapping._nodes.items():
                conn.execute("INSERT INTO regulated_evidence_map_v2(tenant,hash,kind,left_hash,right_hash,leaf_key,value) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",(self.scope.scope_id,digest,'leaf' if node.key is not None else 'node',node.left,node.right,node.key,node.value))
                if _map_reader(conn,self.scope.scope_id)(digest)!=node:raise EvidenceError("namespace map conflict")
            for node in nodes:conn.execute("INSERT INTO regulated_ns_tree_v2 VALUES(%s,%s,%s,%s,%s,%s)",self._args()+(node.level,node.index,node.digest))
            conn.execute("INSERT INTO regulated_ns_transition_v2 VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",self._args()+(version,operation_id,raw,source,canonical_bytes(frontier_document(frontier)).decode(),frontier.root,mapping.root,chain))
            snapshot=NamespaceSnapshot(version,frontier.root,mapping.root,chain)
            from .evidence_dependencies import observe
            observe(self.scope,snapshot,'write')
            return snapshot

class PostgresNamespaceSealer(PostgresNamespaceWriter):
    def __init__(self,scope,*,signer,trust,clock,keys,historical_keys,verify_source,retention):
        super().__init__(scope);self.signer=signer;self.trust=trust;self.clock=clock;self.keys=keys
        self.historical_keys=historical_keys;self.verify_source=verify_source;self.retention=retention
        if not isinstance(retention,NamespaceRetention):raise EvidenceError("explicit namespace retention required")
    def seal_on(self,conn,*,previous,through,max_tail=256):
        _transaction(conn,self.scope.scope_id)
        if type(max_tail) is not int or not 1<=max_tail<=256 or type(through) is not int:raise EvidenceError("seal bound")
        start=0 if previous is None else previous.version
        if not start<through<=start+max_tail:raise EvidenceError("seal catch-up exceeds bound")
        args=dict(**self.scope.fields(),clock_domain=self.clock.domain,trust=self.trust,allowed_keys=self.keys,historical_keys=self.historical_keys)
        if previous is not None and not verify_namespace_head(previous,**args):raise EvidenceError("unverified previous namespace seal")
        if previous is None:frontier=Frontier();root=EMPTY_LEAF;chain=GENESIS
        else:
            row=conn.execute("SELECT frontier FROM regulated_ns_transition_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s AND version=%s::bigint",self._args()+(start,)).fetchone()
            if row is None:raise EvidenceError("sealed frontier absent")
            frontier=decode_frontier(row[0],size=start,root=bytes.fromhex(previous.tree_root));root=bytes.fromhex(previous.map_root);chain=previous.chain
        rows=conn.execute("SELECT version,transition,source,tree_root,map_root,chain FROM regulated_ns_transition_v2 WHERE tenant=%s AND scope_type=%s AND namespace=%s AND version>%s::bigint AND version<=%s::bigint ORDER BY version LIMIT %s",self._args()+(start,through,max_tail+1)).fetchall()
        if len(rows)!=through-start:raise EvidenceError("namespace transition gap")
        mapping=MemorySparseMap(reader=_map_reader(conn,self.scope.scope_id));mapping.root=root
        for expected,row in enumerate(rows,start+1):
            version,raw,source,tr,mr,claimed_chain=row;raw=bytes(raw);source=bytes(source);transition=Transition.from_bytes(raw)
            if (transition.scope_type,transition.scope_id,transition.namespace)!=(self.scope.scope_type,self.scope.scope_id,self.scope.namespace):raise EvidenceError("sealed transition scope mismatch")
            if version!=expected or len(source)>1048576 or sha256(source).hexdigest()!=transition.content_digest or self.verify_source(transition,source) is not True:raise EvidenceError("namespace source verification failed")
            frontier,_=frontier.append(raw);mapping.update(bytes.fromhex(transition.key),transition.state_value().bytes());chain=advance_chain(chain,transition)
            if frontier.root!=bytes(tr) or mapping.root!=bytes(mr) or chain!=claimed_chain:raise EvidenceError("namespace projection mismatch")
            # Callback must retain exact transition AND source and verify read-back.
            self.retention.retain(version,raw,source)
        self.retention.check(through)
        proof=consistency_proof(self._read_tree(conn),start,through)
        head=sign_namespace_head(**self.scope.fields(),version=through,tree_root=frontier.root,map_root=mapping.root,chain=chain,previous=previous,consistency=proof,signer=self.signer,clock=self.clock,trust=self.trust,signing_keys=self.keys,historical_keys=self.historical_keys)
        conn.execute("INSERT INTO regulated_ns_seal_v2 VALUES(%s,%s,%s,%s,%s::jsonb)",self._args()+(through,canonical_bytes(head.document()).decode()))
        return head


class NamespaceRetention:
    """Retain the exact transition and source before advancing a contiguous seal."""
    def __init__(self,*,scope,worm,journal,clock,retain_us):
        if type(retain_us) is not int or retain_us<=0:raise EvidenceError('namespace retention duration')
        self.scope=scope;self.worm=worm;self.journal=journal;self.clock=clock;self.retain_us=retain_us
    def retain(self,version,transition,source):
        import base64
        from .clock import read_clock
        if type(version) is not int or version<1:raise EvidenceError('namespace retention version')
        t=Transition.from_bytes(transition)
        if (t.scope_type,t.scope_id,t.namespace)!=(self.scope.scope_type,self.scope.scope_id,self.scope.namespace) or sha256(source).hexdigest()!=t.content_digest:raise EvidenceError('namespace retention source binding')
        raw=canonical_bytes({'schema':'regulated/ns-retention/v1',**self.scope.fields(),'version':version,'transition':loads(transition),'source':base64.b64encode(source).decode('ascii')})
        now=read_clock(self.clock).now_us
        receipt=self.worm.anchor(self.scope.scope_id,raw,retain_us=self.retain_us,now_us=now)
        if (not self.worm.verify(receipt) or receipt.content_digest!=sha256(raw).hexdigest() or receipt.retained_until_us<now+self.retain_us
            or self.worm.fetch(self.scope.scope_id,receipt.object_ref)!=raw):raise EvidenceError('namespace full retention read-back failed')
        self.journal.mark_retained(version-1,transition,receipt)
        return receipt
    def check(self,through):
        from .clock import read_clock
        self.journal.check();size,expiry=self.journal.watermark()
        if size<through or read_clock(self.clock).now_us>=expiry:raise EvidenceError('namespace seal exceeds live retained prefix')
