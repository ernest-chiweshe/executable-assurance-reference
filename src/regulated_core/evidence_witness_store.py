"""Durable serialized witness endpoint; SQLite is owned by the witness process.

An explicitly enrolled store is required on restart. Each reply is signed and
all accepted records are committed with synchronous=FULL before returning.
An independent deployment/admin boundary is required for independent custody.
"""
from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from .evidence_encoding import canonical_bytes,loads
from .evidence_service import EvidenceError,TreeHead
from .evidence_namespace import NamespaceHead
from .evidence_witness import (WitnessScope,HeadPolicy,Checkpoint,WitnessRequest,WitnessAck,
    WitnessReack,GENESIS_ACK,decide_request,_nonce,_ack_valid)
from .signing import Signature
from .clock import read_clock

MAX_WIRE=1048576

def ack_document(ack):
    return {"body":ack.body(),"signature":ack.signature}

def decode_ack(doc):
    doc=loads(canonical_bytes(doc))
    try:
        b=dict(doc["body"])
        if b.pop("schema")!="regulated/witness-ack/v1":raise ValueError("ack schema")
        scope=WitnessScope(b.pop("scope_type"),b.pop("scope_id"),b.pop("namespace"))
        point=Checkpoint(b.pop("size"),b.pop("root"),b.pop("head_digest"))
        return WitnessAck(scope=scope,checkpoint=point,signature=Signature(**doc["signature"]),**b)
    except (KeyError,TypeError,ValueError) as e:raise EvidenceError("invalid stored acknowledgement") from e

def decode_head(doc):
    doc=loads(canonical_bytes(doc))
    if doc["body"]["schema"]=="regulated/evidence-sth/v2":return TreeHead.from_document(doc)
    return NamespaceHead.from_document(doc)

class DurableWitness:
    def __init__(self,path,*,witness_id,signer,trust,clock,policies,create=False):
        self.path=Path(path);self.witness_id=witness_id;self.signer=signer
        self.trust=trust;self.clock=clock;self.policies=dict(policies)
        if not witness_id or not trust.matches_signer(signer):raise EvidenceError("invalid witness signer")
        if create:
            # Exclusive creation prevents accidental re-enrollment/overwrite.
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self.path.open("xb"):pass
        elif not self.path.is_file():raise EvidenceError("lost witness state: explicit enrollment required")
        with self._connect() as c:
            if create:
                c.executescript("""CREATE TABLE identity(id TEXT PRIMARY KEY,key_id TEXT NOT NULL);
                CREATE TABLE accepted(scope TEXT NOT NULL,ordinal INTEGER NOT NULL,size INTEGER NOT NULL,
                 digest TEXT NOT NULL,head BLOB NOT NULL,ack BLOB NOT NULL,ack_digest TEXT NOT NULL,
                 PRIMARY KEY(scope,ordinal),UNIQUE(scope,size),UNIQUE(scope,ack_digest));
                CREATE TRIGGER accepted_no_update BEFORE UPDATE ON accepted BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER accepted_no_delete BEFORE DELETE ON accepted BEGIN SELECT RAISE(ABORT,'immutable'); END;""")
                c.execute("INSERT INTO identity VALUES(?,?)",(witness_id,signer.key_id))
            if c.execute("SELECT id,key_id FROM identity").fetchall()!=[(witness_id,signer.key_id)]:raise EvidenceError("witness enrollment mismatch")

    def _open(self):
        c=sqlite3.connect(str(self.path),timeout=5)
        c.execute("PRAGMA synchronous=FULL")
        return c

    @contextmanager
    def _connect(self):
        c=self._open()
        try:
            with c:yield c
        finally:c.close()

    def _scope(self,scope):
        if type(scope) is not WitnessScope or scope not in self.policies:raise EvidenceError("unknown witness scope")
        return canonical_bytes(scope.fields()).decode("ascii")

    def _current(self,c,scope):
        row=c.execute("SELECT ordinal,head,ack,ack_digest FROM accepted WHERE scope=? ORDER BY ordinal DESC LIMIT 1",(self._scope(scope),)).fetchone()
        if row is None:return None
        ordinal,raw,araw,digest=row
        if len(raw)>MAX_WIRE or len(araw)>MAX_WIRE:raise EvidenceError("oversized witness record")
        head=decode_head(loads(raw));ack=decode_ack(loads(araw));point=Checkpoint.from_head(head,self.policies[scope])
        if not _ack_valid(ack,self.witness_id,self.signer.key_id,scope,point,self.trust) or ack.digest()!=digest:raise EvidenceError("corrupt witness record")
        return ordinal,head,ack

    def _signed(self,body):
        return {"body":body,"signature":self.signer.sign(body)}

    def latest(self,scope,nonce):
        if not _nonce(nonce):raise EvidenceError("invalid latest nonce")
        with self._connect() as c:
            row=self._current(c,scope)
            return self._signed({"schema":"regulated/witness-latest/v1","witness_id":self.witness_id,
                "nonce":nonce,**scope.fields(),"head":None if row is None else row[1].document(),
                "ack":None if row is None else ack_document(row[2])})

    def ack_range(self,scope,after_digest,*,limit=64):
        if type(limit) is not int or not 1<=limit<=64:raise EvidenceError("ack range bound")
        name=self._scope(scope)
        with self._connect() as c:
            if after_digest==GENESIS_ACK:ordinal=0
            else:
                row=c.execute("SELECT ordinal FROM accepted WHERE scope=? AND ack_digest=?",(name,after_digest)).fetchone()
                if row is None:raise EvidenceError("unknown acknowledgement pin")
                ordinal=row[0]
            rows=c.execute("SELECT ack FROM accepted WHERE scope=? AND ordinal>? ORDER BY ordinal LIMIT ?",(name,ordinal,limit+1)).fetchall()
            if len(rows)>limit:raise EvidenceError("acknowledgement recovery exceeds bound")
            return tuple(decode_ack(loads(bytes(row[0]))) for row in rows)

    def request(self,request):
        if type(request) is not WitnessRequest:raise EvidenceError("invalid request")
        name=self._scope(request.scope);policy=self.policies[request.scope]
        if len(canonical_bytes(request.document(policy)))>MAX_WIRE:raise EvidenceError("request exceeds byte bound")
        c=self._open()
        try:
            c.execute("BEGIN IMMEDIATE")
            row=self._current(c,request.scope);current=None if row is None else row[1]
            decision=decide_request(request,current,policy)
            if decision=="ACK":
                reading=read_clock(self.clock)
                if row is not None and reading.now_us<row[2].issued_at_us:raise EvidenceError("witness clock regressed")
                ack=WitnessAck(self.witness_id,request.request_id,request.scope,request.checkpoint(policy),
                    GENESIS_ACK if row is None else row[2].digest(),reading.now_us,Signature(self.signer.key_id,"",self.signer.alg))
                ack=replace(ack,signature=self.signer.sign(ack.body()))
                c.execute("INSERT INTO accepted VALUES(?,?,?,?,?,?,?)",(name,1 if row is None else row[0]+1,
                    ack.checkpoint.size,ack.checkpoint.head_digest,canonical_bytes(request.head.document()),canonical_bytes(ack_document(ack)),ack.digest()))
                c.commit() # durable before reply; a dropped reply becomes REACK
                return ack
            c.commit()
            if decision=="REACK":
                result=WitnessReack(self.witness_id,request.request_id,row[2],Signature(self.signer.key_id,"",self.signer.alg))
                return replace(result,signature=self.signer.sign(result.body()))
            return self._signed({"schema":"regulated/witness-refusal/v1","witness_id":self.witness_id,
                "request_id":request.request_id,**request.scope.fields(),"reason":decision,
                "requested":request.checkpoint(policy).fields(),"head":None if row is None else row[1].document(),
                "ack":None if row is None else ack_document(row[2])})
        except BaseException:
            c.rollback();raise
        finally:c.close()

    def batch(self,requests,*,max_items=64):
        if type(max_items) is not int or not 1<=max_items<=256 or type(requests) is not tuple or not 1<=len(requests)<=max_items:raise EvidenceError("batch item bound")
        if any(type(r) is not WitnessRequest for r in requests):raise EvidenceError("batch item type")
        if len({r.scope for r in requests})!=len(requests) or len({r.request_id for r in requests})!=len(requests):raise EvidenceError("duplicate batch item")
        docs=[r.document(self.policies[r.scope]) for r in requests]
        if len(canonical_bytes({"schema":"regulated/witness-request-batch/v1","items":docs}))>MAX_WIRE:raise EvidenceError("batch request bytes")
        # Each success is durable independently; retry reconciles partial progress.
        replies=tuple(self.request(r) for r in requests)
        if len(canonical_bytes(replies))>MAX_WIRE:raise EvidenceError("batch response bytes")
        return replies
