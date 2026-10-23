"""Synchronous retained-prefix publication and final dependency gate.

Adapters provide verified stored heads and logarithmic log proofs. This module
never decides caller policy and never treats an evidence object as permission.
Network waits happen before caller locks. Durable clocks remain host-owned.
"""
from __future__ import annotations
import sqlite3,secrets,time,threading
from pathlib import Path
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor,wait
from dataclasses import dataclass
from hashlib import sha256
from .clock import read_clock
from .evidence_encoding import canonical_bytes,loads
from .evidence_service import EvidenceError
from .evidence_witness import (Checkpoint,WitnessAck,WitnessReack,WitnessRequest,GENESIS_ACK,
    verify_quorum,_ack_valid,_signed)
from .evidence_witness_store import decode_ack,decode_head,ack_document
from .signing import Signature
from .merkle import verify_inclusion,verify_consistency

class RetryRequired(EvidenceError):pass

class PublicationJournal:
    """Local crash journal; witnesses supply rollback protection, not this file."""
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS retained(seq INTEGER PRIMARY KEY,digest TEXT NOT NULL,receipt BLOB NOT NULL,expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS watermark(id INTEGER PRIMARY KEY CHECK(id=1),size INTEGER NOT NULL,expires INTEGER NOT NULL);
            INSERT OR IGNORE INTO watermark VALUES(1,0,9223372036854775807);
            CREATE TABLE IF NOT EXISTS pins(witness TEXT PRIMARY KEY,ack BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS publications(counter INTEGER PRIMARY KEY,head BLOB NOT NULL,acks BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS latch(id INTEGER PRIMARY KEY CHECK(id=1),reason TEXT NOT NULL);""")
    @contextmanager
    def connect(self):
        c=sqlite3.connect(str(self.path),timeout=5);c.execute("PRAGMA synchronous=FULL")
        try:
            with c:yield c
        finally:c.close()
    def check(self):
        with self.connect() as c:
            if c.execute("SELECT 1 FROM latch").fetchone():raise EvidenceError("publication scope latched")
    def latch(self,reason):
        with self.connect() as c:c.execute("INSERT OR IGNORE INTO latch VALUES(1,?)",(reason,))
        raise EvidenceError(reason)
    def pin(self,identity):
        with self.connect() as c:
            r=c.execute("SELECT ack FROM pins WHERE witness=?",(identity,)).fetchone()
            return None if r is None else decode_ack(loads(bytes(r[0])))
    def save_pin(self,ack):
        with self.connect() as c:c.execute("INSERT INTO pins VALUES(?,?) ON CONFLICT(witness) DO UPDATE SET ack=excluded.ack",(ack.witness_id,canonical_bytes(ack_document(ack))))
    def watermark(self):
        with self.connect() as c:return c.execute("SELECT size,expires FROM watermark WHERE id=1").fetchone()
    def mark_retained(self,seq,raw,receipt):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE");digest=sha256(raw).hexdigest()
            old=c.execute("SELECT digest FROM retained WHERE seq=?",(seq,)).fetchone()
            if old is not None and old[0]!=digest:raise EvidenceError("retained sequence fork")
            c.execute("INSERT OR IGNORE INTO retained VALUES(?,?,?,?)",(seq,digest,canonical_bytes(receipt.as_dict()),receipt.retained_until_us))
            size,expires=c.execute("SELECT size,expires FROM watermark WHERE id=1").fetchone()
            # Bounded catch-up per operation; a larger ready suffix needs another pass.
            for _ in range(1024):
                row=c.execute("SELECT expires FROM retained WHERE seq=?",(size,)).fetchone()
                if row is None:break
                expires=min(expires,row[0]);size+=1
            c.execute("UPDATE watermark SET size=?,expires=? WHERE id=1",(size,expires))
    def renew_retained(self,seq,raw,receipt):
        """Off-path receipt replacement; logical retained bytes cannot change."""
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT digest,expires FROM retained WHERE seq=?",(seq,)).fetchone()
            if row is None or row[0]!=sha256(raw).hexdigest():raise EvidenceError('renewal differs from retained history')
            if receipt.retained_until_us<=row[1]:raise EvidenceError('renewal did not extend retention')
            c.execute("UPDATE retained SET receipt=?,expires=? WHERE seq=?",(canonical_bytes(receipt.as_dict()),receipt.retained_until_us,seq))
    def finish_renewal(self):
        """Linear off-path minimum over the full retained prefix, never issuance."""
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            size,_=c.execute("SELECT size,expires FROM watermark WHERE id=1").fetchone()
            count,expiry=c.execute("SELECT count(*),min(expires) FROM retained WHERE seq<?",(size,)).fetchone()
            if count!=size:raise EvidenceError('renewal prefix gap')
            if size:c.execute("UPDATE watermark SET expires=? WHERE id=1",(expiry,))
            return size,expiry

    def publish(self,head,acks):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO publications(head,acks) VALUES(?,?)",(canonical_bytes(head.document()),canonical_bytes(tuple(ack_document(a) for a in acks))))
            for ack in acks:c.execute("INSERT INTO pins VALUES(?,?) ON CONFLICT(witness) DO UPDATE SET ack=excluded.ack",(ack.witness_id,canonical_bytes(ack_document(ack))))

class WitnessPublisher:
    def __init__(self,*,policy,members,witness_trust,endpoints,journal,protected,clock,
                 head_at,consistency,audit_check,timeout=2.0):
        members.validate(witness_trust)
        if not 0<timeout<=30 or set(endpoints)!=dict(members.members).keys():raise EvidenceError("publisher configuration")
        self.policy=policy;self.members=members;self.trust=witness_trust;self.endpoints=endpoints
        self.journal=journal;self.protected=protected;self.clock=clock;self.head_at=head_at
        self.consistency=consistency;self.audit_check=audit_check;self.timeout=timeout;self._lock=threading.Lock()
        self._pool=ThreadPoolExecutor(max_workers=len(endpoints));self._inflight={}

    def retain(self,*,seq,raw,head,inclusion,worm,retain_us):
        self.journal.check()
        if not self.policy.verify(head) or not verify_inclusion(raw,seq,head.tree_size,inclusion,bytes.fromhex(head.tree_root)):raise EvidenceError("unverified retention leaf")
        now=read_clock(self.clock).now_us
        if type(retain_us) is not int or retain_us<=0:raise EvidenceError("retention duration")
        receipt=worm.anchor(self.policy.scope.scope_id,raw,retain_us=retain_us,now_us=now)
        if (not worm.verify(receipt) or receipt.content_digest!=sha256(raw).hexdigest()
            or receipt.retained_until_us<now+retain_us or worm.fetch(self.policy.scope.scope_id,receipt.object_ref)!=raw):raise EvidenceError("retention/read-back failed")
        self.journal.mark_retained(seq,raw,receipt)
        return receipt

    def _parallel(self,calls):
        # At most one outstanding call per configured witness. Timed-out work
        # keeps its slot until it exits; retries cannot grow an unbounded queue.
        futures={}
        for identity,call in calls.items():
            old=self._inflight.get(identity)
            if old is not None and not old.done():continue
            future=self._pool.submit(call);self._inflight[identity]=future;futures[future]=identity
        done,_=wait(futures,timeout=self.timeout)
        result={}
        for f in done:
            try:result[futures[f]]=f.result()
            except (TimeoutError,ConnectionError,OSError):continue
        return result

    def close(self):
        self._pool.shutdown(wait=True,cancel_futures=True)

    def _latest(self,identity,reply,nonce,target):
        try:
            body=reply["body"];sig=reply["signature"]
            if type(sig) is dict:sig=Signature(**sig)
            if not _signed(body,sig,dict(self.members.members)[identity],self.trust):raise EvidenceError("invalid latest signature")
            if (body.get("schema")!="regulated/witness-latest/v1" or body.get("witness_id")!=identity or body.get("nonce")!=nonce
                or any(body.get(k)!=v for k,v in self.policy.scope.fields().items())):raise EvidenceError("latest response binding")
            pin=self.journal.pin(identity)
            if body["head"] is None:
                if body["ack"] is not None or pin is not None:self.journal.latch("witness state lost")
                return None,GENESIS_ACK
            head=decode_head(body["head"]);ack=decode_ack(body["ack"]);point=Checkpoint.from_head(head,self.policy)
            key=dict(self.members.members)[identity]
            if not _ack_valid(ack,identity,key,self.policy.scope,point,self.trust):raise EvidenceError("invalid latest ack")
            local=self.head_at(point.size)
            if local is None or local.digest()!=point.head_digest:self.journal.latch("witness history absent locally")
            if point.size>target.tree_size:raise RetryRequired("checkpoint must catch up to witness")
            prior=GENESIS_ACK if pin is None else pin.digest()
            if prior!=ack.digest():
                result=self._parallel({identity:lambda:self.endpoints[identity].ack_range(self.policy.scope,prior,limit=64)})
                if identity not in result:raise EvidenceError("acknowledgement recovery unavailable")
                chain=result[identity]
                if not chain or len(chain)>64:raise EvidenceError("missing acknowledgement chain")
                for link in chain:
                    if (link.previous_ack_digest!=prior or not _ack_valid(link,identity,key,self.policy.scope,link.checkpoint,self.trust)):
                        raise EvidenceError("acknowledgement chain mismatch")
                    prior=link.digest()
                if prior!=ack.digest():raise RetryRequired("witness advanced during reconciliation")
                self.journal.save_pin(ack)
            return point,ack.digest()
        except (KeyError,TypeError,ValueError) as exc:
            if isinstance(exc,EvidenceError):raise
            raise EvidenceError("invalid latest response") from exc

    def publish(self,head):
        with self._lock:
            self.journal.check();self.audit_check()
            if not self.policy.verify(head,current_only=True) or self.head_at(head.tree_size)!=head:raise EvidenceError("unverified target checkpoint")
            size,expiry=self.journal.watermark();now=read_clock(self.clock).now_us
            if head.tree_size>size or now>=expiry:raise EvidenceError("checkpoint exceeds live retained prefix")
            nonces={i:secrets.token_hex(16) for i,_ in self.members.members}
            latest=self._parallel({i:lambda i=i:self.endpoints[i].latest(self.policy.scope,nonces[i]) for i in nonces})
            states={i:self._latest(i,r,nonces[i],head) for i,r in latest.items()}
            if len(states)<self.members.quorum:raise EvidenceError("insufficient reachable witnesses")
            ids={i:secrets.token_hex(16) for i in nonces};pins={i:GENESIS_ACK for i in nonces};requests={}
            for identity,(old,pin) in states.items():
                pins[identity]=pin
                proof=self.consistency(0 if old is None else old.size,head.tree_size)
                requests[identity]=WitnessRequest(ids[identity],self.policy.scope,old,head,proof)
            replies=self._parallel({i:lambda i=i:self.endpoints[i].request(requests[i]) for i in requests})
            for identity,reply in replies.items():
                if type(reply) is dict:
                    b=reply.get("body",{});sig=reply.get("signature")
                    if type(sig) is dict:sig=Signature(**sig)
                    if (b.get("schema")!="regulated/witness-refusal/v1" or b.get("requested")!=requests[identity].checkpoint(self.policy).fields()
                        or not _signed(b,sig,dict(self.members.members)[identity],self.trust)
                        or b.get("request_id")!=ids[identity] or b.get("witness_id")!=identity
                        or any(b.get(k)!=v for k,v in self.policy.scope.fields().items())):raise EvidenceError("invalid witness refusal")
                    if b.get("reason")=="CONFLICT":self.journal.latch("witness conflict")
                    raise RetryRequired("reconcile witness before retry")
            acks=verify_quorum(tuple(replies.values()),requests=ids,checkpoint=Checkpoint.from_head(head,self.policy),scope=self.policy.scope,previous_acks=pins,members=self.members,trust=self.trust)
            self.audit_check()
            if read_clock(self.clock).now_us>=expiry:raise EvidenceError("retention expired during wait")
            self.journal.publish(head,acks)
            previous=self.protected.read()
            if previous is not None and previous.tree_size>head.tree_size:raise RetryRequired("protected head advanced")
            self.protected.advance(previous,head,self.consistency(0 if previous is None else previous.tree_size,head.tree_size))
            return head

@dataclass(frozen=True)
class Dependency:
    scope: object
    version: int
    prefix_root: bytes
    state_root: bytes
    kind: str

class PermitGate:
    """Host composes existing locks/checks and actual permit signer here.

    Changed final dependencies refuse the attempt; retry performs a new decision
    and witness barrier. Signing remains inside the caller's final lock scope.
    """
    def __init__(self,*,clock,cover,locks,final_checks,release):
        self.clock=clock;self.cover=cover;self.locks=locks;self.final_checks=final_checks;self.release=release
    def issue(self,operation,dependencies,*,deadline_us,sign):
        if type(dependencies) is not tuple or len(dependencies)>256:raise EvidenceError("dependency bound")
        try:
            self.cover(operation,dependencies) # no caller/database lock held across I/O
            with self.locks(operation):
                now=read_clock(self.clock)
                if now.now_us>=deadline_us:raise EvidenceError("caller deadline elapsed")
                observed=self.final_checks(operation,now)
                if type(observed) is not tuple or any(d not in dependencies for d in observed):raise RetryRequired("final checks introduced uncovered dependency")
                return sign(now)
        except BaseException:
            self.release(operation) # caller's witnessed release transition; never deletion
            raise


class DependencyBarrier:
    """Require a verified sealer head at each observed version, then witness its
    extension. A not-yet-sealed observation refuses until the sealer catches up.
    No whole-history reconstruction is permitted inside this barrier.
    """
    def __init__(self,publishers,current_head):
        self.publishers=dict(publishers);self.current_head=current_head
    def __call__(self,operation,dependencies):
        if type(dependencies) is not tuple or len(dependencies)>256:raise EvidenceError("dependency count")
        grouped={}
        for d in dependencies:
            if (type(d) is not Dependency or type(d.version) is not int or not 0<=d.version<(1<<63)
                or type(d.prefix_root) is not bytes or len(d.prefix_root)!=32
                or type(d.state_root) is not bytes or len(d.state_root)!=32
                or type(d.kind) is not str or d.kind not in ("read","write")):
                raise EvidenceError("dependency representation")
            publisher=self.publishers[d.scope]
            observed=publisher.head_at(d.version)
            if observed is None:raise RetryRequired("observed version is not sealed yet")
            if (not publisher.policy.verify(observed) or observed.tree_root!=d.prefix_root.hex()
                or observed.map_root!=d.state_root.hex()):publisher.journal.latch("observed dependency differs from authenticated history")
            grouped.setdefault(d.scope,[]).append(d)
        for scope,deps in grouped.items():
            pub=self.publishers[scope];head=self.current_head(scope)
            for dep in deps:
                if head.tree_size<dep.version:raise RetryRequired("dependency is ahead of current seal")
                if not verify_consistency(dep.version,head.tree_size,dep.prefix_root,bytes.fromhex(head.tree_root),pub.consistency(dep.version,head.tree_size)):
                    pub.journal.latch("dependency prefix does not extend to checkpoint")
            pub.publish(head)


class SynchronousGroupCommit:
    """Bounded queue; every waiter requires a covering witnessed head.

    A timer starts a flush at W, or B arrivals trigger one immediately. Actual
    scheduling/network delay is measured by the caller; W is not a latency SLA.
    """
    def __init__(self,publisher,current_head,*,batch_size=64,wait_seconds=.005,max_pending=4096):
        if type(batch_size) is not int or not 1<=batch_size<=256 or not 0<=wait_seconds<=.1 or not batch_size<=max_pending<=4096:raise EvidenceError("group configuration")
        self.publisher=publisher;self.current_head=current_head;self.batch_size=batch_size
        self.delay=wait_seconds;self.max_pending=max_pending;self.lock=threading.Lock();self.pending=[];self.timer=None;self.flushing=False;self.timer_immediate=False
    def wait_for(self,seq,*,timeout=2.0):
        if type(seq) is not int or seq<0 or not 0<timeout<=30:raise EvidenceError("group request")
        event=threading.Event();item=[seq,event,None]
        with self.lock:
            if len(self.pending)>=self.max_pending:raise EvidenceError("group queue full")
            self.pending.append(item)
            if self.timer is None and not self.flushing:
                self.timer=threading.Timer(self.delay,self._flush);self.timer.daemon=True;self.timer.start()
            if len(self.pending)>=self.batch_size and not self.flushing and not self.timer_immediate:
                if self.timer:self.timer.cancel();self.timer=None
                self.timer_immediate=True
                self.timer=threading.Timer(0,self._flush);self.timer.daemon=True;self.timer.start()
        if not event.wait(timeout):raise EvidenceError("group deadline exceeded")
        if isinstance(item[2],BaseException):raise item[2]
        if item[2] is None or seq>=item[2].tree_size:raise EvidenceError("group did not cover action")
        return item[2]
    def _flush(self):
        with self.lock:
            if self.flushing:return
            self.flushing=True;self.timer=None;self.timer_immediate=False
            items=self.pending[:self.batch_size];self.pending=self.pending[self.batch_size:]
        try:
            size,_=self.publisher.journal.watermark();head=self.current_head(size)
            if head is None:raise RetryRequired("no contiguous retained checkpoint")
            self.publisher.publish(head)
            for item in items:item[2]=head if item[0]<head.tree_size else RetryRequired("action not yet retained")
        except BaseException as exc:
            for item in items:item[2]=exc
        finally:
            for item in items:item[1].set()
            with self.lock:
                self.flushing=False
                if self.pending and self.timer is None:
                    self.timer=threading.Timer(self.delay,self._flush);self.timer.daemon=True;self.timer.start()
