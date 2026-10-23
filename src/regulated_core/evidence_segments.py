"""Off-path complete segment copies. Originals and individual receipts remain.

A segment contains at most1024 full envelopes and64MiB encoded bytes. This work
is linear in its admitted batch and is never called by permit issuance.
"""
import base64
from hashlib import sha256
from .clock import read_clock
from .evidence_encoding import canonical_bytes,loads,MAX_ENVELOPE_BYTES
from .evidence_service import EvidenceError
from .merkle import MemoryMerkleLog,verify_inclusion
from .worm import WormReceipt

class SegmentCompactor:
    def __init__(self,*,journal,provider,policy,worm,clock,retain_us,segment_size=1024,max_bytes=67108864):
        if type(segment_size) is not int or not 1<=segment_size<=1024 or type(retain_us) is not int or retain_us<=0 or type(max_bytes) is not int or not 1024<=max_bytes<=67108864:raise EvidenceError('segment configuration')
        self.journal=journal;self.provider=provider;self.policy=policy;self.worm=worm;self.clock=clock
        self.retain_us=retain_us;self.size=segment_size;self.max_bytes=max_bytes
        with journal.connect() as c:c.execute('CREATE TABLE IF NOT EXISTS segments(start INTEGER NOT NULL,end INTEGER NOT NULL,digest TEXT NOT NULL,receipt BLOB NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(start,end,expires))')
    def _retain(self,raw):
        now=read_clock(self.clock).now_us
        receipt=self.worm.anchor(self.policy.scope.scope_id,raw,retain_us=self.retain_us,now_us=now)
        if not self.worm.verify(receipt) or receipt.content_digest!=sha256(raw).hexdigest() or receipt.retained_until_us<now+self.retain_us or self.worm.fetch(self.policy.scope.scope_id,receipt.object_ref)!=raw:raise EvidenceError('segment retention read-back failed')
        return receipt
    def step(self,*,include_partial=False):
        self.journal.check()
        with self.journal.connect() as c:
            row=c.execute('SELECT end FROM segments ORDER BY end DESC LIMIT 1').fetchone()
            start=0 if row is None else row[0]
        retained,expiry=self.journal.watermark()
        if read_clock(self.clock).now_us>=expiry:raise EvidenceError('segment source custody expired')
        end=min(retained,start+self.size)
        if end<=start or (end-start<self.size and not include_partial):return None
        head=self.provider.head_at(end)
        if head is None or not self.policy.verify(head) or head.tree_size!=end:raise EvidenceError('segment checkpoint invalid')
        with self.journal.connect() as c:rows=c.execute('SELECT seq,digest,receipt FROM retained WHERE seq>=? AND seq<? ORDER BY seq LIMIT ?',(start,end,self.size)).fetchall()
        if len(rows)!=end-start:raise EvidenceError('segment retained gap')
        bodies=[];tree=MemoryMerkleLog();used=0
        for expected,(seq,digest,doc) in enumerate(rows,start):
            old=WormReceipt(**loads(bytes(doc)));raw=self.worm.fetch(self.policy.scope.scope_id,old.object_ref)
            if seq!=expected or type(raw) is not bytes or len(raw)>MAX_ENVELOPE_BYTES or sha256(raw).hexdigest()!=digest or old.content_digest!=digest or not self.worm.verify(old) or read_clock(self.clock).now_us>=old.retained_until_us:raise EvidenceError('segment source invalid')
            if not verify_inclusion(raw,seq,end,self.provider.inclusion(seq,end),bytes.fromhex(head.tree_root)):raise EvidenceError('segment source not in checkpoint')
            encoded=base64.b64encode(raw).decode('ascii');used+=len(encoded)+3
            if used>self.max_bytes:raise EvidenceError('segment exceeds configured byte cap')
            bodies.append(encoded);tree.append(raw)
        raw=canonical_bytes({'schema':'regulated/evidence-segment/v1','tenant':self.policy.scope.scope_id,'from_seq':start,'to_seq':end,'subtree_root':tree.root().hex(),'head':head.document(),'envelopes':bodies})
        if len(raw)>self.max_bytes:raise EvidenceError('segment exceeds configured byte cap')
        receipt=self._retain(raw)
        with self.journal.connect() as c:
            existing=c.execute('SELECT digest FROM segments WHERE start=? AND end=? LIMIT 1',(start,end)).fetchone()
            if existing is not None and existing[0]!=receipt.content_digest:raise EvidenceError('segment identity conflict')
            c.execute('INSERT OR IGNORE INTO segments VALUES(?,?,?,?,?)',(start,end,receipt.content_digest,canonical_bytes(receipt.as_dict()),receipt.retained_until_us))
        return receipt
    def renew(self,start,end):
        self.journal.check()
        with self.journal.connect() as c:row=c.execute('SELECT digest,receipt FROM segments WHERE start=? AND end=? ORDER BY expires DESC LIMIT 1',(start,end)).fetchone()
        if row is None:raise EvidenceError('segment absent')
        old=WormReceipt(**loads(bytes(row[1])));raw=self.worm.fetch(self.policy.scope.scope_id,old.object_ref)
        if type(raw) is not bytes or len(raw)>self.max_bytes or sha256(raw).hexdigest()!=row[0] or old.content_digest!=row[0] or not self.worm.verify(old) or read_clock(self.clock).now_us>=old.retained_until_us:raise EvidenceError('segment renewal source invalid or expired')
        new=self._retain(raw)
        if new.retained_until_us<=old.retained_until_us:raise EvidenceError('segment renewal did not extend custody')
        with self.journal.connect() as c:c.execute('INSERT INTO segments VALUES(?,?,?,?,?)',(start,end,new.content_digest,canonical_bytes(new.as_dict()),new.retained_until_us))
        return new

    def renew_batch(self,start=0,limit=64):
        """Off-path grouped receipt selection may scan segment history.

        At most64 complete objects are fetched/re-retained per call. This is
        not a claim of bounded internal SQLite selection work.
        """
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=64:raise EvidenceError('segment renewal batch')
        with self.journal.connect() as c:rows=c.execute('SELECT start,end FROM segments WHERE start>=? GROUP BY start,end ORDER BY start LIMIT ?',(start,limit+1)).fetchall()
        for begin,end in rows[:limit]:self.renew(begin,end)
        return (rows[min(limit,len(rows))-1][1] if rows else start),len(rows)<=limit
