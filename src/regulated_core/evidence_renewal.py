"""Off-path full retention renewal with explicit per-batch work and byte caps."""
from hashlib import sha256
from .clock import read_clock
from .evidence_service import EvidenceError
from .evidence_encoding import loads,canonical_bytes

class RetentionRenewal:
    def __init__(self,*,journal,worm,tenant,clock,retain_us,max_object_bytes=2097152):
        if type(retain_us) is not int or retain_us<=0 or not 0<max_object_bytes<=4194304:raise EvidenceError('renewal configuration')
        self.journal=journal;self.worm=worm;self.tenant=tenant;self.clock=clock;self.retain_us=retain_us;self.max_bytes=max_object_bytes
    def batch(self,start,limit=64):
        from .worm import WormReceipt
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=64:raise EvidenceError('renewal batch bound')
        self.journal.check();size,_=self.journal.watermark()
        with self.journal.connect() as c:rows=c.execute('SELECT seq,digest,receipt FROM retained WHERE seq>=? AND seq<? ORDER BY seq LIMIT ?',(start,size,limit)).fetchall()
        for expected,(seq,digest,doc) in enumerate(rows,start):
            if seq!=expected:raise EvidenceError('renewal gap')
            old=WormReceipt(**loads(bytes(doc)));raw=self.worm.fetch(self.tenant,old.object_ref)
            if type(raw) is not bytes or len(raw)>self.max_bytes or sha256(raw).hexdigest()!=old.content_digest or not self.worm.verify(old):raise EvidenceError('retained renewal source invalid')
            logical=raw
            if sha256(logical).hexdigest()!=digest:
                bundle=loads(raw)
                if bundle.get('schema')!='regulated/ns-retention/v1' or bundle.get('scope_id')!=self.tenant or bundle.get('version')!=seq+1:raise EvidenceError('namespace renewal binding')
                logical=canonical_bytes(bundle['transition'])
                if sha256(logical).hexdigest()!=digest:raise EvidenceError('namespace renewal transition mismatch')
            now=read_clock(self.clock).now_us
            if now>=old.retained_until_us:raise EvidenceError('retention already expired; cannot silently recover custody')
            new=self.worm.anchor(self.tenant,raw,retain_us=self.retain_us,now_us=now)
            if not self.worm.verify(new) or new.content_digest!=old.content_digest or new.retained_until_us<now+self.retain_us or self.worm.fetch(self.tenant,new.object_ref)!=raw:raise EvidenceError('renewed receipt invalid')
            self.journal.renew_retained(seq,logical,new)
        return start+len(rows),size
    def finish(self):return self.journal.finish_renewal()
