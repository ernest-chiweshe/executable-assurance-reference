"""Host-composed action retention and witness barrier, used by target issuance."""
from dataclasses import dataclass
from hashlib import sha256
from .clock import read_clock
from .evidence_encoding import canonical_bytes,loads
from .evidence_service import EvidenceError
from .evidence_publication import SynchronousGroupCommit
from .worm import WormReceipt

@dataclass(frozen=True)
class RetainedAction:
    tenant:str
    seq:int
    digest:str
    head:object
    dependencies:tuple
    receipt:object

class SharedEvidenceRuntime:
    def __init__(self,*,publisher_for,provider_for,worm,retain_us,dependency_barrier,
                 final_locks,final_checks,required_namespaces=(),batch_size=64,wait_seconds=.005):
        if type(retain_us) is not int or retain_us<=0:raise EvidenceError('retention duration')
        for f in (publisher_for,provider_for,dependency_barrier,final_locks,final_checks):
            if not callable(f):raise EvidenceError('incomplete shared evidence composition')
        self.publisher_for=publisher_for;self.provider_for=provider_for;self.worm=worm;self.retain_us=retain_us
        self.dependency_barrier=dependency_barrier;self.final_locks=final_locks;self.final_checks=final_checks
        self.required_namespaces=frozenset(required_namespaces);self.groups={}
        self.batch_size=batch_size;self.wait_seconds=wait_seconds
        import threading
        self._group_lock=threading.Lock()
    def cover(self,prepared,dependencies):
        envelope=prepared.decided.envelope;tenant=envelope.record.tenant_id
        if not self.required_namespaces.issubset({d.scope.namespace for d in dependencies}):raise EvidenceError('required namespace dependency missing')
        provider=self.provider_for(tenant);publisher=self.publisher_for(tenant)
        raw,head,path=provider.leaf(envelope)
        if raw!=canonical_bytes(envelope):raise EvidenceError('retention leaf differs from action')
        start,_=publisher.journal.watermark()
        if start<envelope.seq:
            if envelope.seq-start>256:raise EvidenceError('retention worker must catch up before issuance')
            for seq,prior_raw,prior_head,prior_path in provider.delta(start,envelope.seq,limit=256):
                publisher.retain(seq=seq,raw=prior_raw,head=prior_head,inclusion=prior_path,worm=self.worm,retain_us=self.retain_us)
        receipt=publisher.retain(seq=envelope.seq,raw=raw,head=head,inclusion=path,worm=self.worm,retain_us=self.retain_us)
        with self._group_lock:
            group=self.groups.get(tenant)
            if group is None:
                group=SynchronousGroupCommit(publisher,provider.head_at,batch_size=self.batch_size,wait_seconds=self.wait_seconds)
                self.groups[tenant]=group
        witnessed=group.wait_for(envelope.seq)
        self.dependency_barrier(prepared,dependencies)
        return RetainedAction(tenant,envelope.seq,sha256(raw).hexdigest(),witnessed,dependencies,receipt)
    def check_ticket(self,ticket,prepared,dependencies):
        envelope=prepared.decided.envelope
        if (type(ticket) is not RetainedAction or ticket.tenant!=envelope.record.tenant_id or ticket.seq!=envelope.seq
            or ticket.digest!=sha256(canonical_bytes(envelope)).hexdigest() or ticket.dependencies!=dependencies
            or ticket.head.tree_size<=ticket.seq):raise EvidenceError('retention ticket mismatch')
        pub=self.publisher_for(ticket.tenant);pub.journal.check();pub.audit_check()
        size,expiry=pub.journal.watermark();now=read_clock(pub.clock).now_us
        if size<=ticket.seq or now>=min(expiry,ticket.receipt.retained_until_us):raise EvidenceError('retention expired before permit')
        if not pub.policy.verify(ticket.head,current_only=True):raise EvidenceError('witnessed head no longer admitted')
        for dep in dependencies:
            scoped=self.dependency_barrier.publishers[dep.scope]
            scoped.journal.check();scoped.audit_check()
            retained,deadline=scoped.journal.watermark()
            if retained<dep.version or read_clock(scoped.clock).now_us>=deadline:raise EvidenceError('namespace retention expired before permit')
    def receipt_for(self,tenant,seq):
        with self.publisher_for(tenant).journal.connect() as c:
            row=c.execute('SELECT receipt FROM retained WHERE seq=?',(seq,)).fetchone()
        if row is None:raise EvidenceError('action receipt missing')
        return WormReceipt(**loads(bytes(row[0])))
