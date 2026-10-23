import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from regulated_core.evidence_publication import SynchronousGroupCommit
from regulated_core.evidence_service import EvidenceError

class Publisher:
    def __init__(self):
        self.journal=SimpleNamespace(watermark=lambda:(64,1000));self.calls=0;self.entered=threading.Event();self.release=threading.Event()
    def publish(self,head):
        self.calls+=1;self.entered.set()
        if not self.release.wait(2):raise EvidenceError('fixture deadline')

def test_waiters_do_not_return_until_witness_publication_finishes():
    pub=Publisher();group=SynchronousGroupCommit(pub,lambda size:SimpleNamespace(tree_size=size),batch_size=8,wait_seconds=.05)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures=[pool.submit(group.wait_for,i) for i in range(8)]
        assert pub.entered.wait(1);assert not any(f.done() for f in futures)
        pub.release.set();assert all(f.result().tree_size==64 for f in futures)
    assert pub.calls==1

def test_retention_gap_rejects_even_when_publication_succeeds():
    pub=Publisher();pub.release.set();group=SynchronousGroupCommit(pub,lambda size:SimpleNamespace(tree_size=1),batch_size=1)
    with pytest.raises(EvidenceError):group.wait_for(1)

def test_pending_limit_rejects_excess_without_unbounded_work():
    pub=Publisher();group=SynchronousGroupCommit(pub,lambda size:SimpleNamespace(tree_size=size),batch_size=1,max_pending=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(group.wait_for,0);assert pub.entered.wait(1)
        second=pool.submit(group.wait_for,1)
        # Synchronize on the fixture queue, never time-based optimistic success.
        for _ in range(1000):
            with group.lock:queued=len(group.pending)
            if queued:break
            threading.Event().wait(.001)
        assert queued==1
        with pytest.raises(EvidenceError):group.wait_for(2)
        pub.release.set();assert first.result().tree_size==second.result().tree_size==64
