"""Scheduling cooperation cannot publish a partial or expired audit as complete."""
import pytest
from test_evidence_service_formats import case
from test_evidence_audit_010 import auditor
from regulated_core import evidence_audit
from regulated_core.evidence_service import EvidenceError


def test_receiving_check_during_yield_refuses_partial_sweep(auditor,monkeypatch):
    audit,head,raw,clock=auditor
    seen=[]
    def receive(_):
        seen.append(audit.tree.frontier.size)
        with pytest.raises(EvidenceError):audit.check()
    monkeypatch.setattr(evidence_audit,'_yield_cpu',receive)
    audit.begin(head)
    assert audit.step()
    assert seen==list(range(1,head.tree_size+1))
    assert audit.tree.root().hex()==head.tree_root and audit.map.root.hex()==head.map_root
    audit.check()


def test_scheduler_delay_does_not_waive_sweep_deadline(auditor,monkeypatch):
    audit,head,raw,clock=auditor
    monkeypatch.setattr(evidence_audit,'_yield_cpu',lambda _:setattr(clock,'value',clock.value+501))
    audit.begin(head)
    with pytest.raises(EvidenceError):audit.step()
    with pytest.raises(EvidenceError):audit.check()


def test_corruption_after_scheduling_yield_still_latches(auditor,monkeypatch):
    audit,head,raw,clock=auditor
    def receiving_turn(_):raw[1]=b'{}'
    monkeypatch.setattr(evidence_audit,'_yield_cpu',receiving_turn)
    # Fetch one record at a time so a later batch sees changed source bytes.
    audit.begin(head);assert not audit.step(1)
    with pytest.raises(EvidenceError):audit.step(1)
    with pytest.raises(EvidenceError):audit.journal.check()
