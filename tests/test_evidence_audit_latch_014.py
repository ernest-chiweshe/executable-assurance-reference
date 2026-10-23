"""Malformed stored envelopes must latch, including decoder RuntimeError."""
import pytest
from test_evidence_service_formats import case
from test_evidence_audit_010 import auditor
from regulated_core.evidence_service import EvidenceError

@pytest.mark.parametrize('bad',[b'{}',b'{"record":{}}',b'{"record":null}'])
def test_invalid_decoded_envelope_latches(auditor,bad):
    audit,head,raw,clock=auditor
    audit.begin(head);assert not audit.step(1)
    raw[1]=bad
    with pytest.raises(EvidenceError):audit.step(1)
    with pytest.raises(EvidenceError):audit.journal.check()
