from dataclasses import replace
import pytest
from assurance_reference.local_retention import LocalRetentionStore
from regulated_core.evidence_publication import PublicationJournal
from regulated_core.evidence_renewal import RetentionRenewal
from regulated_core.evidence_service import EvidenceError
from test_evidence_service_formats import Clock

def test_partial_renewal_does_not_claim_whole_prefix_extended(tmp_path):
    clock=Clock();worm=LocalRetentionStore(tmp_path/'worm');journal=PublicationJournal(tmp_path/'journal.db')
    for i in range(3):
        raw=str(i).encode();receipt=worm.anchor('t',raw,retain_us=1000,now_us=100);journal.mark_retained(i,raw,receipt)
    assert journal.watermark()==(3,1100)
    clock.value=200;renew=RetentionRenewal(journal=journal,worm=worm,tenant='t',clock=clock,retain_us=2000)
    assert renew.batch(0,2)==(2,3)
    assert renew.finish()==(3,1100)
    assert renew.batch(2,2)==(3,3)
    assert renew.finish()==(3,2200)
    assert PublicationJournal(journal.path).watermark()==(3,2200)

def test_expired_custody_cannot_be_silently_recreated(tmp_path):
    clock=Clock();worm=LocalRetentionStore(tmp_path/'worm');journal=PublicationJournal(tmp_path/'journal.db')
    receipt=worm.anchor('t',b'body',retain_us=100,now_us=100);journal.mark_retained(0,b'body',receipt)
    clock.value=200
    with pytest.raises(EvidenceError):RetentionRenewal(journal=journal,worm=worm,tenant='t',clock=clock,retain_us=1000).batch(0)
    assert journal.watermark()==(1,200)

def test_renewal_refuses_logical_byte_change(tmp_path):
    worm=LocalRetentionStore(tmp_path/'worm');journal=PublicationJournal(tmp_path/'journal.db')
    receipt=worm.anchor('t',b'body',retain_us=1000,now_us=100);journal.mark_retained(0,b'body',receipt)
    with pytest.raises(EvidenceError):journal.renew_retained(0,b'other',replace(receipt,retained_until_us=3000))
