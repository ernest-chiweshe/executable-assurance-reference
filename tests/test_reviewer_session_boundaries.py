"""Signed synthetic receipt windows and explicit legacy migration behavior."""
import pytest

from assurance_reference.reviewer_session_admission import admit_reviewer_sessions
from regulated_core.approval_evidence import _credential, _data
from regulated_core.identity_provider import CredentialError, CredentialReceipt
from regulated_core.permit import EmissionError
from regulated_core.reviewer_sessions import issue_session_credential
from test_reviewer_group_admission import group, receipts  # noqa: F401


def test_receipt_deadline_precedes_session_and_permit(group, receipts):  # noqa: F811
    _, reader, clock, _ = group
    signed, source, trust, signer = receipts
    original = signed[0]
    short = issue_session_credential(signer, reviewer_session=original.reviewer_session,
        subject_id=original.subject_id, tenant=original.tenant, role=original.role,
        licence_type=original.licence_type, jurisdiction=original.jurisdiction,
        status="active", expires_at_us=200, verified_at_us=100, provider=original.provider)
    assert trust.verify(short.signed_body(), short.signature)
    with admit_reviewer_sessions(receipts=(short,), tenant="school", not_after_us=600,
                                sessions=source, trust=trust, signer_id=signer.key_id) as current:
        current()
        clock.now = 200
        assert clock.now < short.reviewer_session.expires_at_us
        with pytest.raises(EmissionError, match="expired"):
            current()
    assert reader.depth == 0


def test_valid_historical_receipt_decodes_but_needs_fresh_session_review(group, receipts):  # noqa: F811
    _, reader, _, _ = group
    signed, source, trust, signer = receipts
    old = signed[0]
    body = {key: value for key, value in old.signed_body().items() if key != "reviewer_session"}
    body["schema"] = "regulated/credential-receipt/v1"
    fields = {key: value for key, value in body.items() if key != "schema"}
    legacy = CredentialReceipt(signature=signer.sign(body), **fields)
    assert trust.verify(legacy.signed_body(), legacy.signature)
    decoded = _credential(_data(legacy))
    assert type(decoded) is CredentialReceipt and decoded == legacy
    with pytest.raises(CredentialError, match="signed retained session binding"):
        with admit_reviewer_sessions(receipts=(decoded,), tenant="school", not_after_us=600,
                                    sessions=source, trust=trust, signer_id=signer.key_id):
            pytest.fail("historical receipt needs a fresh authorized review")
    assert reader.connections == 0
