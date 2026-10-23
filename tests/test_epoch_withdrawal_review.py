"""Serialization preserves ordinarily issued supervisor evidence exactly."""
import pytest

from assurance_reference.epoch_withdrawal_admission import verify_supervisor_approval
from assurance_reference.epoch_withdrawal_review import decode_review, encode_review
from regulated_core.canonical import canonical_bytes
from regulated_core.persistence_pg import PersistenceError
from regulated_core.permit import EmissionError
from test_epoch_withdrawal_admission import composition


@pytest.mark.parametrize("count", [1, 2])
def test_retained_roundtrip_preserves_all_signed_bytes_and_verifies(count):
    app = composition(count)
    stored = encode_review("synthetic-tenant", app.parameters["change"], app.approved)
    change, restored = decode_review("synthetic-tenant", stored)
    assert change == app.parameters["change"]
    assert canonical_bytes(restored) == canonical_bytes(app.approved)
    assert verify_supervisor_approval(restored, **app.parameters, now_us=app.now) == (
        "supervisor-a", "supervisor-b")[:count]
    assert encode_review("synthetic-tenant", change, restored) == stored


def test_loading_retained_bytes_does_not_refresh_expired_receipt():
    app = composition()
    stored = encode_review("synthetic-tenant", app.parameters["change"], app.approved)
    _, restored = decode_review("synthetic-tenant", stored)
    now = restored.credential_receipts[0].expires_at_us
    with pytest.raises(EmissionError, match="supervisor receipt is stale"):
        verify_supervisor_approval(restored, **app.parameters, now_us=now)
    assert canonical_bytes(restored) == canonical_bytes(app.approved)


@pytest.mark.parametrize("value", [None, {}, {"schema": "unsupported"}])
def test_absent_or_unrecognized_storage_format_is_refused(value):
    with pytest.raises(PersistenceError):
        decode_review("synthetic-tenant", value)
