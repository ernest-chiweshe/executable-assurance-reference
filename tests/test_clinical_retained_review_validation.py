"""Original signed membership receipts stay fixed during read-only revalidation."""
from types import SimpleNamespace

import pytest

from assurance_reference.clinical_review_admission import ClinicalReviewCredentials
from factory.health_ui.clinician_credentials import HealthIdentityProvider, HealthMembershipRegistry, RECEIPT_WINDOW_US
from factory.health_ui.identity import IdentityStore
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Ed25519Signer, TrustDirectory


def make(tmp_path):
    now = [1_800_000_000_000_000]
    member_store = IdentityStore(tmp_path / "members.json", clock=lambda: now[0] / 1e6)
    member = member_store.bootstrap_user("reviewer.local", "Fictional reviewer",
                                         "fictional-password-001", ["workspace"])
    signer = Ed25519Signer("fixture:retained-clinical-review")
    trust = TrustDirectory()
    trust.register_signer(signer)
    registry = HealthMembershipRegistry(member_store, workspace_id="workspace",
                                       jurisdiction="global", clock_us=lambda: now[0])
    credentials = ClinicalReviewCredentials(trust, signer, HealthIdentityProvider(member_store),
        registry, sessions=SimpleNamespace(admit_session=lambda *a, **k: None),
        reviewer_session_authority=SimpleNamespace(admit_many=lambda *a, **k: None),
        clock_us=lambda: now[0])
    receipt = credentials.verify(member.user_id, "workspace", "clinician",
                                  jurisdiction="global", now_us=now[0])
    return now, credentials, receipt, registry


def test_read_only_validation_preserves_original_signed_receipt_with_rolling_lookup(tmp_path):
    now, credentials, receipt, registry = make(tmp_path)
    original = receipt.digest()
    now[0] += 2_000_000
    assert registry.lookup(receipt.subject_id, receipt.role).expires_at_us > receipt.expires_at_us
    credentials.validate_review(receipt, contract={}, context=SimpleNamespace(tenant="workspace"))
    assert receipt.digest() == original


def test_elapsed_original_receipt_is_not_refreshed_by_current_membership(tmp_path):
    now, credentials, receipt, registry = make(tmp_path)
    now[0] = receipt.expires_at_us
    assert registry.lookup(receipt.subject_id, receipt.role).expires_at_us == now[0] + RECEIPT_WINDOW_US
    with pytest.raises(CredentialError, match="invalid or expired"):
        credentials.validate_review(receipt, contract={}, context=SimpleNamespace(tenant="workspace"))
