"""Signed synthetic product policies; no database or application release claim."""
import pytest

from assurance_reference.local_product_spec_fixture import (
    _product_spec_fixture_policy, build_product_spec_fixture)
from regulated_core.document_policy import DocumentPolicy
from regulated_core.policy_document import verify_document
from regulated_core.signing import Ed25519Signer, TrustDirectory


class SyntheticClock:
    def now_us(self):
        return 1_000_000


@pytest.mark.parametrize("tier", [3, 4])
def test_fixture_policy_is_signed_and_compiles_with_explicit_review_requirements(tier):
    signer = Ed25519Signer("fixture:product-policy:issuer")
    trust = TrustDirectory()
    trust.register_signer(signer)
    doc = _product_spec_fixture_policy(signer, SyntheticClock(), risk_tier=tier)
    assert verify_document(trust, doc, authority=signer.key_id)
    assert DocumentPolicy(doc).risk_tier == tier
    approval = doc.content["actions"]["product-spec:release"]["approval"]
    assert approval["minimum_approvers"] == (1 if tier == 3 else 2)
    assert approval["role_groups"] == (
        [["reviewer"]] if tier == 3 else [["reviewer"], ["independent_reviewer"]])
    assert approval["requester_may_approve"] is False
    assert doc.content["actions"]["product-spec:release"]["mission_budget"] == {"units": 1, "limit": 1}
    assert doc.content["actions"]["product-spec:release"]["required_outcomes"] == ["product-spec:readiness"]
    assert doc.effective_until_us - doc.effective_from_us == 120_000_000
    assert doc.policy_id == ("local-release" if tier == 3 else "local-release-tier4")
    assert doc.version == ("fixture-1" if tier == 3 else "fixture-tier4-1")


def test_tier_four_issue_does_not_change_prior_signed_tier_three_document():
    signer = Ed25519Signer("fixture:product-policy:issuer")
    baseline = _product_spec_fixture_policy(signer, SyntheticClock())
    prior_digest = baseline.digest()
    higher = _product_spec_fixture_policy(signer, SyntheticClock(), risk_tier=4)
    assert baseline.digest() == prior_digest
    assert higher.digest() != prior_digest
    assert baseline.content["risk_tier"] == 3
    assert baseline.content["actions"]["product-spec:release"]["approval"]["minimum_approvers"] == 1


@pytest.mark.parametrize("tier", [0, 1, 2, 5, True, 3.0, "4", None])
def test_unsupported_profile_fails_before_any_database_composition(tier):
    with pytest.raises(ValueError, match="exactly three or four"):
        build_product_spec_fixture(None, None, factory=None, fixture_risk_tier=tier)
