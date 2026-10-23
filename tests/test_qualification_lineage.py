"""Offline historical permit-to-report resolution; no receiver or target exists."""

import copy
from dataclasses import replace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.qualification import QualificationError
from regulated_core.signing import Ed25519Signer
from regulated_core.target import SignedTargetPermit, TargetPermit
from test_qualified_engine import gate, report_case


def lineage_case():
    _, trust, report, requirement = report_case(now=100, duration=100)
    issuer = Ed25519Signer("fixture:permit-authority")
    trust.register_signer(issuer)
    permit = TargetPermit(tenant_id="fixture:tenant", principal="fixture:requester",
        mission="fixture:mission", budget_reservation="fixture:reservation", budget_units=1,
        policy_version="fixture:policy/1", decision_record_id="fixture:decision",
        decision_record_hash="a" * 64, approval_ref="fixture:approval", assertion_id="fixture:assertion",
        action_id="fixture:release", operation="write", target_kind="fixture:no-target",
        target_digest="b" * 64, expected_target_state="absent", output_digest="c" * 64,
        qualification_digests=(report.digest(),), revocation_epoch=0, expires_at_us=190,
        nonce="fixture:nonce", clock_domain="fixture:clock", issued_at_us=150)
    return gate(trust, report, requirement), issuer, permit, report


def signed(issuer, permit):
    return SignedTargetPermit(permit, issuer.sign(permit.signed_body()))


def test_retained_lineage_preserves_exact_signed_report_dataset_and_permit():
    configured, issuer, permit, report = lineage_case()
    envelope = signed(issuer, permit)
    before = canonical_bytes(envelope)
    result = configured.retained_lineage(envelope, permit_authority=issuer.key_id)
    assert canonical_bytes(result["signed_target_permit"]) == before == canonical_bytes(envelope)
    assert result["decision_record_hash"] == permit.decision_record_hash
    assert result["checked_at_issuance_us"] == 150
    row, = result["reports"]
    assert row["report_digest"] == report.digest()
    assert canonical_bytes(row["report"]) == canonical_bytes(report)
    assert row["dataset_reference"] == {"id": report.dataset_id, "version": report.dataset_version,
                                        "digest": report.dataset_digest}
    assert "no new execution authority" in result["limits"][0]
    # Detached returned JSON cannot mutate the pinned report or permit.
    before_result = copy.deepcopy(result)
    result["reports"][0]["report"]["dataset_id"] = "different"
    assert configured.retained_lineage(envelope, permit_authority=issuer.key_id) == before_result


@pytest.mark.parametrize("change", [
    {"qualification_digests": ()}, {"qualification_digests": ("f" * 64,)},
    {"issued_at_us": 99}, {"issued_at_us": 200, "expires_at_us": 210},
    {"expires_at_us": 201}, {"clock_domain": "fixture:other"},
    {"clock_domain": "", "issued_at_us": 0},
])
def test_signed_ordinary_contract_mismatch_cannot_claim_report_lineage(change):
    configured, issuer, permit, _ = lineage_case()
    with pytest.raises(QualificationError):
        configured.retained_lineage(signed(issuer, replace(permit, **change)), permit_authority=issuer.key_id)


def test_report_signature_and_host_report_trust_are_still_required():
    configured, issuer, permit, report = lineage_case()
    # A changed report is untrusted even when a signed fixture permit names its new digest.
    changed_report = replace(report, dataset_version="changed")
    configured._reports = (changed_report,)
    changed_permit = replace(permit, qualification_digests=(changed_report.digest(),))
    with pytest.raises(QualificationError, match="untrusted"):
        configured.retained_lineage(signed(issuer, changed_permit), permit_authority=issuer.key_id)


def test_expected_permit_authority_and_signed_content_are_required():
    configured, issuer, permit, _ = lineage_case()
    envelope = signed(issuer, permit)
    for candidate, expected in (
        (envelope, "fixture:other"), (envelope, ""),
        (replace(envelope, permit=replace(permit, principal="fixture:changed")), issuer.key_id),
        (signed(Ed25519Signer(issuer.key_id), permit), issuer.key_id),
    ):
        with pytest.raises(QualificationError, match="signature is untrusted"):
            configured.retained_lineage(candidate, permit_authority=expected)
