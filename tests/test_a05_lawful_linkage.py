"""One lawful certificate-backed approval and qualification linkage observation."""

from regulated_core.approval_evidence import _certificate, _credential, _grant
from regulated_core.canonical import canonical_bytes
from regulated_core.certificates import DEMONSTRATION_CERTIFICATE
from test_education_session_release import education, approved_request  # noqa: F401

# ruff: noqa: F811


def test_certificate_backed_approvals_and_qualification_bind_one_committed_release(education):
    app = education
    context, decision = approved_request(app)
    gate = app.gates["requester"]
    retained = app.stores.reviews.get(context.tenant, context.approval)
    assert retained is not None
    receipts = tuple(_credential(raw) for raw in retained["credential_receipts"])
    grants = tuple(_grant(raw) for raw in retained["grants"])
    certificate = _certificate(retained["certificate"])
    assert certificate is not None
    assert len(receipts) == len(grants) == 2
    assert {receipt.subject_id for receipt in receipts} == {"teacher", "head"}
    assert {receipt.role for receipt in receipts} == {"teacher", "head-of-department"}
    by_digest = {receipt.digest(): receipt for receipt in receipts}
    now = app.clock.now_us()
    for receipt in receipts:
        assert receipt.tenant == context.tenant
        assert receipt.licence_type == DEMONSTRATION_CERTIFICATE
        assert receipt.verified_at_us <= now < receipt.expires_at_us
        assert gate._credverify.verify_receipt(receipt, now_us=now)
    for grant in grants:
        receipt = by_digest[grant.credential_receipt_digest]
        assert receipt.subject_id == grant.reviewer_id
        assert receipt.verified_at_us <= grant.granted_at_us < receipt.expires_at_us
    assert gate._engine._approvals.verify_certificate(certificate)
    assert certificate.credential_receipt_digests == tuple(sorted(by_digest))
    assert set(certificate.approver_ids) == {"teacher", "head"}
    permit = decision.permit.permit.permit
    assert permit.qualification_digests == (app.report.digest(),)
    assert permit.expires_at_us <= app.report.expires_at_us
    assert decision.evidence["qualification_lineage"]["reports"][0]["report_digest"] == app.report.digest()
    assert permit.decision_record_hash == decision.permit.envelope.record_hash
    result = gate.commit_release(
        spec=app.spec, contract=app.contract, decision=decision, artifact=app.body,
        out_path=str(app.path), context=context,
    )
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(context.tenant)
    (app.path.parent / "a05-lawful-observation.json").write_bytes(canonical_bytes({
        "scope": "Fictional local certificate-backed approval and qualification linkage",
        "credential_receipts": receipts, "approval_grants": grants,
        "approval_certificate": certificate, "signed_permit": decision.permit.permit,
        "qualification_lineage": decision.evidence["qualification_lineage"],
        "outcome": result,
        "limits": ["No external identity provider or domain-validity claim.",
                   "This lawful case alone does not qualify the A05 refusal matrix."],
    }))
