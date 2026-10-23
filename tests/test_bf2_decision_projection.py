"""One normal signed release binds its licence receipts into both DSSE verifiers.

Synthetic identities, local certificate registry and local keys only.
No malformed authority, guard replacement or external provider is used.
"""

import copy
import json

from securesystemslib.dsse import Envelope

from assurance_reference.projections import project
from regulated_core.approval_evidence import _credential, _grant
from regulated_core.canonical import canonical_bytes
from regulated_core.certificates import DEMONSTRATION_CERTIFICATE
from regulated_core.reporting import verify_dsse_attestation
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_a05_actual_production_gate import compose
from test_education_session_release import reviewed_context
from test_external_attestation import external_key


def test_one_committed_decision_retains_approval_time_receipts_in_both_dsse_verifiers(tmp_path):
    app, authority = compose(tmp_path)
    context = reviewed_context(app)
    gate = app.gates["requester"]
    decision = gate.authorize_release(
        spec=app.spec, contract=app.contract, out_path=str(app.path),
        context=context, artifact=app.body,
    )
    assert decision.allowed and decision.permit is not None, decision.reason
    retained = app.stores.reviews.get(context.tenant, context.approval)
    receipts = tuple(_credential(raw) for raw in retained["credential_receipts"])
    grants = tuple(_grant(raw) for raw in retained["grants"])
    assert len(receipts) == len(grants) == 2
    by_digest = {receipt.digest(): receipt for receipt in receipts}
    for grant in grants:
        receipt = by_digest[grant.credential_receipt_digest]
        assert receipt.subject_id == grant.reviewer_id
        assert receipt.tenant == context.tenant
        assert receipt.licence_type == DEMONSTRATION_CERTIFICATE
        assert receipt.verified_at_us <= grant.granted_at_us < receipt.expires_at_us
    receipt_bytes = canonical_bytes(receipts)
    assert canonical_bytes(decision.evidence["approval_credential_receipts"]) == receipt_bytes
    permit = decision.permit.permit.permit
    digests = tuple(sorted(report.digest() for report in authority.reports.values()))
    assert permit.qualification_digests == digests
    lineage = decision.evidence["qualification_lineage"]
    assert tuple(sorted(report["report_digest"] for report in lineage["reports"])) == digests
    assert lineage["decision_record_hash"] == decision.permit.envelope.record_hash

    outcome = gate.commit_release(
        spec=app.spec, contract=app.contract, decision=decision,
        artifact=app.body, out_path=str(app.path), context=context,
    )
    assert outcome.state == "committed", outcome
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(context.tenant)
    after = app.stores.reviews.get(context.tenant, context.approval)
    assert after["credential_receipts"] == retained["credential_receipts"]

    source = json.loads(canonical_bytes({
        "entries": app.stores.recorder.entries(context.tenant),
        "public_keys": app.public_keys,
        "release_evidence": decision.evidence,
        "scope": "One synthetic local certificate-backed committed release",
    }))
    before = copy.deepcopy(source)
    signer = Ed25519Signer("fixture:bf2-report")
    views = project(source, signer, complete=True,
                    system_name="Synthetic reference", provider="Local test fixture")
    envelope = views["attestation"]
    trust = TrustDirectory()
    trust.register_signer(signer)
    assert verify_dsse_attestation(trust, envelope)
    external = Envelope.from_dict(copy.deepcopy(envelope))
    key = external_key(signer)
    assert external.verify([key], threshold=1) == {signer.key_id: key}
    predicate = json.loads(external.payload)["predicate"]
    assert predicate["source_bundle"] == before == source
    evidence = predicate["source_bundle"]["release_evidence"]
    assert canonical_bytes(evidence["approval_credential_receipts"]) == receipt_bytes
    assert evidence["qualification_lineage"] == lineage
    assert predicate["audit"] == views["audit"]
    assert predicate["regulator"] == views["regulator"]
    assert views["regulator"]["application_evidence_complete"] is False
