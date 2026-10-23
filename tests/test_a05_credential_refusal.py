"""Ordinary local certificate availability and expiry at the intact review gate."""

import os
import time
from dataclasses import replace

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.approval_evidence import ReviewError
from regulated_core.canonical import canonical_bytes
from regulated_core.certificates import issue_certificate
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Ed25519Signer
from test_education_session_release import reviewed_context


def scene(tmp_path):
    keys = {}

    def signer(key_id):
        key = Ed25519Signer(key_id)
        keys[key_id] = key
        return key

    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path, signer_factory=signer)
    return app, keys["reference-host-fixture:issuer"]


@pytest.mark.parametrize("case", ["missing-certificate", "expired-certificate"])
def test_unavailable_current_credential_cannot_add_a_review_grant(tmp_path, case):
    app, issuer = scene(tmp_path)
    requester = app.gates["requester"]
    opened = requester.open_review(spec=app.spec, contract=app.contract, context=app.context)
    if case == "missing-certificate":
        principal = "uncertified-teacher"
        app.sessions.provision_identity("school-a", principal, principal, "fictional-password-003")
        identity = app.sessions.authenticate("school-a", app.sessions.login(
            "school-a", principal, "fictional-password-003"))
        reviewer = app.make_gate(identity)
    else:
        principal, reviewer = "teacher", app.gates["teacher"]
        reviewer._credverify._registry.present(issue_certificate(
            issuer, subject_id=principal, role="teacher", jurisdiction="ZA",
            expires_at_us=app.clock.now_us() - 1,
        ))
    with pytest.raises((ReviewError, CredentialError)):
        reviewer.grant_review(
            spec=app.spec, contract=app.contract, review_id=opened["review_id"], role="teacher",
            context=replace(app.context, actor_id=principal, now_us=app.clock.now_us()),
        )
    retained = app.stores.reviews.get("school-a", opened["review_id"])
    assert retained["grants"] == [] and retained["credential_receipts"] == []
    context = replace(app.context, approval=opened["review_id"], now_us=app.clock.now_us())
    answer = requester.authorize_release(
        spec=app.spec, contract=app.contract, context=context,
        out_path=str(app.path), artifact=app.body,
    )
    assert not answer.allowed and answer.permit is None and not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")
    (tmp_path / "a05-credential-refusal.json").write_bytes(canonical_bytes({
        "case": case, "retained_review": retained, "reason": answer.reason,
        "allowed": answer.allowed, "target_exists": app.path.exists(),
        "scope": "Fictional local certificate-backed review boundary; no external identity claim",
    }))


def test_retained_credential_receipt_expiry_refuses_release_without_refresh(tmp_path):
    app, issuer = scene(tmp_path)
    expires = app.clock.now_us() + 5_000_000
    app.gates["teacher"]._credverify._registry.present(issue_certificate(
        issuer, subject_id="teacher", role="teacher", jurisdiction="ZA",
        expires_at_us=expires,
    ))
    context = reviewed_context(app)
    before = app.stores.reviews.get("school-a", context.approval)
    assert len(before["grants"]) == len(before["credential_receipts"]) == 2
    teacher, = [r for r in before["credential_receipts"] if r["subject_id"] == "teacher"]
    assert teacher["expires_at_us"] == expires
    timeout = time.monotonic() + 8
    while app.clock.now_us() < expires and time.monotonic() < timeout:
        time.sleep(0.02)
    now = app.clock.now_us()
    assert expires <= now < app.report.expires_at_us
    assert now < app.identities["requester"].expires_at_us
    answer = app.gates["requester"].authorize_release(
        spec=app.spec, contract=app.contract, context=replace(context, now_us=now),
        out_path=str(app.path), artifact=app.body,
    )
    assert not answer.allowed and answer.permit is None
    assert not app.path.exists()
    after = app.stores.reviews.get("school-a", context.approval)
    assert after["credential_receipts"] == before["credential_receipts"]
    assert app.stores.recorder.verify_chain("school-a")
    (tmp_path / "a05-credential-refusal.json").write_bytes(canonical_bytes({
        "case": "retained-receipt-expired", "retained_receipts": after["credential_receipts"],
        "credential_expiry_us": expires, "checked_at_us": now,
        "qualification_expiry_us": app.report.expires_at_us, "reason": answer.reason,
        "allowed": answer.allowed, "target_exists": app.path.exists(),
        "scope": "Real local time passes a short signed fixture certificate deadline; guards unchanged",
    }))
