"""B-6.4 negative approval cases on actual restricted logins; fictional school, isolated PostgreSQL.

Adds the forged-authority-name and replayed (stale) certificate cases to the existing restricted-role suite
(test_education_session_release.py: lawful dual approval, same person in two roles, requester self-review,
cross-tenant reviewer; test_sole_owner_approval_pg.py: the labelled signed-policy self-approval case). Each refusal
stops at approval, leaves the review awaiting and releases nothing.
"""
from dataclasses import replace

import pytest

from regulated_core.approval_evidence import ReviewError
from regulated_core.certificates import issue_certificate
from regulated_core.signing import Ed25519Signer
from test_education_session_release import education  # noqa: F401


def _open(app):
    opened = app.gates["requester"].open_review(spec=app.spec, contract=app.contract, context=app.context)
    return {"spec": app.spec, "contract": app.contract, "review_id": opened["review_id"]}


def _refused_release(app, common):
    state = app.gates["requester"].get_review(**common, context=replace(app.context, now_us=app.clock.now_us()))
    assert state["status"] == "awaiting-review"
    refused = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), artifact=app.body, context=replace(app.context, approval=common["review_id"]))
    assert not refused.allowed and not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")


def _grant(app, common, principal, role):
    return app.gates[principal].grant_review(**common, role=role,
        context=replace(app.context, actor_id=principal, now_us=app.clock.now_us()))


def test_forged_authority_name_on_a_certificate_is_refused_at_approval(education):  # noqa: F811
    app = education
    common = _open(app)
    # A different key claims the registered issuer's name; its signature cannot verify under that trust anchor.
    impostor = Ed25519Signer(app.certificate_issuer_id)
    app.present_certificate(issue_certificate(impostor, subject_id="teacher", role="teacher", jurisdiction="ZA",
                                              expires_at_us=app.clock.now_us() + 60_000_000))
    with pytest.raises(ReviewError):
        _grant(app, common, "teacher", "teacher")
    _refused_release(app, common)


def test_replayed_expired_certificate_is_refused_at_approval(education):  # noqa: F811
    app = education
    common = _open(app)
    # A genuinely signed certificate whose validity has already ended, presented again.
    app.certify("teacher", "teacher", expires_at_us=app.clock.now_us() - 1)
    with pytest.raises(ReviewError):
        _grant(app, common, "teacher", "teacher")
    _refused_release(app, common)


def test_certificate_from_an_unregistered_issuer_does_not_qualify_the_reviewer(education):  # noqa: F811
    app = education
    common = _open(app)
    # The head's registered certificate is replaced by one from an issuer this installation never registered.
    app.present_certificate(issue_certificate(Ed25519Signer("fixture:unregistered-issuer"), subject_id="head",
                                              role="head-of-department", jurisdiction="ZA",
                                              expires_at_us=app.clock.now_us() + 60_000_000))
    _grant(app, common, "teacher", "teacher")
    with pytest.raises(ReviewError):
        _grant(app, common, "head", "head-of-department")
    _refused_release(app, common)
