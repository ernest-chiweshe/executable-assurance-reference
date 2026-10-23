"""Normal reviewer session lifecycle through intact Education receiving guards."""
from dataclasses import fields
import os
import time

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from regulated_core.reviewer_sessions import SessionCredentialReceipt
from test_education_scoped_release import source_decision, commit
from test_education_session_release import approved_request


@pytest.mark.parametrize("principal", ["teacher", "head"])
@pytest.mark.parametrize("transition", ["revoke", "expire"])
def test_retained_reviewer_session_must_remain_current_at_release(tmp_path, principal, transition):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        app = build_education_fixture(roles, tmp_path, scoped_authority=True)
        if transition == "expire":
            token = app.sessions.login("school-a", principal + ".local", "fictional-password-001",
                                       ttl_us=8_000_000)
            identity = app.sessions.authenticate("school-a", token)
            app.identities[principal] = identity
            app.gates[principal] = app.make_gate(identity)
        source_decision(app)
        context, decision = approved_request(app)
        gate = app.gates["requester"]
        approved = gate.resolve_review_context(spec=app.spec, contract=app.contract, context=context).approval
        receipt = next(r for r in approved.credential_receipts if r.subject_id == principal)
        assert isinstance(receipt, SessionCredentialReceipt)
        assert receipt.reviewer_session.reference == app.identities[principal].reference
        original_digest = receipt.digest()
        if transition == "revoke":
            app.sessions.revoke(app.identities[principal])
        else:
            expires = receipt.reviewer_session.expires_at_us
            assert expires < decision.permit.permit.permit.expires_at_us
            timeout = time.monotonic() + 12
            while app.clock.now_us() < expires:
                assert time.monotonic() < timeout, "fixture expiry observation exceeded its bound"
                time.sleep(0.05)
        outcome = commit(app, context, decision)
        assert outcome.state == "failed", outcome
        assert not app.path.exists()
        assert receipt.digest() == original_digest
        assert app.stores.recorder.verify_chain("school-a")
    finally:
        for field in fields(roles):
            value = getattr(roles, field.name)
            if isinstance(value, LocalPool):
                value.close()
