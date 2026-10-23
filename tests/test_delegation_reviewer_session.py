"""Intact delegation-review session contract using synthetic retained sessions."""
from dataclasses import replace
import os

import pytest

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.approval_exchange import ReviewError
from regulated_core.signing import Ed25519Signer
from synthetic_bounded_education import build_bounded_education_fixture, SYNTHETIC_PUBLISHER
from test_delegation_root_journey import unbound_receiving_source


@pytest.mark.parametrize("principal,role", [
    ("teacher", "teacher"), ("head", "head-of-department"),
])
def test_revoked_reviewer_cannot_add_a_delegation_approval(tmp_path, principal, role):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "signed-budget-pack"
    build_bounded_education_fixture(bundle, publisher=publisher)
    app = build_education_fixture(
        roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
        fixture_budget_limit=None, fixture_validity_us=300_000_000,
        delegation_signer=Ed25519Signer("fictional:delegation-review"),
        delegation_source_status=unbound_receiving_source,
    )
    owner = app.gates["requester"]
    context = replace(app.context, nonce="root-session-contract", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opened = owner.open_delegation_review(
        **common, context=context, destinations=(str(app.path),),
        expires_in_us=60_000_000, admit_within_us=30_000_000, delegable=True,
    )
    request = dict(**common, delegation_review_id=opened["delegation_review_id"])
    before = owner.get_delegation_review(**request, context=context)
    assert before["approver_ids"] == [] and before["root_digest"] is None
    # Ordinary session lifecycle API; no credential, guard or retained row replaced.
    app.sessions.revoke(app.identities[principal])
    with pytest.raises(ReviewError, match="session authority changed"):
        app.gates[principal].grant_delegation_review(
            **request, role=role,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
        )
    after = owner.get_delegation_review(**request, context=context)
    assert after == before
    assert not app.path.exists()
    assert app.stores.budget.committed(context.tenant, before["proposal"]["root_mission"]) == 0
    assert app.stores.recorder.verify_chain(context.tenant)
