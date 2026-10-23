"""Ordinary pack withdrawal at guarded delegation-review entry points.

Run only with the approved additive RulebookGate integration. Synthetic signed
pack and local lifecycle data; no guard replacement or direct authority edits.
"""
from dataclasses import replace
import os

import pytest

from a08_education_fixture import build_education_fixture
from a08_pack_withdrawal_fixture import PackWithdrawalFixture
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from regulated_core.delegation_review import DelegationRootExchange
from regulated_core.signing import Ed25519Signer
from synthetic_bounded_education import build_bounded_education_fixture, SYNTHETIC_PUBLISHER
from test_delegation_root_journey import unbound_receiving_source


@pytest.mark.parametrize("method", [
    "open_delegation_review", "get_delegation_review", "grant_delegation_review",
    "admit_delegation", "delegation_root",
])
def test_withdrawn_pack_refuses_delegation_operation_before_state_change(tmp_path, method):
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "signed-budget-pack"
    build_bounded_education_fixture(bundle, publisher=publisher)
    app = build_education_fixture(
        roles, tmp_path / "app", synthetic_pack_directory=bundle,
        synthetic_publisher=publisher, fixture_budget_limit=None,
        fixture_validity_us=600_000_000, partitioned_lifecycle=True,
        delegation_signer=Ed25519Signer("fictional:delegation-review"),
        delegation_source_status=unbound_receiving_source,
    )
    owner = app.gates["requester"]
    context = replace(app.context, nonce="withdrawal-root-contract", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opening = dict(destinations=(str(app.path),), expires_in_us=300_000_000,
                   admit_within_us=240_000_000, delegable=True)
    rid = DelegationRootExchange._id(context)
    request = dict(**common, delegation_review_id=rid)
    if method != "open_delegation_review":
        opened = owner.open_delegation_review(**common, context=context, **opening)
        assert opened["delegation_review_id"] == rid
    if method in ("admit_delegation", "delegation_root"):
        for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
            reviewed = app.gates[principal].grant_delegation_review(
                **request, role=role, context=replace(context, actor_id=principal,
                                                     now_us=app.clock.now_us()),
            )
        assert reviewed["status"] == "approved"
    if method == "delegation_root":
        admitted = owner.admit_delegation(**request, context=context)
        assert admitted["status"] == "admitted"
    before = app.stores.reviews.get(context.tenant, rid)
    PackWithdrawalFixture(roles, None, synthetic_bundle=bundle,
                          synthetic_publisher=publisher).withdraw()
    assert app.stores.activation.resolve_record(context.tenant, owner.pack.manifest.id) is None
    context = replace(context, now_us=app.clock.now_us())
    with pytest.raises(ValueError, match="pack is inactive, revoked"):
        if method == "open_delegation_review":
            owner.open_delegation_review(**common, context=context, **opening)
        elif method == "grant_delegation_review":
            app.gates["teacher"].grant_delegation_review(
                **request, role="teacher", context=replace(context, actor_id="teacher"),
            )
        else:
            getattr(owner, method)(**request, context=context)
    assert app.stores.reviews.get(context.tenant, rid) == before
    assert not app.path.exists()
    assert app.stores.budget.committed(context.tenant, app.contract["release_mission"]) == 0
    assert app.stores.recorder.verify_chain(context.tenant)
