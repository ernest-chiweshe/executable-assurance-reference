"""Real signed-pack delegation review; synthetic people and local services only.

This stages the root-review journey. Receiving source provenance is deliberately
unbound and refuses all delegated effect admission in this fixture.
"""
from dataclasses import replace
import os

import pytest

from a08_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.approval_exchange import ReviewError
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer
from synthetic_bounded_education import build_bounded_education_fixture, SYNTHETIC_PUBLISHER


def unbound_receiving_source(tenant, grant_digest):
    raise EmissionError("this root-review fixture has no delegated project admission")


def test_authenticated_owner_and_two_reviewers_admit_one_root(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    assert roles.delegation_issuer.role != roles.receiver.role
    for pool, may_insert in ((roles.receiver, False), (roles.delegation_issuer, True)):
        with pool.connection() as connection:
            privileges = connection.execute(
                "SELECT has_table_privilege(current_user, 'regulated_delegation_grants_v1', 'SELECT'), "
                "has_table_privilege(current_user, 'regulated_delegation_grants_v1', 'INSERT'), "
                "has_table_privilege(current_user, 'regulated_delegation_grants_v1', 'UPDATE'), "
                "has_table_privilege(current_user, 'regulated_delegation_grants_v1', 'DELETE'), "
                "has_table_privilege(current_user, 'regulated_delegation_revocations_v1', 'INSERT')"
            ).fetchone()
        assert privileges == (True, may_insert, False, False, False)
    publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
    bundle = tmp_path / "signed-budget-pack"
    build_bounded_education_fixture(bundle, publisher=publisher)
    app = build_education_fixture(
        roles, tmp_path, synthetic_pack_directory=bundle, synthetic_publisher=publisher,
        fixture_budget_limit=None, fixture_validity_us=300_000_000,
        delegation_signer=Ed25519Signer("fictional:delegation-review"),
        delegation_source_status=unbound_receiving_source,
    )
    gate = app.gates["requester"]
    context = replace(app.context, nonce="root-review-journey", now_us=app.clock.now_us())
    common = dict(spec=app.spec, contract=app.contract)
    opened = gate.open_delegation_review(
        **common, context=context, destinations=(str(app.path),),
        expires_in_us=60_000_000, admit_within_us=30_000_000, delegable=True,
    )
    rid = opened["delegation_review_id"]
    assert opened["status"] == "awaiting-review"
    assert opened["owner_id"] == "requester"
    request = dict(**common, delegation_review_id=rid)
    with pytest.raises((ReviewError, ValueError), match="approval"):
        gate.admit_delegation(**request, context=context)
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        reviewed = app.gates[principal].grant_delegation_review(
            **request, role=role,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
        )
        if principal == "teacher":
            assert reviewed["status"] == "awaiting-review"
            with pytest.raises((ReviewError, ValueError), match="approval"):
                gate.admit_delegation(**request, context=context)
    assert reviewed["status"] == "approved"
    admitted = gate.admit_delegation(
        **request, context=replace(context, now_us=app.clock.now_us()),
    )
    assert admitted["status"] == "admitted"
    root = admitted["root"]
    assert root["subject"] == context.actor_id
    assert root["root_mission"] == opened["proposal"]["root_mission"]
    assert root["targets"] == opened["proposal"]["targets"]
    assert gate.admit_delegation(**request, context=context)["root"] == root
    assert gate.delegation_root(**request, context=context)["root"] == root
    assert not app.path.exists()
    assert app.stores.budget.committed(context.tenant, root["root_mission"]) == 0
    assert app.stores.recorder.verify_chain(context.tenant)
