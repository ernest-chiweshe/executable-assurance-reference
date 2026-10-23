"""Actual Education pack-gate budgets under isolated PostgreSQL; fictional data only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from threading import Barrier

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from factory.projectos.governed_release import MISSION_FIELD, TARGET_FIELD
from regulated_core.signing import Ed25519Signer
from application_budget_observation import BudgetSigningObserver, assert_recorded_budget_refusal
from synthetic_bounded_education import build_bounded_education_fixture, SYNTHETIC_PUBLISHER


def build(tmp_path, mode):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    observer = BudgetSigningObserver(roles.allocator)
    options = {}
    if mode == "signed-pack":
        publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
        bundle = tmp_path / "bounded-pack"
        build_bounded_education_fixture(bundle, publisher=publisher)
        options = dict(synthetic_pack_directory=bundle, synthetic_publisher=publisher,
                       fixture_budget_limit=None)
    elif mode == "missing":
        options = dict(fixture_budget_limit=None)
    app = build_education_fixture(roles, tmp_path, signer_factory=observer, **options)
    return app, observer


def reviewed(app, nonce, contract):
    context = replace(app.context, nonce=nonce, now_us=app.clock.now_us())
    opened = app.gates["requester"].open_review(spec=app.spec, contract=contract, context=context)
    assert opened["status"] == "awaiting-review"
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        state = app.gates[principal].grant_review(spec=app.spec, contract=contract,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
    assert state["status"] == "approved"
    return replace(context, approval=opened["review_id"], now_us=app.clock.now_us())


def authorize(app, context, contract):
    context = replace(context, now_us=app.clock.now_us())
    return app.gates["requester"].authorize_release(spec=app.spec, contract=contract,
        out_path=str(app.path), context=context, artifact=app.body)


def commit(app, context, contract, decision):
    context = replace(context, now_us=app.clock.now_us())
    return app.gates["requester"].commit_release(spec=app.spec, contract=contract,
        out_path=str(app.path), context=context, artifact=app.body, decision=decision)


def refused_with(app, decision, code):
    assert_recorded_budget_refusal(app, decision, code, tenant=app.context.tenant)


@pytest.mark.parametrize("mode", ["host-default", "signed-pack"])
def test_education_reserves_before_signing_consumes_and_refuses_exhaustion(tmp_path, mode):
    app, observed = build(tmp_path, mode)
    context = reviewed(app, "first-release", app.contract)
    first = authorize(app, context, app.contract)
    assert first.allowed, first.reason
    permit = first.permit.permit.permit
    assert permit.budget_units == 1 and permit.mission == app.contract[MISSION_FIELD]
    assert observed.signed == [(context.tenant, permit.mission, permit.budget_reservation)]
    assert not app.path.exists()
    assert app.stores.budget.committed(context.tenant, permit.mission) == 0
    assert commit(app, context, app.contract, first).state == "committed"
    assert app.path.read_bytes() == app.body
    assert app.stores.budget.committed(context.tenant, permit.mission) == 1
    # An ordinary new review binds the now-current target state and the same mission.
    fresh = replace(app.context, nonce="second-release", now_us=app.clock.now_us())
    contract = {**app.contract, TARGET_FIELD: app.gates["requester"].describe_target(
        spec=app.spec, out_path=str(app.path), context=fresh)}
    second_context = reviewed(app, fresh.nonce, contract)
    refused_with(app, authorize(app, second_context, contract), "BUDGET_EXCEEDED")
    assert len(observed.signed) == 1 and app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(context.tenant)


@pytest.mark.parametrize("mode", ["host-default", "signed-pack"])
def test_education_competing_last_unit_gives_one_authority_and_one_commit(tmp_path, mode):
    app, observed = build(tmp_path, mode)
    contexts = [reviewed(app, f"competing-{i}", app.contract) for i in range(2)]
    start = Barrier(2)

    def compete(context):
        start.wait(timeout=20)
        return authorize(app, context, app.contract)

    with ThreadPoolExecutor(max_workers=2) as workers:
        decisions = list(workers.map(compete, contexts))
    winners = [i for i, decision in enumerate(decisions) if decision.allowed]
    assert len(winners) == 1
    winner = winners[0]
    refused_with(app, decisions[1 - winner], "BUDGET_EXCEEDED")
    assert len(observed.signed) == 1 and not app.path.exists()
    assert commit(app, contexts[winner], app.contract, decisions[winner]).state == "committed"
    assert app.path.read_bytes() == app.body
    assert app.stores.budget.committed(app.context.tenant, app.contract[MISSION_FIELD]) == 1
    assert app.stores.recorder.verify_chain(app.context.tenant)


def test_original_education_without_resolved_budget_refuses_at_real_gate(tmp_path):
    app, observed = build(tmp_path, "missing")
    context = reviewed(app, "unconfigured-budget", app.contract)
    refused_with(app, authorize(app, context, app.contract), "BUDGET_UNCONFIGURED")
    assert observed.signed == [] and not app.path.exists()
    assert not app.stores.permits.used(context.tenant, context.nonce)
    assert app.stores.recorder.verify_chain(context.tenant)
