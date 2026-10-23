"""ProductSpec application gates with intact authority and synthetic PG state only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from application_budget_observation import BudgetSigningObserver, assert_recorded_budget_refusal
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from factory.projectos.governed_release import MISSION_FIELD, PREPARATION_FIELD
from factory.projectos.regulated import EmissionContext
from factory.tenant import TenantContext
from hashlib import sha256
from test_local_roles import roles  # noqa: F401
from test_product_spec_authority import ScriptedFactory

# ruff: noqa: F811


@pytest.fixture
def budget_product(roles, tmp_path):
    observer = BudgetSigningObserver(roles.allocator)
    app = build_product_spec_fixture(roles, tmp_path, factory=ScriptedFactory(),
                                     signer_factory=observer)
    app.engine.new("inventory", title="Fictional inventory", idea="A local workshop fixture")
    for stage in ("problem", "solution", "scope", "spec"):
        app.engine.run_stage("inventory", stage, tenant=app.tenant)
    app.context = EmissionContext(tenant=app.tenant, actor_id="requester", project_id="inventory",
        vertical_name=app.spec.name, action_id="release", nonce="budget-release",
        now_us=app.clock.now_us(), not_after_us=app.clock.now_us() + 30_000_000,
        release_target=str(app.path))
    _, assembled = app.engine.assemble("inventory", tenant=app.tenant, context=app.context)
    assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
    return app, observer


def reviewed(app, nonce):
    context = replace(app.context, nonce=nonce, now_us=app.clock.now_us())
    contract = app.engine.governed_contract("inventory", tenant=app.tenant, context=context)
    prepared = app.state.load("inventory")[PREPARATION_FIELD]
    app.body = app.engine._artifact_store.get(
        TenantContext(tenant_id=app.tenant, display_name=app.tenant),
        prepared["artifact_address"])
    assert sha256(app.body).hexdigest() == contract[PREPARATION_FIELD]["artifact_sha256"]
    opened = app.engine.open_review("inventory", context=context)
    assert opened["status"] == "awaiting-review"
    granted = app.gates["reviewer"].grant_review(spec=app.spec, contract=contract,
        context=replace(context, actor_id="reviewer", now_us=app.clock.now_us()),
        review_id=opened["review_id"], role="reviewer")
    assert granted["status"] == "approved"
    return replace(context, approval=opened["review_id"], now_us=app.clock.now_us()), contract


def authorize(app, context, contract):
    context = replace(context, now_us=app.clock.now_us())
    return app.gates["requester"].authorize_release(spec=app.spec, contract=contract,
        out_path=str(app.path), context=context, artifact=app.body)


def commit(app, context, contract, decision):
    context = replace(context, now_us=app.clock.now_us())
    return app.gates["requester"].commit_release(spec=app.spec, contract=contract,
        out_path=str(app.path), context=context, artifact=app.body, decision=decision)


def exhausted(app, decision):
    assert_recorded_budget_refusal(app, decision, "BUDGET_EXCEEDED", tenant=app.tenant)


def test_product_spec_reserves_before_signing_consumes_and_refuses_exhaustion(budget_product):
    app, observed = budget_product
    context, contract = reviewed(app, "first-budget-release")
    first = authorize(app, context, contract)
    assert first.allowed, first.reason
    permit = first.permit.permit.permit
    assert permit.mission == contract[MISSION_FIELD] and permit.budget_units == 1
    assert observed.signed == [(app.tenant, permit.mission, permit.budget_reservation)]
    assert app.stores.budget.committed(app.tenant, permit.mission) == 0
    assert not app.path.exists()
    assert commit(app, context, contract, first).state == "committed"
    assert app.path.read_bytes() == app.body
    assert app.stores.budget.committed(app.tenant, permit.mission) == 1
    # A fresh ordinary review binds the current target, retaining the host mission.
    second_context, second_contract = reviewed(app, "second-budget-release")
    assert second_contract[MISSION_FIELD] == permit.mission
    exhausted(app, authorize(app, second_context, second_contract))
    assert len(observed.signed) == 1 and app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain(app.tenant)


def test_product_spec_competing_last_unit_gives_one_authority_and_one_commit(budget_product):
    app, observed = budget_product
    requests = [reviewed(app, f"competing-budget-{i}") for i in range(2)]
    assert requests[0][1][MISSION_FIELD] == requests[1][1][MISSION_FIELD]
    start = Barrier(2)

    def compete(request):
        start.wait(timeout=20)
        return authorize(app, *request)

    with ThreadPoolExecutor(max_workers=2) as workers:
        decisions = list(workers.map(compete, requests))
    winners = [i for i, decision in enumerate(decisions) if decision.allowed]
    assert len(winners) == 1
    winner = winners[0]
    exhausted(app, decisions[1 - winner])
    assert len(observed.signed) == 1 and not app.path.exists()
    context, contract = requests[winner]
    assert commit(app, context, contract, decisions[winner]).state == "committed"
    assert app.path.read_bytes() == app.body
    assert app.stores.budget.committed(app.tenant, contract[MISSION_FIELD]) == 1
    assert app.stores.recorder.verify_chain(app.tenant)
