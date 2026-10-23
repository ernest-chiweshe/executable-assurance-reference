"""Neutral existing workflow with real retained authority; no model/provider calls."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest

from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from factory.projectos.engine import ProjectEngineError
from factory.projectos.regulated import EmissionContext
from factory.verticals.product_spec.export import render_product_spec_markdown
from test_local_roles import roles  # noqa: F401

# ruff: noqa: F811


class ScriptedFactory:
    def run(self, prompt, profile, tenant, *, context):
        assert profile.gate_checks == frozenset({"input-guardrail", "grounded-critic"})
        return SimpleNamespace(output=("A fictional workshop needs a local inventory tool. "
            "Users record each item, its location and the date of the latest count. "
            "The proposed workflow keeps a readable history and requires a second person to review changes. "
            "A successful trial lets staff find a listed item and reconcile an incorrect count. "
            "The interface displays the current count, previous entries and the reason for each adjustment. "
            "Acceptance checks cover missing names, duplicated identifiers, stale updates and unavailable storage. "
            "This text is a scripted test fixture, with no generated model verdict or product validation claim."),
            accepted=True, gate_reason="Explicit scripted fixture verdict", run_id="offline-product-fixture",
            cost_usd=0, harness_name="scripted-no-provider")


@pytest.fixture
def product(roles, tmp_path):
    c = build_product_spec_fixture(roles, tmp_path, factory=ScriptedFactory())
    c.engine.new("inventory", title="Fictional inventory", idea="A local workshop fixture")
    for stage in ("problem", "solution", "scope", "spec"):
        c.engine.run_stage("inventory", stage, tenant=c.tenant)
    c.context = EmissionContext(tenant=c.tenant, actor_id="requester", project_id="inventory",
        vertical_name=c.spec.name, action_id="release", nonce="fixture-release",
        now_us=c.clock.now_us(), not_after_us=c.clock.now_us() + 30_000_000, release_target=str(c.path))
    _, assembled = c.engine.assemble("inventory", tenant=c.tenant, context=c.context)
    assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
    return c


def approve(c):
    contract = c.engine.governed_contract("inventory", tenant=c.tenant, context=c.context)
    opened = c.engine.open_review("inventory", context=c.context)
    granted = c.gates["reviewer"].grant_review(spec=c.spec, contract=contract,
        context=replace(c.context, actor_id="reviewer", now_us=c.clock.now_us()),
        review_id=opened["review_id"], role="reviewer")
    assert granted["status"] == "approved"
    return replace(c.context, approval=opened["review_id"])


def test_product_spec_releases_through_shared_authority_without_domain_pack(product):
    c = product
    context = approve(c)
    expected = render_product_spec_markdown(c.engine.contract("inventory"))
    result = c.engine.release("inventory", str(c.path), context=context)
    assert Path(result) == c.path.resolve()
    assert c.path.read_text(encoding="utf-8") == expected
    saved = c.state.load("inventory")
    assert all(saved["stages"][name]["accepted"] for name in ("problem", "solution", "scope", "spec"))
    assert saved["release_outcomes"][-1]["state"] == "committed"
    assert c.domain_packs == ()
    with c.stores.pool.connection() as connection:
        # Partitioned lifecycle (candidate 060): the receiving login has no access to the shared legacy store.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("SELECT count(*) FROM pack_lifecycle")
    assert c.gates["requester"].pinning["pack_version"].startswith("document:")
    assert c.stores.recorder.verify_chain(c.tenant)
    modified = c.path.stat().st_mtime_ns
    assert c.engine.release("inventory", str(c.path), context=context) == result
    assert c.path.stat().st_mtime_ns == modified
    observed = c.engine.observe_release("inventory", str(c.path), context=context)
    assert observed.outcome.state == "committed"


def test_product_spec_requires_review_and_refuses_direct_export(product):
    c = product
    with pytest.raises(ProjectEngineError):
        c.engine.export("inventory", str(c.path))
    assert not c.path.exists()
    with pytest.raises(ProjectEngineError):
        c.engine.release("inventory", str(c.path), context=c.context)
    assert not c.path.exists()
    assert c.stores.recorder.verify_chain(c.tenant)


def test_product_spec_stub_stays_refused_at_readiness(product):
    c = product
    # A normal hand-edit changes the artifact; no guard or verdict is patched.
    c.engine.set_field("inventory", title="Incomplete fixture")
    c.engine.set_output("inventory", "spec", "Too short")
    _, assembled = c.engine.assemble("inventory", tenant=c.tenant, context=c.context)
    assert assembled["accepted"] is False
    assert assembled["regulated_draft"]["allowed"] is False
    assert not c.path.exists()
