"""Ordinary application tier matrix, staged for restricted local PostgreSQL.

All principals and documents are fictional. No guard is replaced. Cooling-off
uses elapsed database time; this file does not supply a clock or shorten a live
policy. Collection alone is not runtime qualification.
"""
from dataclasses import fields, replace
import os
from pathlib import Path
import time

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from factory.projectos.engine import ProjectEngineError
from factory.projectos.regulated import EmissionContext
from factory.verticals.product_spec.export import render_product_spec_markdown
from regulated_core.approval_exchange import ReviewError
from regulated_core.persistence_pg import PostgresClearanceStore
from regulated_core.signing import Ed25519Signer
from regulated_core.tier4 import issue_clearance
from test_product_spec_authority import ScriptedFactory


class FictionalDirectory:
    def __init__(self):
        self.lines = {}

    def reporting_line(self, tenant_id, subject_id):
        return self.lines.get((tenant_id, subject_id))


CASES = (
    ("tier3-one-reviewer", 3, 1, None),
    ("tier3-no-reviewer", 3, 0, "quorum"),
    ("tier4-lawful", 4, 2, None),
    ("tier4-one-reviewer", 4, 1, "quorum"),
    ("tier4-same-line", 4, 2, "TIER4_SAME_REPORTING_LINE"),
    ("tier4-unknown-line", 4, 2, "TIER4_REPORTING_LINE_UNKNOWN"),
    ("tier4-no-clearance", 4, 2, "TIER4_MONITOR_NOT_CLEARED"),
    ("tier4-cooling", 4, 2, "TIER4_COOLING_OFF"),
)


@pytest.mark.parametrize("partitioned", [True], ids=["partitioned"])  # legacy profile refused since candidate 060
@pytest.mark.parametrize("case,tier,reviewers,refusal", CASES, ids=[c[0] for c in CASES])
def test_actual_product_application_tier_controls(partitioned, case, tier, reviewers, refusal, tmp_path):
    provision = provision_partitioned_local_roles if partitioned else provision_local_roles
    roles = provision(os.environ["FACTORY_TEST_DB_URL"])
    try:
        directory = FictionalDirectory()
        keys = {}

        def fixture_signer(key_id):
            key = Ed25519Signer(key_id)
            keys[key_id] = key
            return key

        period = 60_000_000 if case == "tier4-cooling" else 1_000_000
        app = build_product_spec_fixture(
            roles, tmp_path, factory=ScriptedFactory(), partitioned_lifecycle=partitioned,
            signer_factory=fixture_signer, fixture_risk_tier=tier,
            tier4_directory=directory if tier == 4 else None,
            tier4_cooling_off_us=period if tier == 4 else 0)
        directory.lines[(app.tenant, "reviewer")] = "fictional-product"
        if case != "tier4-unknown-line":
            directory.lines[(app.tenant, "independent_reviewer")] = (
                "fictional-product" if case == "tier4-same-line" else "fictional-assurance")
        app.engine.new("inventory", title="Fictional inventory", idea="A local workshop fixture")
        for stage in ("problem", "solution", "scope", "spec"):
            app.engine.run_stage("inventory", stage, tenant=app.tenant)
        now = app.clock.now_us()
        context = EmissionContext(
            tenant=app.tenant, actor_id="requester", project_id="inventory",
            vertical_name=app.spec.name, action_id="release", nonce="a03-" + case,
            now_us=now, not_after_us=now + 30_000_000, release_target=str(app.path))
        _, assembled = app.engine.assemble("inventory", tenant=app.tenant, context=context)
        assert assembled["accepted"] and assembled["regulated_draft"]["allowed"]
        contract = app.engine.governed_contract("inventory", tenant=app.tenant, context=context)
        opened = app.engine.open_review("inventory", context=context)
        actors = ("reviewer", "independent_reviewer")[:reviewers]
        for index, actor in enumerate(actors):
            granted = app.gates[actor].grant_review(
                spec=app.spec, contract=contract,
                context=replace(context, actor_id=actor, now_us=app.clock.now_us()),
                review_id=opened["review_id"], role=actor)
            expected = "approved" if index + 1 == (1 if tier == 3 else 2) else "awaiting-review"
            assert granted["status"] == expected
        context = replace(context, approval=opened["review_id"], now_us=app.clock.now_us())
        gate = app.gates["requester"]
        if refusal == "quorum":
            with pytest.raises(ReviewError, match="required quorum"):
                app.engine.release("inventory", str(app.path), context=context)
        else:
            resolved = gate.resolve_review_context(spec=app.spec, contract=contract, context=context)
            approved = resolved.approval
            assert len(set(approved.certificate.approver_ids)) == reviewers
            assert {receipt.subject_id for receipt in approved.credential_receipts} == set(actors)
            if tier == 4:
                if case != "tier4-no-clearance":
                    clearance = issue_clearance(keys["reference-host-fixture:monitor"],
                        approved.envelope, cleared_at_us=app.clock.now_us())
                    PostgresClearanceStore(pool=roles.monitor_ingress).put(clearance)
                    assert app.stores.clearances.get(app.tenant, approved.envelope.record.record_id) == clearance
                end = approved.envelope.record.decided_at_us + period
                if case == "tier4-cooling":
                    assert app.clock.now_us() < end
                else:
                    deadline = time.monotonic() + 10
                    while app.clock.now_us() < end:
                        assert time.monotonic() < deadline, "ordinary cooling-off wait exceeded its bound"
                        time.sleep(0.02)
            context = replace(context, now_us=app.clock.now_us())
            prior_record_ids = {env.record.record_id for env in app.stores.recorder.entries(app.tenant)}
            if refusal:
                with pytest.raises(ProjectEngineError):
                    app.engine.release("inventory", str(app.path), context=context)
                matching = [
                    envelope.record for envelope in app.stores.recorder.entries(app.tenant)
                    if envelope.record.record_id not in prior_record_ids
                    and envelope.record.tenant_id == approved.envelope.record.tenant_id
                    and envelope.record.correlation_id == approved.envelope.record.correlation_id
                    and envelope.record.action == approved.envelope.record.action
                ]
                assert matching, "expected new decision evidence bound to this attempt"
                assert any(refusal in record.decision.reason_codes for record in matching)
            else:
                expected_body = render_product_spec_markdown(app.engine.contract("inventory"))
                result = app.engine.release("inventory", str(app.path), context=context)
                assert Path(result) == app.path.resolve()
                assert app.path.read_text(encoding="utf-8") == expected_body
                assert app.state.load("inventory")["release_outcomes"][-1]["state"] == "committed"
                assert app.stores.permits.used(app.tenant, context.nonce)
                modified = app.path.stat().st_mtime_ns
                assert app.engine.release("inventory", str(app.path), context=context) == result
                assert app.path.stat().st_mtime_ns == modified
        if refusal:
            assert not app.path.exists()
            assert not app.stores.permits.used(app.tenant, context.nonce)
        assert app.stores.recorder.verify_chain(app.tenant)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
