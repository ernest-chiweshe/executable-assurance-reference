"""Staged Education pack-gate tier-four matrix using intact authority paths."""
from dataclasses import fields, replace
import os
import time

import pytest

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from regulated_core.persistence_pg import PostgresClearanceStore
from regulated_core.signing import Ed25519Signer
from regulated_core.tier4 import issue_clearance
from synthetic_tier4_education import build_tier4_education_fixture, SYNTHETIC_PUBLISHER


class FictionalDirectory:
    def __init__(self, case):
        self.case = case

    def reporting_line(self, tenant_id, subject_id):
        if tenant_id != "school-a":
            return None
        if subject_id == "teacher":
            return "fictional-teaching"
        if subject_id == "head" and self.case != "unknown-line":
            return "fictional-teaching" if self.case == "same-line" else "fictional-assurance"
        return None


CASES = (
    ("lawful", 2, None),
    ("one-reviewer", 1, "quorum"),
    ("same-line", 2, "TIER4_SAME_REPORTING_LINE"),
    ("unknown-line", 2, "TIER4_REPORTING_LINE_UNKNOWN"),
    ("no-clearance", 2, "TIER4_MONITOR_NOT_CLEARED"),
    ("cooling", 2, "TIER4_COOLING_OFF"),
)


@pytest.mark.parametrize("partitioned", [True], ids=["partitioned"])  # legacy profile refused since candidate 060
@pytest.mark.parametrize("case,reviewers,refusal", CASES, ids=[c[0] for c in CASES])
def test_education_tier4_pack_release(partitioned, case, reviewers, refusal, tmp_path):
    provision = provision_partitioned_local_roles if partitioned else provision_local_roles
    roles = provision(os.environ["FACTORY_TEST_DB_URL"])
    try:
        publisher = Ed25519Signer(SYNTHETIC_PUBLISHER)
        bundle = tmp_path / "synthetic-tier4-pack"
        build_tier4_education_fixture(bundle, publisher=publisher)
        keys = {}

        def fixture_signer(key_id):
            signer = Ed25519Signer(key_id)
            keys[key_id] = signer
            return signer

        period = 60_000_000 if case == "cooling" else 1_000_000
        app = build_education_fixture(
            roles, tmp_path / "application", partitioned_lifecycle=partitioned,
            signer_factory=fixture_signer, synthetic_pack_directory=bundle,
            synthetic_publisher=publisher, tier4_directory=FictionalDirectory(case),
            tier4_cooling_off_us=period)
        context = replace(app.context, nonce="a03-education-" + case, now_us=app.clock.now_us())
        gate = app.gates["requester"]
        assert gate.RISK_TIER == 4
        opened = gate.open_review(spec=app.spec, contract=app.contract, context=context)
        assert opened["minimum_approvers"] == 2
        actors = (("teacher", "teacher"), ("head", "head-of-department"))[:reviewers]
        for index, (principal, role) in enumerate(actors):
            state = app.gates[principal].grant_review(
                spec=app.spec, contract=app.contract, review_id=opened["review_id"], role=role,
                context=replace(context, actor_id=principal, now_us=app.clock.now_us()))
            assert state["status"] == ("approved" if index == 1 else "awaiting-review")
        context = replace(context, approval=opened["review_id"], now_us=app.clock.now_us())
        if refusal != "quorum":
            resolved = gate.resolve_review_context(spec=app.spec, contract=app.contract, context=context)
            approved = resolved.approval
            assert set(approved.certificate.approver_ids) == {"teacher", "head"}
            assert {receipt.subject_id for receipt in approved.credential_receipts} == {"teacher", "head"}
            if case != "no-clearance":
                clearance = issue_clearance(keys["reference-host-fixture:monitor"],
                    approved.envelope, cleared_at_us=app.clock.now_us())
                PostgresClearanceStore(pool=roles.monitor_ingress).put(clearance)
                assert app.stores.clearances.get(context.tenant, approved.envelope.record.record_id) == clearance
            end = approved.envelope.record.decided_at_us + period
            if case == "cooling":
                assert app.clock.now_us() < end
            else:
                deadline = time.monotonic() + 10
                while app.clock.now_us() < end:
                    assert time.monotonic() < deadline, "ordinary cooling-off wait exceeded its bound"
                    time.sleep(0.02)
        context = replace(context, now_us=app.clock.now_us())
        prior_record_ids = {env.record.record_id for env in app.stores.recorder.entries(context.tenant)}
        decision = gate.authorize_release(
            spec=app.spec, contract=app.contract, out_path=str(app.path), context=context, artifact=app.body)
        if refusal:
            assert not decision.allowed, decision
            assert decision.permit is None
            if refusal == "quorum":
                assert "quorum" in decision.reason
            else:
                matching = [
                    envelope.record for envelope in app.stores.recorder.entries(context.tenant)
                    if envelope.record.record_id not in prior_record_ids
                    and envelope.record.tenant_id == approved.envelope.record.tenant_id
                    and envelope.record.correlation_id == approved.envelope.record.correlation_id
                    and envelope.record.action == approved.envelope.record.action
                ]
                assert matching, "expected new decision evidence bound to this attempt"
                assert any(refusal in record.decision.reason_codes for record in matching)
            assert not app.path.exists()
            assert not app.stores.permits.used(context.tenant, context.nonce)
        else:
            assert decision.allowed, decision.reason
            assert decision.permit.permit.permit.qualification_digests == (app.report.digest(),)
            result = gate.commit_release(spec=app.spec, contract=app.contract, decision=decision,
                artifact=app.body, out_path=str(app.path), context=context)
            assert result.state == "committed", result
            assert app.path.read_bytes() == app.body
            assert app.stores.permits.used(context.tenant, context.nonce)
            modified = app.path.stat().st_mtime_ns
            observed = gate.reconcile_release(spec=app.spec,
                artifact_sha256=decision.permit.permit.permit.output_digest,
                out_path=str(app.path), context=context, nonce=context.nonce)
            assert observed.state == "committed", observed
            assert app.path.stat().st_mtime_ns == modified
        assert app.stores.recorder.verify_chain(context.tenant)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
