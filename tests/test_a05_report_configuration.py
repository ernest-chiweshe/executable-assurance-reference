"""Ordinary host configuration refusals with intact qualification guards."""

import os
from dataclasses import replace

import pytest

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.qualified_engine import QualificationSet
from regulated_core.canonical import canonical_bytes
from test_reference_host import render_request


@pytest.mark.parametrize("case,reason", [
    ("missing", "missing"),
    ("expired", "not current"),
    ("dataset-mismatch", "dataset differs"),
])
def test_host_report_configuration_refuses_before_permit_or_effect(tmp_path, case, reason):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, configured, report, keys = configuration(roles, tmp_path)
    reports = ()
    if case != "missing":
        if case == "expired":
            now = authorities.clock.now_us()
            report = replace(report, qualified_at_us=now - 20, expires_at_us=now - 10)
        else:
            report = replace(report, dataset_digest="f" * 64)
        report = replace(report, signature=keys["qualification"].sign(report.signed_body()))
        reports = (report,)
    qualifications = QualificationSet(
        trust=authorities.trust, authority=keys["qualification"].key_id,
        clock_domain=authorities.clock.domain, required=configured._required, reports=reports,
    )
    host = compose_reference_host(
        stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified",
    )
    _, answer, target, _ = render_request(host, tmp_path)
    assert not answer.authorized and answer.permit is None
    assert reason in answer.reason
    assert answer.envelope.record.decision.reason_codes == ("QUALIFICATION_REFUSED",)
    assert not target.path.exists()
    assert not (target.path.parent / ".commit-receipts").exists()
    assert not stores.permits.used("synthetic-host", "render")
    assert stores.budget.committed("synthetic-host", "synthetic:host-render") == 0
    assert stores.recorder.verify_entry(answer.envelope)
    assert stores.recorder.verify_chain("synthetic-host")
    (tmp_path / "a05-report-refusal.json").write_bytes(canonical_bytes({
        "case": case, "reason": answer.reason, "decision": answer.envelope,
        "report": report if reports else None, "target_exists": target.path.exists(),
        "limits": ["Host qualification refusal only; no credential-approval or deployed readiness claim."],
    }))
