"""Local snapshots and synthetic altered artifacts; no runtime guard removed."""

import copy
from dataclasses import replace

import pytest

from assurance_reference.governance_artifact import retain_governance_artifact, verify_governance_artifact
from regulated_core.governance_targets import GovernanceEvent, GovernanceLog
from regulated_core.worm import LocalWormStore, WormUnavailable


def event(index, tenant="synthetic-office"):
    return GovernanceEvent(tenant, "pack-activation", "fixture-pack", str(index) * 64,
                           "prior", "nonce-" + str(index), "decision-" + str(index), index)


def retained():
    log = GovernanceLog()
    for index in range(1, 4):
        log.append(event(index))
    root = log.root("synthetic-office")
    artifact = retain_governance_artifact(log, LocalWormStore(), "synthetic-office", retain_us=100, now_us=10)
    return artifact, root


def test_odd_event_snapshot_roundtrips_and_retains_exact_root():
    artifact, root = retained()
    assert verify_governance_artifact(artifact, expected_tenant="synthetic-office", expected_root=root)
    assert artifact["root_record"]["events"] == 3
    assert artifact["receipt"]["provider"] == "local-mock"
    assert artifact["receipt"]["retained_until_us"] == 110


@pytest.mark.parametrize("change", ["event", "order", "missing", "root", "tenant", "receipt"])
def test_altered_artifact_refuses_against_independent_root(change):
    artifact, root = retained()
    altered = copy.deepcopy(artifact)
    if change == "event":
        altered["events"][0]["decision_record_id"] = "different"
    elif change == "order":
        altered["events"].reverse()
    elif change == "missing":
        altered["events"].pop()
    elif change == "root":
        altered["root_record"]["root"] = "0" * 64
    elif change == "tenant":
        altered["events"][0]["tenant_id"] = "another-office"
    else:
        altered["receipt"]["content_digest"] = "0" * 64
    with pytest.raises(ValueError):
        verify_governance_artifact(altered, expected_tenant="synthetic-office", expected_root=root)


def test_snapshot_reads_source_log_once():
    class AdvancingLog:
        calls = 0

        def events(self, tenant):
            self.calls += 1
            return (event(1, tenant),) * self.calls

    log = AdvancingLog()
    artifact = retain_governance_artifact(log, LocalWormStore(), "synthetic-office", retain_us=100, now_us=10)
    assert log.calls == 1 and artifact["root_record"]["events"] == 1


def test_local_retention_outage_produces_no_artifact():
    store = LocalWormStore()
    store.set_available(False)
    with pytest.raises(WormUnavailable):
        retain_governance_artifact(GovernanceLog(), store, "synthetic-office", retain_us=100, now_us=10)


def test_exact_readback_checked_independently_of_provider_verification():
    class DifferentReadback(LocalWormStore):
        def fetch(self, tenant, object_ref):
            return b"different synthetic bytes"

    with pytest.raises(ValueError, match="read-back differs"):
        retain_governance_artifact(GovernanceLog(), DifferentReadback(), "synthetic-office", retain_us=100, now_us=10)


def test_short_retention_receipt_refuses():
    class ShortRetention(LocalWormStore):
        def anchor(self, tenant, data, *, retain_us, now_us):
            receipt = super().anchor(tenant, data, retain_us=retain_us, now_us=now_us)
            return replace(receipt, retained_until_us=now_us)

    with pytest.raises(ValueError, match="shorter than requested"):
        retain_governance_artifact(GovernanceLog(), ShortRetention(), "synthetic-office", retain_us=100, now_us=10)
