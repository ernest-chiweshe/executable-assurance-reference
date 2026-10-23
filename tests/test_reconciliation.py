"""Detached synthetic reconciliation records and real local signatures."""

from copy import deepcopy
from dataclasses import replace

import pytest

from assurance_reference.reconciliation import (
    EffectRecord, checkpoint, reconcile_records, verify_witnesses, witness_receipt,
)
from regulated_core.signing import Ed25519Signer, TrustDirectory


def record(**changes):
    return replace(EffectRecord("tenant-a", "release", "nonce-1", "a" * 64, "committed"), **changes)


def reconcile(decisions, receipts):
    return reconcile_records(decisions, receipts, tenant="tenant-a", start_seq=0, end_seq=1,
                             decision_source="signed-log-snapshot", receipt_source="target-snapshot")


@pytest.mark.parametrize("decisions,receipts,status", [
    ([record()], [record()], "MATCHED"),
    ([record(outcome="unknown")], [record()], "MATCHED"),
    ([record()], [], "MISSING_RECEIPT"),
    ([], [record()], "UNMATCHED_RECEIPT"),
    ([record()], [record(output_digest="b" * 64)], "CONFLICT"),
    ([record()], [record(outcome="not_committed")], "CONFLICT"),
    ([record()], [record(outcome="unknown")], "UNRESOLVED"),
])
def test_reconciliation_distinguishes_observation_states(decisions, receipts, status):
    result = reconcile(decisions, receipts)
    assert result["rows"][0]["status"] == status
    assert result["consistent_within_supplied_scope"] == (status == "MATCHED")


def test_empty_inputs_never_claim_consistency():
    assert not reconcile([], [])["consistent_within_supplied_scope"]


@pytest.mark.parametrize("records", [
    [record(), record()], [record(tenant="other")], [record(output_digest="bad")],
])
def test_invalid_snapshot_refuses(records):
    with pytest.raises(ValueError):
        reconcile(records, [])


def test_bounded_snapshot():
    with pytest.raises(ValueError, match="bound"):
        reconcile_records([record(), record(nonce="n2")], [], tenant="tenant-a", start_seq=0,
                          end_seq=1, decision_source="log", receipt_source="target", max_records=1)


@pytest.fixture
def signed():
    keys = [Ed25519Signer(name) for name in ("reporter", "witness-a", "witness-b")]
    trust = TrustDirectory()
    for key in keys:
        trust.register_signer(key)
    report = reconcile([record()], [record()])
    point = checkpoint(report, signer=keys[0], previous_digest="", created_us=10, expires_us=100)
    args = dict(trust=trust, issuer_key_id="reporter", tenant="tenant-a", previous_digest="", now_us=20)
    receipts = [witness_receipt(point, report, signer=key, **args) for key in keys[1:]]
    return report, point, receipts, args, keys


def verify(report, point, receipts, args):
    return verify_witnesses(point, report, receipts,
                            required_witness_ids=frozenset({"witness-a", "witness-b"}), **args)


def test_exact_report_with_two_local_witnesses(signed):
    report, point, receipts, args, _ = signed
    result = verify(report, point, receipts, args)
    assert result["verified_witness_ids"] == ["witness-a", "witness-b"]
    assert result["consistent_within_supplied_scope"]
    assert result["external_independence_proven"] is False


@pytest.mark.parametrize("mutation", ["report", "checkpoint", "witness", "duplicate", "missing", "stale", "prior", "tenant"])
def test_changed_or_incomplete_witness_material_refuses(signed, mutation):
    report, point, receipts, args, _ = deepcopy(signed[:4]) + (signed[4],)
    if mutation == "report":
        report["receipt_source"] = "another-source"
    elif mutation == "checkpoint":
        point["body"]["report_digest"] = "b" * 64
    elif mutation == "witness":
        receipts[0]["body"]["checkpoint_digest"] = "b" * 64
    elif mutation == "duplicate":
        receipts = [receipts[0], receipts[0]]
    elif mutation == "missing":
        receipts.pop()
    elif mutation == "stale":
        args["now_us"] = 100
    elif mutation == "prior":
        args["previous_digest"] = "b" * 64
    else:
        args["tenant"] = "another-tenant"
    with pytest.raises(ValueError):
        verify(report, point, receipts, args)


def test_issuer_cannot_supply_witness_identity(signed):
    report, point, _, args, keys = signed
    with pytest.raises(ValueError, match="distinct"):
        witness_receipt(point, report, signer=keys[0], **args)


def test_discrepancies_remain_visible_when_witnessed(signed):
    _, _, _, args, keys = signed
    report = reconcile([record()], [])
    point = checkpoint(report, signer=keys[0], previous_digest="", created_us=10, expires_us=100)
    receipts = [witness_receipt(point, report, signer=key, **args) for key in keys[1:]]
    assert not verify(report, point, receipts, args)["consistent_within_supplied_scope"]
    altered = deepcopy(report)
    altered["consistent_within_supplied_scope"] = True
    with pytest.raises(ValueError, match="reproduce"):
        checkpoint(altered, signer=keys[0], previous_digest="", created_us=10, expires_us=100)
