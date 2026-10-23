"""Detached signed local checkpoint observations; no witness service is called."""

from copy import deepcopy

import pytest

from assurance_reference.checkpoint_observations import observe_checkpoints
from assurance_reference.reconciliation import checkpoint, witness_receipt
from test_reconciliation import reconcile, record, signed as _signed_fixture


signed = _signed_fixture


def candidate(report, point, receipts):
    return {"checkpoint": point, "report": report, "receipts": receipts}


def observe(items, args, **changes):
    return observe_checkpoints(items, **{**args, "start_seq": 0, "end_seq": 1,
        "required_witness_ids": ("witness-a", "witness-b"), **changes})


def test_one_verified_observation_never_claims_complete_history(signed):
    report, point, receipts, args, _ = signed
    supplied = [candidate(report, point, receipts)]
    before = deepcopy(supplied)
    result = observe(supplied, args)
    assert result["status"] == "ONE_VERIFIED_CHECKPOINT_OBSERVED"
    assert not result["history_completeness_proven"]
    assert not result["external_independence_proven"]
    assert result["selected_checkpoint"] is None
    assert supplied == before


def test_duplicate_copy_is_not_a_second_witnessed_root(signed):
    report, point, receipts, args, _ = signed
    item = candidate(report, point, receipts)
    result = observe([item, deepcopy(item)], args)
    assert len(result["verified_checkpoints"]) == 1
    assert [r["status"] for r in result["observations"]] == ["VERIFIED", "DUPLICATE"]


@pytest.mark.parametrize("change", ["report", "issuance-time"])
def test_individually_valid_cosigned_branches_are_reported_without_winner(signed, change):
    report, point, receipts, args, keys = signed
    other_report = reconcile([record(nonce="different")], [record(nonce="different")]) if (
        change == "report") else report
    other_point = checkpoint(other_report, signer=keys[0], previous_digest="",
                             created_us=11, expires_us=100)
    other_receipts = [witness_receipt(other_point, other_report, signer=key, **args)
                      for key in keys[1:]]
    result = observe([candidate(report, point, receipts),
                      candidate(other_report, other_point, other_receipts)], args)
    assert result["status"] == "CONFLICTING_CHECKPOINTS"
    assert result["has_conflicting_checkpoints"]
    assert len(result["verified_checkpoints"]) == 2
    assert result["selected_checkpoint"] is None


@pytest.mark.parametrize("change", ["missing-witness", "changed-signature", "wrong-parent",
                                   "wrong-range", "missing-report"])
def test_bad_observation_is_preserved_as_incomplete_even_alongside_good_one(signed, change):
    report, point, receipts, args, _ = signed
    good = candidate(report, point, receipts)
    bad = deepcopy(good)
    if change == "missing-witness":
        bad["receipts"].pop()
    elif change == "changed-signature":
        bad["checkpoint"]["signature"]["value"] = "0" * 128
    elif change == "wrong-parent":
        bad["checkpoint"]["body"]["previous_digest"] = "a" * 64
    elif change == "wrong-range":
        bad["checkpoint"]["body"]["end_seq"] = 2
    else:
        del bad["report"]
    result = observe([good, bad], args)
    assert result["status"] == "INCOMPLETE_OBSERVATIONS"
    assert result["observations"][1]["status"] == "REJECTED"
    assert len(result["verified_checkpoints"]) == 1


def test_current_validity_and_host_position_are_required(signed):
    report, point, receipts, args, _ = signed
    item = candidate(report, point, receipts)
    for changes in ({"now_us": 100}, {"tenant": "another"}, {"previous_digest": "b" * 64}):
        assert observe([item], args, **changes)["status"] == "INCOMPLETE_OBSERVATIONS"
    assert observe([], args)["status"] == "INCOMPLETE_OBSERVATIONS"
    with pytest.raises(ValueError, match="bound"):
        observe([item, item], args, max_candidates=1)


def test_cosigning_does_not_make_reconciliation_discrepancies_clean(signed):
    _, _, _, args, keys = signed
    report = reconcile([record()], [])
    point = checkpoint(report, signer=keys[0], previous_digest="", created_us=10, expires_us=100)
    receipts = [witness_receipt(point, report, signer=key, **args) for key in keys[1:]]
    assert observe([candidate(report, point, receipts)], args)["status"] == "DISCREPANT_RECONCILIATION"
