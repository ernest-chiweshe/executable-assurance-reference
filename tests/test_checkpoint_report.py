"""Local report contracts over detached, signed synthetic observations."""

from copy import deepcopy
from hashlib import sha256
from html.parser import HTMLParser
import json

import pytest

from assurance_reference.checkpoint_report import checkpoint_report
from test_reconciliation import signed as _signed_fixture


signed = _signed_fixture


def report(items, args, **changes):
    return checkpoint_report(items, **{**args, "start_seq": 0, "end_seq": 1,
        "required_witness_ids": ("witness-a", "witness-b"), **changes})


def test_export_retains_exact_signed_inputs_and_verified_results(signed):
    data, point, receipts, args, _ = signed
    items = [{"checkpoint": point, "report": data, "receipts": receipts}]
    original = deepcopy(items)
    result = report(items, args)
    document = json.loads(result["json_bytes"])
    assert document["supplied_evidence"] == original == items
    assert result["sha256"] == sha256(result["json_bytes"]).hexdigest()
    assert result["status"] == "ONE_VERIFIED_CHECKPOINT_OBSERVED"
    assert document["observations"]["selected_checkpoint"] is None
    assert not document["observations"]["history_completeness_proven"]
    assert not document["observations"]["external_independence_proven"]
    assert document["supplied_evidence"][0]["report"]["decision_source"] == data["decision_source"]
    items[0]["receipts"].clear()
    assert json.loads(result["json_bytes"])["supplied_evidence"] == original


def test_export_reverifies_at_host_time_and_keeps_rejected_evidence(signed):
    data, point, receipts, args, _ = signed
    item = {"checkpoint": point, "report": data, "receipts": receipts}
    result = report([item], args, now_us=100)
    document = json.loads(result["json_bytes"])
    assert result["status"] == "INCOMPLETE_OBSERVATIONS"
    assert document["observations"]["observations"][0]["status"] == "REJECTED"
    assert document["supplied_evidence"] == [item]
    assert document["host_pins"]["checked_at_us"] == 100


def test_empty_report_is_incomplete_and_does_not_claim_a_clean_history(signed):
    args = signed[3]
    result = report([], args)
    assert result["status"] == "INCOMPLETE_OBSERVATIONS"
    assert json.loads(result["json_bytes"])["observations"]["verified_checkpoints"] == []


@pytest.mark.parametrize("items", [(), [None] * 129, [float("nan")], [object()], ["x" * (4 * 1024 * 1024)]])
def test_non_json_or_excessive_inputs_are_refused(signed, items):
    with pytest.raises(ValueError):
        report(items, signed[3])


def test_supplied_claims_are_escaped_and_cannot_become_report_verdict(signed):
    items = [{"status": "COMPLETE", "note": "<script>synthetic</script>\u202e"}]
    result = report(items, signed[3])
    assert result["status"] == "INCOMPLETE_OBSERVATIONS"
    assert "<script>" not in result["html"] and "\u202e" not in result["html"]
    assert "\\u202e" in result["html"]

    class Tags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, dict(attrs)))

    parsed = Tags()
    parsed.feed(result["html"])
    assert not {"script", "a", "img", "iframe", "form", "style"} & {t for t, _ in parsed.tags}
    assert ("html", {"lang": "en"}) in parsed.tags
    assert sum(t == "main" for t, _ in parsed.tags) == 1
    assert all(attrs.get("tabindex") == "0" for t, attrs in parsed.tags if t == "pre")
