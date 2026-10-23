"""Bounded retained-object parsing; decoding is never authentication."""
import json
from dataclasses import replace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_service import EvidenceDelta, EvidenceError, verify_delta
from test_evidence_service_formats import case, delta_case


def limits(delta):
    return dict(max_bytes=len(delta.bytes()), max_entries=len(delta.envelopes),
                max_envelope_bytes=max(map(len, delta.envelopes)))


def test_exact_boundary_roundtrip_then_authentication(case):
    delta, verification = delta_case(case)
    decoded = EvidenceDelta.from_bytes(delta.bytes(), **limits(delta))
    assert decoded == delta
    assert verify_delta(decoded, **verification) == tuple(case[-1][1:])
    for bound in limits(delta):
        smaller = limits(delta)
        smaller[bound] -= 1
        with pytest.raises(EvidenceError):
            EvidenceDelta.from_bytes(delta.bytes(), **smaller)


def test_byte_limit_checked_before_json_parser(case, monkeypatch):
    delta, _ = delta_case(case)
    def no_parse(*args, **kwargs):
        raise AssertionError("oversized input reached parser")
    monkeypatch.setattr(json, "loads", no_parse)
    with pytest.raises(EvidenceError, match="byte bound"):
        EvidenceDelta.from_bytes(delta.bytes(), **(limits(delta) | {"max_bytes": 1}))


@pytest.mark.parametrize("change", ["extra", "schema", "bool_seq", "reverse_range", "missing_body",
                                    "extra_path", "long_path", "long_consistency", "odd_hex",
                                    "upper_hex", "whitespace_hex", "oversized_envelope"])
def test_structural_ambiguities_and_bounds_refuse(case, change):
    delta, _ = delta_case(case)
    value = json.loads(delta.bytes())
    if change == "extra": value["ignored"] = "not allowed"
    elif change == "schema": value["schema"] = "other"
    elif change == "bool_seq": value["from_seq"] = True
    elif change == "reverse_range": value["to_seq"] = 0
    elif change == "missing_body": value["envelopes"].pop()
    elif change == "extra_path": value["inclusion_paths"].append([])
    elif change == "long_path": value["inclusion_paths"][0] = ["a" * 64] * 65
    elif change == "long_consistency": value["consistency"] = ["a" * 64] * 66
    elif change == "odd_hex": value["envelopes"][0] = "a"
    elif change == "upper_hex": value["envelopes"][0] = value["envelopes"][0].upper()
    elif change == "whitespace_hex": value["envelopes"][0] = "aa aa"
    else: value["envelopes"][0] += "00" * 1000
    raw = canonical_bytes(value)
    with pytest.raises(EvidenceError):
        EvidenceDelta.from_bytes(raw, **(limits(delta) | {"max_bytes": len(raw)}))


@pytest.mark.parametrize("kind", ["duplicate", "nan", "space", "nested", "utf8"])
def test_malformed_or_noncanonical_json_refuses(case, kind):
    delta, _ = delta_case(case)
    raw = delta.bytes()
    if kind == "duplicate": raw = b'{"tenant":"tenant",' + raw[1:]
    elif kind == "nan": raw = raw.replace(b'"from_seq":1', b'"from_seq":NaN')
    elif kind == "space": raw = b" " + raw
    elif kind == "nested": raw = b"[" * 2000 + b"0" + b"]" * 2000
    else: raw = b"\xff"
    with pytest.raises(EvidenceError):
        EvidenceDelta.from_bytes(raw, **(limits(delta) | {"max_bytes": len(raw)}))


def test_valid_encoding_does_not_imply_signature_acceptance(case):
    delta, verification = delta_case(case)
    head = replace(delta.head, signature=replace(delta.head.signature, value="00" * 64))
    changed = replace(delta, head=head)
    decoded = EvidenceDelta.from_bytes(changed.bytes(), **limits(changed))
    assert decoded == changed
    with pytest.raises(EvidenceError):
        verify_delta(decoded, **(verification | {"expected_head": head}))


@pytest.mark.parametrize("bound", ["max_bytes", "max_entries", "max_envelope_bytes"])
def test_boolean_and_zero_limits_refuse(case, bound):
    delta, _ = delta_case(case)
    for bad in (True, 0, -1, "10"):
        with pytest.raises(EvidenceError):
            EvidenceDelta.from_bytes(delta.bytes(), **(limits(delta) | {bound: bad}))


def test_canonical_invalid_core_model_reports_evidence_error(case):
    from regulated_core.merkle import MemoryMerkleLog
    delta, verification = delta_case(case)
    tree = MemoryMerkleLog()
    raw = b"{}"
    tree.append(raw)
    head = replace(case[6][0], tree_root=tree.root().hex())
    head = replace(head, signature=case[1].sign(head.body()))
    bad = EvidenceDelta("tenant", 0, 0, (raw,), None, head, (), ((),))
    with pytest.raises(EvidenceError, match="invalid retained envelope"):
        verify_delta(bad, **(verification | {"expected_previous": None, "expected_head": head}))
