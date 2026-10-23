"""Synthetic migration fixtures; no SQL, authority bypass or live effects."""
from copy import deepcopy

import pytest

from assurance_reference.lifecycle_partition import partition_snapshot, plan_legacy_row, restore_partition
from factory.packs.lifecycle import ActivationLedger, LifecycleError
from factory.packs.lifecycle_pg import _canonical, _digest, _encode, _restore, _snapshot


def legacy_snapshot():
    ledger = ActivationLedger()
    requests = {}

    def invoke(key, method, *args, **kwargs):
        result = getattr(ledger, method)(*args, **kwargs)
        requests[key] = {"request": _canonical([method, args, kwargs]), "result": _encode(result)}

    invoke("install-one", "activate", "education", "1", "a" * 64, at="1")
    invoke("install-two", "activate", "education", "2", "b" * 64, at="2")
    invoke("private-a", "pin", "school-a", "education", "1",
           receipt=("school-a", "pin", "nonce-a", "c" * 64))
    invoke("private-b", "pin", "school-b", "education", "2",
           receipt=("school-b", "pin", "nonce-b", "d" * 64))
    invoke("global-rollback", "rollback", "education", at="3", reason="synthetic rollback")
    invoke("private-revoke", "revoke", "education", "2", at="4", reason="synthetic revocation",
           receipt=("school-a", "revoke", "nonce-c", "e" * 64))
    return _snapshot(ledger, "education", requests)


def test_lossless_partition_preserves_original_transitions_and_exact_retry_responses():
    payload = legacy_snapshot()
    original = deepcopy(payload)
    partition = partition_snapshot("education", payload)
    restored = restore_partition("education", partition)
    assert _canonical(restored) == _canonical(original)
    assert payload == original
    ledger = _restore("education", restored)
    assert ledger.pack_ids() == ("education",)
    assert ledger.active("education").version == "1"
    assert ledger.resolve("school-a", "education") == "1"
    assert ledger.resolve("school-b", "education") is None  # revoked pin never falls back
    assert ledger.resolve("unbound-school", "education") == "1"
    assert len(ledger.history("education")) == 3
    assert ledger.is_revoked("education", "2")
    assert ledger.governance_receipt("education", ("school-b", "pin", "nonce-b", "d" * 64))
    # The first activation's exact old reply survives subsequent rollback/revocation.
    assert restored["requests"]["install-one"] == original["requests"]["install-one"]


def test_shared_snapshot_excludes_raw_private_maps_and_requests():
    partition = partition_snapshot("education", legacy_snapshot())
    shared = partition["shared"]
    assert shared["pins"] == shared["requests"] == {}
    assert shared["governance_receipts"] == []
    visible = _canonical([shared, partition["retry_index"]])
    for secret in ("school-a", "school-b", "nonce-a", "private-a", "nonce-b", "private-revoke"):
        assert secret not in visible
    assert len(partition["retry_index"]) == 6
    a = partition["scopes"]["school-a"]
    b = partition["scopes"]["school-b"]
    assert set(a["requests"]) == {"private-a", "private-revoke"}
    assert set(b["requests"]) == {"private-b"}
    assert "school-b" not in _canonical(a)
    assert "school-a" not in _canonical(b)
    assert set(partition["scopes"][None]["requests"]) == {
        "install-one", "install-two", "global-rollback"}


@pytest.mark.parametrize("mutation", ["drop-index", "wrong-index", "foreign-receipt", "foreign-retry",
                                     "private-in-shared", "duplicate-key", "installation-pin"])
def test_corrupted_partition_is_refused(mutation):
    partition = partition_snapshot("education", legacy_snapshot())
    a, b = partition["scopes"]["school-a"], partition["scopes"]["school-b"]
    if mutation == "drop-index":
        partition["retry_index"].pop(next(iter(partition["retry_index"])))
    elif mutation == "wrong-index":
        partition["retry_index"][next(iter(partition["retry_index"]))] = "0" * 64
    elif mutation == "foreign-receipt":
        a["governance_receipts"].append(b["governance_receipts"][0])
    elif mutation == "foreign-retry":
        a["requests"]["private-b"] = b["requests"].pop("private-b")
    elif mutation == "private-in-shared":
        partition["shared"]["pins"]["school-a"] = "1"
    elif mutation == "duplicate-key":
        b["requests"]["private-a"] = a["requests"]["private-a"]
    else:
        partition["scopes"][None]["pin"] = "1"
    with pytest.raises(LifecycleError):
        restore_partition("education", partition)


@pytest.mark.parametrize("fingerprint", [
    "not-json", '["unknown",[],{}]',
    _canonical(["pin", ["school-a", "education", "1"],
                {"receipt": ["", "pin", "nonce", "d" * 64]}]),
    _canonical(["activate", ["other-pack", "1", "a" * 64], {"at": "1"}]),
])
def test_ambiguous_legacy_retry_stops_migration_without_mutating_source(fingerprint):
    payload = legacy_snapshot()
    payload["requests"]["install-one"]["request"] = fingerprint
    original = deepcopy(payload)
    with pytest.raises(LifecycleError):
        partition_snapshot("education", payload)
    assert payload == original


def test_governance_tenant_can_pin_another_tenant_without_losing_retry_or_authority():
    ledger = ActivationLedger()
    ledger.activate("education", "1", "a" * 64, at="1")
    receipt = ("governance-office", "pin", "cross-tenant-pin", "b" * 64)
    ledger.pin("school-a", "education", "1", receipt=receipt)
    payload = _snapshot(ledger, "education", {"cross-pin": {
        "request": _canonical(["pin", ["school-a", "education", "1"], {"receipt": receipt}]), "result": None}})
    partition = partition_snapshot("education", payload)
    assert partition["scopes"]["school-a"] == {"pin": "1", "requests": {}, "governance_receipts": []}
    governance = partition["scopes"]["governance-office"]
    assert governance["pin"] is None
    assert governance["requests"] == payload["requests"]
    assert governance["governance_receipts"] == [receipt]
    assert _canonical(restore_partition("education", partition)) == _canonical(payload)
    assert plan_legacy_row("education", 2, payload, _digest("education", 2, payload))["partition"] == partition


def test_optional_legacy_receipts_and_empty_installation_are_supported():
    payload = _snapshot(ActivationLedger(), "empty", {})
    payload.pop("governance_receipts")
    partition = partition_snapshot("empty", payload)
    assert partition["scopes"] == partition["retry_index"] == {}
    assert restore_partition("empty", partition) == {**payload, "governance_receipts": []}


@pytest.mark.parametrize("encoding", ["object", "text", "bytes"])
def test_stored_row_preflight_preserves_source_revision_and_exact_original_checksum(encoding):
    payload = legacy_snapshot()
    checksum = _digest("education", 6, payload)
    raw = payload if encoding == "object" else _canonical(payload)
    if encoding == "bytes":
        raw = raw.encode()
    plan = plan_legacy_row("education", 6, raw, checksum)
    assert plan["source_revision"] == 6 and plan["source_digest"] == checksum
    assert plan["pack_id"] == "education"
    assert _canonical(restore_partition("education", plan["partition"])) == _canonical(payload)


@pytest.mark.parametrize("revision,checksum", [(True, "original"), (0, "original"),
                                               (7, "original"), (6, "f" * 64)])
def test_stored_row_preflight_refuses_invalid_revision_or_checksum(revision, checksum):
    payload = legacy_snapshot()
    checksum = _digest("education", 6, payload) if checksum == "original" else checksum
    with pytest.raises(LifecycleError, match="migration preflight"):
        plan_legacy_row("education", revision, payload, checksum)
