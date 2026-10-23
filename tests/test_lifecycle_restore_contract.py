"""Offline observations cannot pass with empty or mismatched retry evidence."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_lifecycle_retry_restore import retry_observation  # noqa: E402
from assurance_reference.lifecycle_partition import partition_snapshot  # noqa: E402
from factory.packs.lifecycle import ActivationLedger, LifecycleError  # noqa: E402
from factory.packs.lifecycle_pg import _canonical, _encode, _snapshot  # noqa: E402
from test_lifecycle_partition import legacy_snapshot  # noqa: E402


def snapshots():
    legacy = legacy_snapshot()
    ledger = ActivationLedger()
    ledger.activate("current-pack", "1", "a" * 64, at="synthetic")
    args = ["school-current", "current-pack", "1"]
    kwargs = {"receipt": ("governance", "pin", "synthetic-nonce", "b" * 64)}
    answer = ledger.pin(*args, **kwargs)
    payload = _snapshot(ledger, "current-pack", {"restore-guarded-retry": {
        "request": _canonical(["pin", args, kwargs]), "result": _encode(answer)}})
    tables = {name: [] for name in ("reference_pack_shared_v1", "reference_pack_tenants_v1",
              "reference_pack_installation_retries_v1", "reference_pack_retry_index_v1")}
    for pack, source in (("education", legacy), ("current-pack", payload)):
        partition = partition_snapshot(pack, source)
        tables["reference_pack_shared_v1"].append({"pack_id": pack, "payload": partition["shared"]})
        for tenant, scope in partition["scopes"].items():
            if tenant is None:
                tables["reference_pack_installation_retries_v1"].append({"pack_id": pack, "requests": scope["requests"]})
            else:
                tables["reference_pack_tenants_v1"].append({"pack_id": pack, "tenant_id": tenant, "payload": scope})
        for key, request in partition["retry_index"].items():
            tables["reference_pack_retry_index_v1"].append({"pack_id": pack, "key_digest": key, "request_digest": request})
    return tables, legacy


def observe(tables, legacy):
    return retry_observation(tables, legacy, current_pack="current-pack", governance_tenant="governance")


def test_populated_observation_preserves_distinct_evidence_classes_and_exact_replies():
    tables, legacy = snapshots()
    before = deepcopy(tables)
    result = observe(tables, legacy)
    assert result == {"synthetic_legacy_installation_retries": 3, "synthetic_legacy_private_retries": 3,
        "current_guarded_private_retries": 1, "total_retry_index_rows": 7,
        "legacy_roundtrip": "EXACT", "effect_resumption": "NOT_ATTEMPTED"}
    assert tables == before


@pytest.mark.parametrize("fault", ["empty-installation", "empty-index", "wrong-index", "missing-current",
                                   "foreign-receipt", "changed-reply"])
def test_incomplete_or_changed_restored_retry_evidence_refuses(fault):
    tables, legacy = snapshots()
    if fault == "empty-installation":
        tables["reference_pack_installation_retries_v1"] = []
    elif fault == "empty-index":
        tables["reference_pack_retry_index_v1"] = []
    elif fault == "wrong-index":
        tables["reference_pack_retry_index_v1"][-1]["request_digest"] = "f" * 64
    elif fault == "changed-reply":
        tables["reference_pack_installation_retries_v1"][0]["requests"]["install-one"]["result"] = None
    else:
        current = next(row["payload"] for row in tables["reference_pack_tenants_v1"]
                       if row["tenant_id"] == "governance")
        if fault == "missing-current":
            current["requests"].clear()
        else:
            current["governance_receipts"][0] = ("foreign", *current["governance_receipts"][0][1:])
    with pytest.raises((AssertionError, LifecycleError)):
        observe(tables, legacy)
