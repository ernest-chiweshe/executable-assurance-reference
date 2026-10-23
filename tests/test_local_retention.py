"""Persistent receipt binding and safe refusals, using synthetic evidence only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json

import pytest

from assurance_reference.local_retention import LocalRetentionStore
from regulated_core.worm import WormError, WormUnavailable


def test_retention_survives_reconstruction_and_binds_tenant_bytes_window(tmp_path):
    first = LocalRetentionStore(tmp_path)
    receipt = first.anchor("school-a", b"synthetic evidence", retain_us=100, now_us=10)
    restored = LocalRetentionStore(tmp_path)
    assert restored.fetch("school-a", receipt.object_ref) == b"synthetic evidence"
    assert restored.verify(receipt)
    assert restored.anchor("school-a", b"synthetic evidence", retain_us=100, now_us=10) == receipt
    for changed in (replace(receipt, retained_until_us=111), replace(receipt, content_digest="0" * 64),
                    replace(receipt, provider="compliance-worm")):
        assert not restored.verify(changed)
    with pytest.raises(WormError, match="another tenant"):
        restored.fetch("school-b", receipt.object_ref)
    later = restored.anchor("school-a", b"synthetic evidence", retain_us=100, now_us=20)
    assert later.retained_until_us == 120 and later != receipt
    assert restored.verify(receipt)  # extending retention never overwrites the earlier receipt


def test_distinct_concurrent_receipts_are_durable(tmp_path):
    store = LocalRetentionStore(tmp_path)
    with ThreadPoolExecutor(max_workers=3) as workers:
        receipts = list(workers.map(
            lambda index: store.anchor("school", str(index).encode(), retain_us=100, now_us=10),
            range(3),
        ))
    restored = LocalRetentionStore(tmp_path)
    assert all(restored.verify(receipt) for receipt in receipts)


def test_missing_partial_or_inconsistent_synthetic_storage_never_verifies(tmp_path):
    store = LocalRetentionStore(tmp_path)
    receipt = store.anchor("school", b"fixture", retain_us=100, now_us=10)
    record = next(tmp_path.glob("*.json"))
    original = json.loads(record.read_bytes())
    record.write_bytes(b'{"schema":')
    assert not store.verify(receipt)
    with pytest.raises(WormUnavailable):
        store.anchor("school", b"fixture", retain_us=100, now_us=10)
    original["data_base64"] = "ZGlmZmVyZW50"
    record.write_text(json.dumps(original))
    assert not store.verify(receipt)
    record.unlink()
    assert not store.verify(receipt)


@pytest.mark.parametrize("tenant,now,retain", [("", 1, 10), ("a", -1, 10),
                                              ("a", 1, 0), ("a", True, 10)])
def test_invalid_retention_request_does_not_create_receipt(tmp_path, tenant, now, retain):
    store = LocalRetentionStore(tmp_path)
    with pytest.raises(WormError):
        store.anchor(tenant, b"fixture", retain_us=retain, now_us=now)
    assert list(tmp_path.iterdir()) == []
