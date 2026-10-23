"""A12 exact-version read-back contracts against the pinned original adapter."""

from datetime import datetime, timezone
from hashlib import sha256

import pytest

from regulated_core.providers_aws import S3ObjectLockWormStore
from regulated_core.worm import WormUnavailable
from retention_adapter_fixtures import RetentionResponses, no_provider_sdks  # noqa: F401

NOW = 1_700_000_000_000_000
YEAR = 365 * 86_400_000_000


@pytest.mark.parametrize("fraction", [0, 1, 999999])
def test_exact_stored_version_bytes_mode_and_retention_are_read_back(fraction):
    client = RetentionResponses()
    store = S3ObjectLockWormStore("fictional-bucket", compliance=True, client=client)
    store.qualify()
    body = b"fictional retained evidence\x00\r\n"
    now = NOW + fraction
    receipt = store.anchor("fictional-school", body, retain_us=YEAR, now_us=now)
    assert receipt.content_digest == sha256(body).hexdigest()
    assert receipt.retained_until_us == now + YEAR
    assert store.verify(receipt)
    writes = [r for operation, r in client.calls if operation == "put"]
    reads = [r for operation, r in client.calls if operation in {"read", "retention"}]
    assert len(writes) == 1 and len(reads) == 4
    assert writes[0]["ObjectLockMode"] == "COMPLIANCE"
    until = writes[0]["ObjectLockRetainUntilDate"]
    assert until >= datetime.fromtimestamp((now + YEAR) / 1_000_000, tz=timezone.utc)
    assert until.microsecond == 0
    assert all(r["VersionId"] == receipt.receipt_id and r["Key"] == writes[0]["Key"] for r in reads)
    assert store._client is client  # no implicit SDK client selection


@pytest.mark.parametrize("fault", ["mode", "short", "bytes", "version", "missing-retention", "unavailable"])
def test_unproven_stored_object_never_produces_a_retention_receipt(fault):
    client = RetentionResponses()
    client.fault = fault
    store = S3ObjectLockWormStore("fictional-bucket", compliance=True, client=client)
    with pytest.raises(WormUnavailable):
        store.anchor("fictional-school", b"fictional evidence", retain_us=YEAR, now_us=NOW)


@pytest.mark.parametrize("setting", ["versioning", "object_lock"])
def test_unqualified_bucket_configuration_refuses_before_write(setting):
    client = RetentionResponses()
    setattr(client, setting, "Disabled")
    store = S3ObjectLockWormStore("fictional-bucket", compliance=True, client=client)
    with pytest.raises(WormUnavailable):
        store.qualify()
    assert client.calls == []


@pytest.mark.parametrize("duration", [0, -1, True, 10**100])
def test_invalid_retention_never_calls_storage(duration):
    client = RetentionResponses()
    store = S3ObjectLockWormStore("fictional-bucket", compliance=True, client=client)
    with pytest.raises(WormUnavailable):
        store.anchor("fictional-school", b"fictional evidence", retain_us=duration, now_us=NOW)
    assert client.calls == []
