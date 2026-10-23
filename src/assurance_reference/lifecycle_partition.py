"""Offline, lossless partition planning for the reference lifecycle migration.

This does not migrate a database or provide tenant isolation by itself. The
original transition engine and lifecycle implementation remain unchanged.
Ambiguous legacy retry ownership stops planning instead of discarding evidence.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from factory.packs.lifecycle import LifecycleError, governance_receipt_key
from factory.packs.lifecycle_pg import _canonical, _digest, _restore


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def request_tenant(pack_id: str, request: str) -> str | None:
    """Recover ownership from the original canonical invocation fingerprint.

    None means an installation operation without a tenant-bearing receipt.
    A governance tenant can legitimately pin a different target tenant. Its
    receipt and retry belong to the governance tenant; the pin itself belongs
    to its explicit target. No stored callable is evaluated.
    """
    try:
        method, args, kwargs = json.loads(request)
        sizes = {"activate": 3, "rollback": 1, "revoke": 2, "pin": 3, "unpin": 2}
        if (method not in sizes or not isinstance(args, list)
                or len(args) != sizes[method] or not isinstance(kwargs, dict)
                or _canonical([method, args, kwargs]) != request):
            raise ValueError("unknown or noncanonical invocation")
        tenant_operation = method in {"pin", "unpin"}
        if args[1 if tenant_operation else 0] != pack_id:
            raise ValueError("retry names another pack")
        tenant = args[0] if tenant_operation else None
        if tenant_operation and (not isinstance(tenant, str) or not tenant):
            raise ValueError("missing tenant")
        receipt = kwargs.get("receipt")
        if receipt is not None:
            tenant = governance_receipt_key(receipt)[0]
        return tenant
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise LifecycleError("legacy retry ownership requires review") from exc


def _empty_scope() -> dict[str, Any]:
    return {"pin": None, "requests": {}, "governance_receipts": []}


def plan_legacy_row(pack_id: str, revision: int, payload: Any, state_digest: str) -> dict[str, Any]:
    """Check a complete stored row before producing privileged migration data.

    The eventual transactional migration must compare the source revision and
    digest again under its locks. This offline plan does not authorize a write.
    """
    try:
        if not isinstance(pack_id, str) or not pack_id or "#" in pack_id:
            raise ValueError("invalid pack identity")
        if type(revision) is not int or revision < 1:
            raise ValueError("invalid source revision")
        decoded = json.loads(payload) if isinstance(payload, (str, bytes)) else deepcopy(payload)
        if _digest(pack_id, revision, decoded) != state_digest:
            raise ValueError("source checksum mismatch")
        partition = partition_snapshot(pack_id, decoded)
        expected = deepcopy(decoded)
        expected.setdefault("governance_receipts", [])
        expected["governance_receipts"].sort()
        if _canonical(restore_partition(pack_id, partition)) != _canonical(expected):
            raise ValueError("partition does not preserve the exact source state")
        return {"pack_id": pack_id, "source_revision": revision,
                "source_digest": state_digest, "partition": partition}
    except (TypeError, ValueError, KeyError) as exc:
        raise LifecycleError("legacy lifecycle row failed migration preflight") from exc


def partition_snapshot(pack_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and separate shared authority from tenant/private retry data.

    The index preserves pack-wide retry-key uniqueness without placing raw
    tenant keys, arguments or results in the shared snapshot. These hashes
    are integrity/index metadata, not protection against guessing inputs.
    The returned scopes mapping is privileged migration material, not a view
    that may be exposed to runtime tenants.
    """
    _restore(pack_id, payload)
    original = deepcopy(payload)
    shared = deepcopy(original)
    shared.update(pins={}, requests={}, governance_receipts=[])
    scopes: dict[str | None, dict[str, Any]] = {}
    index = {}
    for tenant, pin in original["pins"].items():
        scopes.setdefault(tenant, _empty_scope())["pin"] = pin
    for receipt in original.get("governance_receipts", []):
        tenant = governance_receipt_key(receipt)[0]
        scopes.setdefault(tenant, _empty_scope())["governance_receipts"].append(receipt)
    for key, receipt in original["requests"].items():
        tenant = request_tenant(pack_id, receipt["request"])
        scopes.setdefault(tenant, _empty_scope())["requests"][key] = receipt
        key_digest = _hash(["reference/lifecycle-retry-key/v1", pack_id, key])
        if key_digest in index:
            raise LifecycleError("retry-key index collision")
        index[key_digest] = _hash(receipt["request"])
    return {"shared": shared, "scopes": scopes, "retry_index": index}


def restore_partition(pack_id: str, partition: dict[str, Any]) -> dict[str, Any]:
    """Privileged offline round-trip check, never a runtime tenant read API."""
    if set(partition) != {"shared", "scopes", "retry_index"}:
        raise LifecycleError("invalid partition fields")
    payload = deepcopy(partition["shared"])
    _restore(pack_id, payload)
    if payload["pins"] or payload["requests"] or payload.get("governance_receipts"):
        raise LifecycleError("shared snapshot contains private state")
    payload["governance_receipts"] = []
    actual_index = {}
    for tenant, scope in partition["scopes"].items():
        if tenant is not None and (not isinstance(tenant, str) or not tenant):
            raise LifecycleError("invalid partition tenant")
        if set(scope) != {"pin", "requests", "governance_receipts"}:
            raise LifecycleError("invalid private partition fields")
        if scope["pin"] is not None:
            if tenant is None:
                raise LifecycleError("installation scope cannot hold a tenant pin")
            payload["pins"][tenant] = scope["pin"]
        for receipt in scope["governance_receipts"]:
            if governance_receipt_key(receipt)[0] != tenant:
                raise LifecycleError("receipt belongs to another tenant")
            payload["governance_receipts"].append(receipt)
        for key, receipt in scope["requests"].items():
            if key in payload["requests"]:
                raise LifecycleError("duplicate pack-wide retry key")
            if request_tenant(pack_id, receipt["request"]) != tenant:
                raise LifecycleError("retry belongs to another tenant")
            payload["requests"][key] = receipt
            digest = _hash(["reference/lifecycle-retry-key/v1", pack_id, key])
            if digest in actual_index:
                raise LifecycleError("retry-key index collision")
            actual_index[digest] = _hash(receipt["request"])
    if actual_index != partition["retry_index"]:
        raise LifecycleError("retry index does not cover the exact retained requests")
    payload["governance_receipts"].sort()
    _restore(pack_id, payload)
    return payload
