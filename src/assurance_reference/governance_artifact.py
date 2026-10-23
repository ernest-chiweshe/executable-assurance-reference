"""Local governance-root artifacts; integrity is separate from trusted custody."""

import hashlib
import json

from regulated_core.canonical import canonical_bytes
from regulated_core.governance_targets import (
    GovernanceEvent, GovernanceLog, event_body, merkle_root, publish_root,
)


def retain_governance_artifact(log, store, tenant_id, *, retain_us, now_us):
    """Retain one snapshot through the original root publisher, with exact read-back.

    Capture events once so a concurrent append cannot mix a root with a later
    count. This snapshot says nothing about later events or external witnesses.
    """
    if not tenant_id or retain_us <= 0 or now_us < 0:
        raise ValueError("A tenant and positive retention interval are required")
    snapshot = GovernanceLog()
    events = tuple(log.events(tenant_id))
    for event in events:
        if event.tenant_id != tenant_id:
            raise ValueError("Governance snapshot contains a different tenant")
        snapshot.append(event)
    receipt = publish_root(snapshot, store, tenant_id, retain_us=retain_us, now_us=now_us)
    expected = {"schema": "regulated/governance-root/v1", "tenant_id": tenant_id,
                "root": snapshot.root(tenant_id), "events": len(events), "at_us": now_us}
    if store.fetch(tenant_id, receipt.object_ref) != canonical_bytes(expected):
        raise ValueError("Governance root read-back differs from the captured snapshot")
    artifact = {"schema": "reference/governance-artifact/v1", "root_record": expected,
                "events": [event_body(event) for event in events], "receipt": receipt.as_dict()}
    verify_governance_artifact(artifact, expected_tenant=tenant_id, expected_root=expected["root"])
    if receipt.retained_until_us < now_us + retain_us:
        raise ValueError("Governance root retention is shorter than requested")
    return artifact


def verify_governance_artifact(artifact, *, expected_tenant, expected_root):
    """Check content against an independently obtained root, without provider I/O.

    A matching digest is not a signature, proof of provider retention, or proof
    of history completeness. The caller supplies the trusted tenant and root.
    """
    if artifact.get("schema") != "reference/governance-artifact/v1":
        raise ValueError("Unknown governance artifact schema")
    record = artifact["root_record"]
    events = tuple(GovernanceEvent(**row) for row in artifact["events"])
    root = merkle_root([event.digest() for event in events])
    if any(event.tenant_id != expected_tenant for event in events):
        raise ValueError("Governance event tenant differs")
    expected = {"schema": "regulated/governance-root/v1", "tenant_id": expected_tenant,
                "root": expected_root, "events": len(events), "at_us": record["at_us"]}
    if record != expected or root != expected_root:
        raise ValueError("Governance root or event count differs")
    receipt = artifact["receipt"]
    if receipt["content_digest"] != hashlib.sha256(canonical_bytes(record)).hexdigest():
        raise ValueError("Governance root receipt digest differs")
    # Exercise serialization here as well: the artifact is a portable JSON value.
    json.dumps(artifact, allow_nan=False)
    return True
