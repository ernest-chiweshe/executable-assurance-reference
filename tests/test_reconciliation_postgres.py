"""A13 on actual guarded local governance and exact receiving receipts."""

import json

from assurance_reference.checkpoint_report import checkpoint_report
from assurance_reference.packs import verify_bundles
from assurance_reference.reconciliation import (
    EffectRecord, checkpoint, reconcile_records, verify_witnesses, witness_receipt,
)
from regulated_core.canonical import canonical_bytes
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome
from regulated_core.worm import LocalWormStore
from test_governance_root_postgres import app  # noqa: F401


def test_guarded_commits_reconcile_and_retain_two_witness_checkpoint(app):  # noqa: F811
    tenant = "reconciliation-fixture"
    for bundle in verify_bundles()["bundles"]:
        result, _, _, _ = app.enact(tenant, {"activate": bundle["reference"], "at": "fixture"})
        assert result.outcome is Outcome.COMMITTED
    events = tuple(app.log.events(tenant))
    decisions = [EffectRecord(e.tenant_id, e.operation, e.nonce, e.change_digest, "committed")
                 for e in events if e.phase == "committed"]
    assert len(decisions) == 2
    receipts = []
    for decision in decisions:
        # This query binds all four receipt fields in the actual target ledger;
        # it does not infer a receipt from equal current pack state.
        observed = app.packs.governance_receipt(
            decision.tenant, decision.operation, decision.nonce, decision.output_digest)
        assert observed is Outcome.COMMITTED
        receipts.append(EffectRecord(decision.tenant, decision.operation, decision.nonce,
                                     decision.output_digest, observed.value))
    scope = dict(tenant=tenant, start_seq=0, end_seq=len(events) - 1,
                 decision_source="governance-log:" + app.log.root(tenant),
                 receipt_source="partitioned-pack-lifecycle/exact-receiving-query")
    report = reconcile_records(decisions, receipts, **scope)
    assert report["consistent_within_supplied_scope"]
    # Removing an observation from a detached copy changes no runtime record.
    missing = reconcile_records(decisions, receipts[:-1], **scope)
    assert not missing["consistent_within_supplied_scope"]
    assert [row["status"] for row in missing["rows"]].count("MISSING_RECEIPT") == 1
    assert tuple(app.log.events(tenant)) == events
    now = app.clock.now_us()
    point = checkpoint(report, signer=app.keys["evidence"], previous_digest="",
                       created_us=now, expires_us=now + 60_000_000)
    witnesses = [Ed25519Signer("fixture:receipt-witness:" + name) for name in ("a", "b")]
    for signer in witnesses:
        app.trust.register_signer(signer)
    args = dict(trust=app.trust, issuer_key_id=app.keys["evidence"].key_id,
                tenant=tenant, previous_digest="", now_us=now)
    observed = [witness_receipt(point, report, signer=key, **args) for key in witnesses]
    artifact = {"report": report, "checkpoint": point, "witnesses": observed}
    store = LocalWormStore()
    receipt = store.anchor(tenant, canonical_bytes(artifact), retain_us=60_000_000, now_us=now)
    assert store.verify(receipt)
    raw = store.fetch(tenant, receipt.object_ref)
    assert raw == canonical_bytes(artifact)
    reopened = json.loads(raw)
    result = verify_witnesses(reopened["checkpoint"], reopened["report"], reopened["witnesses"],
                              required_witness_ids=frozenset(key.key_id for key in witnesses), **args)
    assert result["consistent_within_supplied_scope"]
    assert result["external_independence_proven"] is False
    exported = checkpoint_report(
        [{"checkpoint": reopened["checkpoint"], "report": reopened["report"],
          "receipts": reopened["witnesses"]}],
        required_witness_ids=tuple(key.key_id for key in witnesses),
        start_seq=scope["start_seq"], end_seq=scope["end_seq"], **args)
    assert exported["status"] == "ONE_VERIFIED_CHECKPOINT_OBSERVED"
    exported_document = json.loads(exported["json_bytes"])
    assert exported_document["supplied_evidence"][0]["report"] == report
    assert exported_document["observations"]["selected_checkpoint"] is None
    assert not exported_document["observations"]["history_completeness_proven"]
    assert not exported_document["observations"]["external_independence_proven"]
    assert app.log.root(tenant) in exported["html"]
    assert "partitioned-pack-lifecycle/exact-receiving-query" in exported["html"]
    # LocalWormStore is a local retention fixture, not external immutable custody.
    export_receipt = store.anchor(tenant, exported["json_bytes"], retain_us=60_000_000, now_us=now)
    assert store.verify(export_receipt)
    assert store.fetch(tenant, export_receipt.object_ref) == exported["json_bytes"]
    assert tuple(app.log.events(tenant)) == events
