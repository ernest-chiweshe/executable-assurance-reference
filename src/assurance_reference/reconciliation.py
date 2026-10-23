"""Bounded receipt reconciliation and local witness attestations (A13).

Inputs are host-owned snapshots. Agreement between them does not prove that
either snapshot is exhaustive or that witness custody is externally independent.
"""

from dataclasses import asdict, dataclass
import re

from regulated_core.canonical import digest_hex
from regulated_core.signing import Signature


@dataclass(frozen=True)
class EffectRecord:
    tenant: str
    operation: str
    nonce: str
    output_digest: str
    outcome: str

    def key(self):
        return self.tenant, self.operation, self.nonce


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _text(value):
    return isinstance(value, str) and bool(value) and value == value.strip() and len(value) <= 512


def _index(records, tenant, bound):
    result = {}
    for count, record in enumerate(records, 1):
        if count > bound:
            raise ValueError("snapshot exceeds the configured bound")
        if (not isinstance(record, EffectRecord) or record.tenant != tenant
                or not all(_text(v) for v in record.key()) or not _digest(record.output_digest)
                or record.outcome not in {"committed", "not_committed", "unknown"}):
            raise ValueError("invalid or cross-tenant snapshot record")
        if record.key() in result:
            raise ValueError("duplicate operation identity in snapshot")
        result[record.key()] = record
    return result


def reconcile_records(decisions, receipts, *, tenant, start_seq, end_seq,
                      decision_source, receipt_source, max_records=10_000):
    """Compare exact operation/digest records; never substitute equal target state.

    The sequence interval describes the caller's decision snapshot. Receipts are
    independently supplied observations for that same declared scope, not effects
    invoked here. A missing receipt stays unresolved; no retry is performed.
    """
    if (not all(_text(v) for v in (tenant, decision_source, receipt_source))
            or type(start_seq) is not int or type(end_seq) is not int
            or start_seq < 0 or end_seq < start_seq
            or type(max_records) is not int or not 1 <= max_records <= 100_000):
        raise ValueError("explicit bounded reconciliation scope required")
    expected = _index(decisions, tenant, max_records)
    observed = _index(receipts, tenant, max_records)
    rows = []
    for key in sorted(expected.keys() | observed.keys()):
        decision, receipt = expected.get(key), observed.get(key)
        if decision is None:
            status = "UNMATCHED_RECEIPT"
        elif receipt is None:
            status = "MISSING_RECEIPT"
        elif decision.output_digest != receipt.output_digest:
            status = "CONFLICT"
        elif receipt.outcome == "unknown":
            status = "UNRESOLVED"
        elif decision.outcome not in {"unknown", receipt.outcome}:
            status = "CONFLICT"
        else:
            status = "MATCHED"
        rows.append({"operation": key[1], "nonce": key[2], "status": status,
                     "decision": asdict(decision) if decision else None,
                     "receipt": asdict(receipt) if receipt else None})
    return {"schema": "reference/receipt-reconciliation/v1", "tenant": tenant,
            "start_seq": start_seq, "end_seq": end_seq,
            "decision_source": decision_source, "receipt_source": receipt_source,
            "rows": rows, "consistent_within_supplied_scope": bool(rows) and all(
                row["status"] == "MATCHED" for row in rows),
            "coverage": "supplied-snapshots-only; no universal completeness assertion"}


def checkpoint(report, *, signer, previous_digest, created_us, expires_us):
    """Sign one report and its chain position; discrepant reports may be retained."""
    _check_report(report)
    body = {"schema": "reference/reconciliation-checkpoint/v1", "tenant": report["tenant"],
            "start_seq": report["start_seq"], "end_seq": report["end_seq"],
            "report_digest": digest_hex(report), "previous_digest": previous_digest,
            "created_us": created_us, "expires_us": expires_us}
    _check_body(body)
    return {"body": body, "signature": asdict(signer.sign(body))}


def _check_report(report):
    expected = reconcile_records(
        (EffectRecord(**row["decision"]) for row in report["rows"] if row["decision"] is not None),
        (EffectRecord(**row["receipt"]) for row in report["rows"] if row["receipt"] is not None),
        tenant=report["tenant"], start_seq=report["start_seq"], end_seq=report["end_seq"],
        decision_source=report["decision_source"], receipt_source=report["receipt_source"],
        max_records=100_000)
    if report != expected:
        raise ValueError("report does not reproduce its supplied observations")


def _check_body(body):
    if (set(body) != {"schema", "tenant", "start_seq", "end_seq", "report_digest",
                      "previous_digest", "created_us", "expires_us"}
            or body["schema"] != "reference/reconciliation-checkpoint/v1"
            or not _text(body["tenant"]) or not _digest(body["report_digest"])
            or (body["previous_digest"] != "" and not _digest(body["previous_digest"]))
            or any(type(body[key]) is not int for key in
                   ("start_seq", "end_seq", "created_us", "expires_us"))
            or not 0 <= body["start_seq"] <= body["end_seq"]
            or not 0 <= body["created_us"] < body["expires_us"]):
        raise ValueError("invalid reconciliation checkpoint")


def _verify_checkpoint(signed, report, *, trust, issuer_key_id, tenant,
                       previous_digest, now_us):
    _check_report(report)
    body = signed["body"]
    _check_body(body)
    signature = Signature(**signed["signature"])
    if (set(signed) != {"body", "signature"} or signature.key_id != issuer_key_id
            or not trust.verify(body, signature) or body["tenant"] != tenant
            or body["previous_digest"] != previous_digest
            or report.get("schema") != "reference/receipt-reconciliation/v1"
            or body["report_digest"] != digest_hex(report)
            or report["tenant"] != tenant
            or (report["start_seq"], report["end_seq"]) != (body["start_seq"], body["end_seq"])
            or type(now_us) is not int or not body["created_us"] <= now_us < body["expires_us"]):
        raise ValueError("checkpoint signature, binding or time differs")


def witness_receipt(signed, report, *, signer, trust, issuer_key_id,
                    tenant, previous_digest, now_us):
    """A local witness verifies the exact checkpoint before acknowledging it."""
    _verify_checkpoint(signed, report, trust=trust, issuer_key_id=issuer_key_id,
                       tenant=tenant, previous_digest=previous_digest, now_us=now_us)
    if signer.key_id == issuer_key_id or not trust.matches_signer(signer):
        raise ValueError("a distinct managed witness identity is required")
    body = {"schema": "reference/reconciliation-witness/v1", "tenant": tenant,
            "checkpoint_digest": digest_hex(signed), "observed_us": now_us}
    return {"body": body, "signature": asdict(signer.sign(body))}


def verify_witnesses(signed, report, receipts, *, trust, issuer_key_id,
                     required_witness_ids, tenant, previous_digest, now_us):
    """Verify every configured witness; duplicates never satisfy another identity.

    The host owns the required set and the prior checkpoint. This does not
    establish independent custody or prevent a witness from signing two forks.
    """
    _verify_checkpoint(signed, report, trust=trust, issuer_key_id=issuer_key_id,
                       tenant=tenant, previous_digest=previous_digest, now_us=now_us)
    required = frozenset(required_witness_ids)
    if (not required or issuer_key_id in required or len(required) > 100
            or any(not trust.is_known(key) for key in required)):
        raise ValueError("explicit distinct managed witness set required")
    seen = set()
    for receipt in receipts:
        body = receipt["body"]
        signature = Signature(**receipt["signature"])
        if (set(receipt) != {"body", "signature"}
                or set(body) != {"schema", "tenant", "checkpoint_digest", "observed_us"}
                or body["schema"] != "reference/reconciliation-witness/v1"
                or body["tenant"] != tenant or body["checkpoint_digest"] != digest_hex(signed)
                or type(body["observed_us"]) is not int
                or not signed["body"]["created_us"] <= body["observed_us"] <= now_us
                or signature.key_id not in required or signature.key_id in seen
                or not trust.verify(body, signature)):
            raise ValueError("witness receipt does not match the exact checkpoint")
        seen.add(signature.key_id)
    if seen != required:
        raise ValueError("required witness receipt missing")
    return {"checkpoint_digest": digest_hex(signed), "verified_witness_ids": sorted(seen),
            "consistent_within_supplied_scope": report["consistent_within_supplied_scope"],
            "external_independence_proven": False}
