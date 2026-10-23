"""Bounded observations of witnessed checkpoints for one host-pinned position.

This detects conflicting supplied evidence. It does not discover checkpoints,
select a winning fork, prove completeness, or operate an external witness service.
"""

from assurance_reference.reconciliation import _digest, _text, verify_witnesses
from regulated_core.canonical import digest_hex


def observe_checkpoints(candidates, *, trust, issuer_key_id, required_witness_ids,
                        tenant, previous_digest, start_seq, end_seq, now_us,
                        max_candidates=128):
    """Verify observations at a single explicitly pinned predecessor and range.

    Every candidate is a dict of checkpoint, report and receipts. Repeated copies
    of one checkpoint are not independent evidence. Invalid, incomplete, expired
    or differently scoped observations remain explicit; they are never silently
    discarded to manufacture an unqualified clean verdict.
    """
    required = frozenset(required_witness_ids)
    if (not _text(tenant) or not _text(issuer_key_id)
            or previous_digest != "" and not _digest(previous_digest)
            or type(start_seq) is not int or type(end_seq) is not int
            or not 0 <= start_seq <= end_seq or type(now_us) is not int or now_us < 0
            or type(max_candidates) is not int or not 1 <= max_candidates <= 1024
            or not required or len(required) > 100 or issuer_key_id in required
            or not trust.is_known(issuer_key_id)
            or any(not _text(key) or not trust.is_known(key) for key in required)):
        raise ValueError("explicit bounded checkpoint position and trusted witnesses required")
    observations, unique = [], {}
    for index, candidate in enumerate(candidates):
        if index >= max_candidates:
            raise ValueError("checkpoint observations exceed configured bound")
        try:
            if (type(candidate) is not dict or set(candidate) != {"checkpoint", "report", "receipts"}
                    or type(candidate["receipts"]) is not list
                    or len(candidate["receipts"]) > 100):
                raise ValueError("invalid candidate shape")
            point, report = candidate["checkpoint"], candidate["report"]
            if (point["body"]["start_seq"], point["body"]["end_seq"]) != (start_seq, end_seq):
                raise ValueError("checkpoint range differs")
            verified = verify_witnesses(point, report, candidate["receipts"], trust=trust,
                issuer_key_id=issuer_key_id, required_witness_ids=required, tenant=tenant,
                previous_digest=previous_digest, now_us=now_us)
        except (ValueError, TypeError, KeyError, AttributeError):
            observations.append({"input_index": index, "status": "REJECTED",
                                 "reason": "invalid-incomplete-expired-or-different-scope"})
            continue
        key = verified["checkpoint_digest"]
        observations.append({"input_index": index,
                             "status": "DUPLICATE" if key in unique else "VERIFIED",
                             "checkpoint_digest": key})
        unique[key] = {**verified, "report_digest": digest_hex(report)}
    rejected = any(row["status"] == "REJECTED" for row in observations)
    consistent = bool(unique) and all(row["consistent_within_supplied_scope"] for row in unique.values())
    if len(unique) > 1:
        status = "CONFLICTING_CHECKPOINTS"
    elif rejected or not unique:
        status = "INCOMPLETE_OBSERVATIONS"
    elif not consistent:
        status = "DISCREPANT_RECONCILIATION"
    else:
        status = "ONE_VERIFIED_CHECKPOINT_OBSERVED"
    return {"schema": "reference/checkpoint-observations/v1", "tenant": tenant,
            "previous_digest": previous_digest, "start_seq": start_seq, "end_seq": end_seq,
            "checked_at_us": now_us, "status": status, "observations": observations,
            "verified_checkpoints": [unique[key] for key in sorted(unique)],
            "has_conflicting_checkpoints": len(unique) > 1,
            "selected_checkpoint": None, "history_completeness_proven": False,
            "external_independence_proven": False,
            "coverage": "supplied observations at one host-pinned position only"}
