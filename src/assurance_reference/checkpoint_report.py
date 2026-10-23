"""Local evidence export from freshly verified, host-pinned observations.

No input-provided verdict is rendered as the report verdict. The export retains
the supplied signed evidence, including rejected candidates, for later review.
It is neither a signed publication nor a complete-history assertion.
"""

import hashlib
import html
import json

from assurance_reference.checkpoint_observations import observe_checkpoints


MAX_EXPORT_BYTES = 4 * 1024 * 1024


def _encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def checkpoint_report(candidates, *, trust, issuer_key_id, required_witness_ids,
                      tenant, previous_digest, start_seq, end_seq, now_us):
    """Return JSON bytes and semantic HTML for at most 128 supplied candidates.

    The host supplies trust, time, scope and required witnesses independently of
    the evidence. A detached finite-JSON snapshot is verified and rendered once.
    Source labels inside signed reports remain assertions of those issuers.
    The caller owns local retention and read access; this function performs no I/O.
    """
    if type(candidates) is not list or len(candidates) > 128:
        raise ValueError("report requires a bounded list of checkpoint candidates")
    try:
        supplied = _encode(candidates)
        if len(supplied) > MAX_EXPORT_BYTES:
            raise ValueError("checkpoint evidence exceeds export byte limit")
        snapshot = json.loads(supplied)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("checkpoint evidence must be bounded finite JSON") from exc
    required = tuple(required_witness_ids)
    result = observe_checkpoints(snapshot, trust=trust, issuer_key_id=issuer_key_id,
        required_witness_ids=required, tenant=tenant, previous_digest=previous_digest,
        start_seq=start_seq, end_seq=end_seq, now_us=now_us)
    document = {"schema": "reference/checkpoint-report-export/v1",
        "host_pins": {"issuer_key_id": issuer_key_id,
                      "required_witness_ids": sorted(set(required)),
                      "tenant": tenant, "previous_digest": previous_digest,
                      "start_seq": start_seq, "end_seq": end_seq, "checked_at_us": now_us},
        "observations": result, "supplied_evidence": snapshot,
        "supplied_evidence_sha256": hashlib.sha256(supplied).hexdigest(),
        "limits": ["Supplied snapshots only; no complete-history or external-custody proof.",
                   "No checkpoint is selected and no target state is changed.",
                   "Validity is evaluated at the host-supplied time; this export does not establish current validity later.",
                   "This export is unsigned. Its digest is an integrity reference, not an authority signature."]}
    encoded = _encode(document)
    if len(encoded) > MAX_EXPORT_BYTES:
        raise ValueError("checkpoint report exceeds export byte limit")
    digest = hashlib.sha256(encoded).hexdigest()

    def section(title, value):
        # JSON escaping makes direction/control characters visible. No supplied
        # string is interpreted as markup, a link, an attribute or an instruction.
        return ("<section><h2>" + html.escape(title) + "</h2><pre tabindex='0'>" +
                html.escape(json.dumps(value, ensure_ascii=True, indent=2)) + "</pre></section>")

    page = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "base-uri 'none'; form-action 'none'\"><title>Checkpoint observation report</title>"
            "</head><body><main><h1>Checkpoint observation report</h1>"
            "<p>Verified observation status: " + html.escape(result["status"]) + "</p>" +
            section("Scope and trust pins supplied by the host", document["host_pins"]) +
            section("Fresh verification results", result) +
            section("Limits", document["limits"]) +
            section("Supplied signed evidence, including rejected candidates", snapshot) +
            section("JSON export SHA-256", digest) + "</main></body></html>")
    return {"json_bytes": encoded, "sha256": digest, "html": page, "status": result["status"]}
