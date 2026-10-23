"""Regulatory reporting — PROJECTIONS over the canonical evidence graph, never a new data model.

The evidence pack (plus the system-level artifacts: assurance evidence, drill reports, qualification
and policy ledgers) is canonical. Different stakeholders need different VIEWS of the same facts:

    Canonical Evidence Graph
            ├── Annex IV projection            (regulators: EU AI Act technical documentation)
            ├── DSSE/in-toto attestation       (machines: standard signed attestation envelope)
            ├── Human assurance report         (people: "why was this decision allowed?" in plain language)
            └── Audit trace projection         (auditors: the digest chain, link by link)

Every projection is a PURE FUNCTION of the evidence — it never mutates, augments, or re-signs the
underlying facts (the DSSE envelope adds a signature over the projection, not over new claims). When a
regime changes its documentation format, a projection changes; the evidence model does not.

Formats are borrowed, not invented (see docs/regulated-architecture/09-prior-art-and-positioning.md):
the machine attestation is a real in-toto v1 Statement in a real DSSE envelope — signed over the DSSE
Pre-Authentication Encoding byte-for-byte, so standard external tooling can verify it. The regulator
projection follows the EU AI Act Annex IV section structure and is HONEST about its boundary: sections
the runtime cannot know (harmonised standards applied, the declaration of conformity, ...) are marked
as supplied by the management system, never fabricated.

Pure core (no factory dependency); standalone import.
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any, cast

from .signing import Signer, TrustDirectory

JSONDict = dict[str, Any]

# --- machine projection: in-toto Statement in a DSSE envelope ----------------------------------

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EMISSION_PREDICATE_TYPE = "urn:regulated-core:attestation:emission-evidence:v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding — byte-exact per the DSSE spec, so external verifiers work."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def project_dsse_attestation(signer: Signer, evidence_pack: JSONDict) -> JSONDict:
    """Project an evidence pack into a signed DSSE envelope carrying an in-toto v1 Statement. The
    statement's subject is the evidence chain head (and the emitted output digest when present); the
    predicate is the evidence pack itself — a projection, not new claims."""
    subject = [{"name": "evidence-chain-head", "digest": {"sha256": evidence_pack["evidence_head_hash"]}}]
    permit = evidence_pack.get("emission_permit")
    if permit:
        subject.append({"name": "emitted-output", "digest": {"sha256": permit["output_digest"]}})
    statement = {"_type": INTOTO_STATEMENT_TYPE, "subject": subject,
                 "predicateType": EMISSION_PREDICATE_TYPE, "predicate": evidence_pack}
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    sig = signer.sign_bytes(_pae(DSSE_PAYLOAD_TYPE, payload))
    return {"payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.standard_b64encode(payload).decode("ascii"),
            "signatures": [{"keyid": sig.key_id,
                            "sig": base64.standard_b64encode(
                                bytes.fromhex(sig.value)).decode("ascii")}]}


def verify_dsse_attestation(trust: TrustDirectory, envelope: JSONDict) -> bool:
    """Verify a DSSE envelope against the trust directory (fail closed on any malformation)."""
    try:
        payload_type = envelope["payloadType"]
        signatures = envelope["signatures"]
        if not isinstance(payload_type, str) or not isinstance(signatures, list):
            return False
        payload = base64.b64decode(envelope["payload"], validate=True)
        pae = _pae(payload_type, payload)
        return any(
            trust.verify_registered_bytes(
                pae,
                s["keyid"],
                base64.b64decode(s["sig"], validate=True).hex(),
            )
            for s in signatures
        )
    except (binascii.Error, KeyError, TypeError, ValueError):
        return False


def dsse_statement(envelope: JSONDict) -> JSONDict:
    """Decode the in-toto Statement carried by a DSSE envelope (no verification — pair with verify)."""
    parsed = json.loads(base64.standard_b64decode(envelope["payload"]))
    if not isinstance(parsed, dict):
        raise ValueError("DSSE statement payload must be a JSON object")
    return cast(JSONDict, parsed)


# --- regulator projection: EU AI Act Annex IV structure ----------------------------------------

_MANAGEMENT_SYSTEM = "supplied by the management system (outside the runtime's knowledge — never fabricated)"


def project_annex_iv(
    evidence_pack: JSONDict,
    *,
    system_name: str,
    provider: str,
    assurance: object | None = None,
    drill_report: object | None = None,
) -> JSONDict:
    """Project the evidence into the EU AI Act Annex IV technical-documentation structure. Sections the
    runtime genuinely knows are filled from evidence; sections it cannot know are explicitly marked."""
    lineage = evidence_pack.get("source_provenance") or {}
    approval = evidence_pack.get("approval") or {}
    quals = evidence_pack.get("qualifications") or {}
    policy = evidence_pack.get("policy") or {}
    worm = evidence_pack.get("worm_retention")
    return {
        "schema": "regulated/annex-iv-projection/v1",
        "1_general_description": {
            "system_name": system_name, "provider": provider,
            "intended_purpose": evidence_pack.get("intended_use", ""),
            "prohibited_uses": evidence_pack.get("prohibited_uses", []),
            "vertical": evidence_pack.get("vertical", "")},
        "2_detailed_description": {
            "producing_model": lineage.get("model_id", ""),
            "producer_run": lineage.get("run_id", ""),
            "content_commitment": evidence_pack.get("assertion_digest", ""),
            "policy_in_force": {"policy_id": policy.get("policy_id", ""),
                                "version": policy.get("version", ""),
                                "document_digest": policy.get("document_digest", "")}},
        "3_monitoring_and_human_oversight": {
            "human_approval": {"approvers": approval.get("approvers", []),
                               "requirement_digest": approval.get("requirement_digest", ""),
                               "credential_verification_receipts": approval.get("credential_receipts", [])},
            "decision_control": evidence_pack.get("decision", {})},
        "4_performance_metrics_and_appropriateness": {
            "verifier_attestations": evidence_pack.get("verifier_attestations", []),
            "verifier_qualifications": quals,
            "note": "operating characteristics are measured against content-addressed datasets; "
                    "see each qualification's report_digest"},
        "5_risk_management_system": {
            "consequence_policy": policy,
            "required_verifiers": sorted(quals) if quals else [],
            "fail_closed": True},
        "6_lifecycle_changes": {
            "policy_supersession": "tracked by digest in the policy ledger",
            "verifier_requalification": "tracked by digest in the qualification registry",
            "detail": _MANAGEMENT_SYSTEM},
        "7_harmonised_standards": _MANAGEMENT_SYSTEM,
        "8_declaration_of_conformity": _MANAGEMENT_SYSTEM,
        "9_post_market_monitoring": {
            "evidence_retention": worm if worm else "no WORM anchor bound for this decision",
            "resilience_posture": (getattr(drill_report, "signed_body", lambda: _MANAGEMENT_SYSTEM)()
                                   if drill_report is not None else _MANAGEMENT_SYSTEM)},
        "evidence_head_hash": evidence_pack.get("evidence_head_hash", ""),
    }


# --- auditor projection: the digest chain, link by link ----------------------------------------

def project_audit_trace(evidence_pack: JSONDict) -> list[JSONDict]:
    """Project the evidence into the auditor's chain-of-custody view: every artifact, its digest, and
    what binds it. Each link answers 'how do I know this was not substituted?'"""
    trace: list[JSONDict] = [{
        "artifact": "content", "digest": evidence_pack.get("assertion_digest", ""),
        "bound_by": "every verifier attestation and the emission permit sign over this digest"}]
    for v in evidence_pack.get("verifier_attestations", []):
        trace.append({"artifact": f"verification:{v['class']}", "outcome": v["outcome"],
                      "digest": "", "signed_by": v.get("signature_key_id", v.get("verifier_id", "")),
                      "bound_by": "signature over (assertion digest, tenant, timestamp, result)"})
    for cls, q in (evidence_pack.get("qualifications") or {}).items():
        trace.append({"artifact": f"qualification:{cls}",
                      "digest": (q or {}).get("report_digest", "MISSING — not currently qualified"),
                      "bound_by": "immutable signed report; dataset pinned by dataset_digest"})
    policy = evidence_pack.get("policy") or {}
    if policy:
        trace.append({"artifact": "policy-document", "digest": policy.get("document_digest", ""),
                      "bound_by": "digest carried inside the signed decision record"})
    approval = evidence_pack.get("approval")
    if approval:
        trace.append({"artifact": "approval-certificate", "digest": approval.get("requirement_digest", ""),
                      "approvers": approval.get("approvers", []),
                      "credential_receipts": approval.get("credential_receipts", []),
                      "bound_by": "certificate signs the requirement digest and the credential receipt digests"})
    permit = evidence_pack.get("emission_permit")
    if permit:
        trace.append({"artifact": "emission-permit", "digest": permit.get("output_digest", ""),
                      "bound_by": "single-use, output-bound, expiring; use recorded in the permit store"})
    trace.append({"artifact": "evidence-chain-head", "digest": evidence_pack.get("evidence_head_hash", ""),
                  "bound_by": "hash-chained, recorder-signed; every prior link is inside this record"})
    worm = evidence_pack.get("worm_retention")
    if worm:
        trace.append({"artifact": "worm-retention", "digest": worm.get("content_digest", ""),
                      "object_ref": worm.get("object_ref", ""),
                      "bound_by": "write-once store; immutable until retained_until_us"})
    return trace


# --- human projection: plain language, still backed by the graph -------------------------------

def project_human_assurance(evidence_pack: JSONDict) -> str:
    """Project the evidence into a plain-language answer to 'why was this decision allowed (or not)?'
    Deterministic, no new claims — every sentence is traceable back to a field in the pack."""
    lines: list[str] = []
    decision = evidence_pack.get("decision", {})
    kind = decision.get("kind", "unknown")
    vertical = evidence_pack.get("vertical", "this system")
    action = evidence_pack.get("action", "the action")
    lines.append(f"Decision summary for {vertical} — action '{action}'.")

    if kind in ("allow", "allow-with-annotation", "require-approval"):
        lines.append("This release was PERMITTED. Here is why, step by step:")
    else:
        codes = ", ".join(decision.get("reason_codes", [])) or "unspecified"
        lines.append(f"This release was DENIED (reason: {codes}). {decision.get('rationale', '')}".strip())

    lines.append(f"Intended use: {evidence_pack.get('intended_use', 'not declared')}.")

    verifs = evidence_pack.get("verifier_attestations", [])
    if verifs:
        passed = [v["class"] for v in verifs if v["outcome"] == "pass"]
        failed = [v["class"] for v in verifs if v["outcome"] != "pass"]
        lines.append(f"Automated safety checks: {len(passed)} of {len(verifs)} passed"
                     + (f"; FAILED: {', '.join(failed)}." if failed else "."))
        quals = evidence_pack.get("qualifications") or {}
        for cls, q in sorted(quals.items()):
            if q:
                lines.append(f"  - {cls}: qualified against dataset {q['dataset']} "
                             f"(precision {q['precision']}, recall {q['recall']}).")
            else:
                lines.append(f"  - {cls}: NOT currently qualified — this gap is visible to the production gate.")

    approval = evidence_pack.get("approval")
    if approval:
        who = ", ".join(approval.get("approvers", []))
        receipts = approval.get("credential_receipts", [])
        lines.append(f"Human approval: {who}."
                     + (f" Each approval is bound to a verified professional credential "
                        f"({len(receipts)} signed verification receipt(s))." if receipts else
                        " (Approver roles were locally credentialed; no external licence verification was wired.)"))

    policy = evidence_pack.get("policy") or {}
    if policy.get("policy_id"):
        doc = policy.get("document_digest", "")
        lines.append(f"Governing policy: {policy['policy_id']} v{policy.get('version', '?')}"
                     + (f", content-committed as {doc[:16]}…." if doc else
                        " (policy content not digest-committed for this decision)."))

    permit = evidence_pack.get("emission_permit")
    if permit:
        lines.append("The released output is bound to a single-use permit: this exact content, once, "
                     "within an expiry window — it cannot be replayed or swapped.")

    worm = evidence_pack.get("worm_retention")
    if worm:
        lines.append("The complete evidence for this decision is retained in write-once storage "
                     f"(ref {worm.get('object_ref', '')}) and cannot be altered or deleted during retention.")

    lines.append("Every statement above is derived from the signed evidence record "
                 f"(chain head {evidence_pack.get('evidence_head_hash', '')[:16]}…); "
                 "nothing in this report exists only in this report.")
    return "\n".join(lines)


__all__ = [
    "INTOTO_STATEMENT_TYPE", "EMISSION_PREDICATE_TYPE", "DSSE_PAYLOAD_TYPE",
    "project_dsse_attestation", "verify_dsse_attestation", "dsse_statement",
    "project_annex_iv", "project_audit_trace", "project_human_assurance",
]
