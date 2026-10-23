"""Opt-in exact-material approval presentation over the existing guarded exchange.

This is the artifact-binding increment of A22, not persuasion qualification or
proof that a human read, understood, or freely approved the displayed material.
"""

import base64
import difflib
import hashlib
import html
import json

from factory.projectos.governed_release import PREPARATION_FIELD, TARGET_FIELD
from regulated_core.approval_evidence import ReviewError


MATERIAL_FIELD = "approval_material_v1"
COMMENTARY_FIELD = "approval_commentary_v1"
MAX_BYTES = 262144
_FIELDS = {"schema", "prior_artifact_sha256", "reversibility", "exposure",
           "checker_findings", "uncertainty"}


def _json(value):
    # Reject opaque Python objects rather than copying the original destination's
    # default=str fallback into an authoritative presentation schema.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ReviewError("approval material must be finite JSON data") from exc


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ReviewError(f"{name} must be nonempty text of at most 4096 characters")
    return value


def _artifact(value):
    if type(value) is not bytes or len(value) > MAX_BYTES:
        raise ReviewError("review artifact must be bytes, at most 262144 bytes")
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReviewError("this review view requires UTF-8 artifacts") from exc
    if len(text.splitlines()) > 4096:
        raise ReviewError("review artifact exceeds 4096 lines")
    return text


def commentary_contract(contract, *, text):
    """Attach shared, non-authoritative text BEFORE the original signed review.

    There is deliberately no recipient, action, role, target or approval field.
    Commentary cannot privately select an approver or supply authority fields.
    Its presence does not establish who actually authored it.
    """
    if COMMENTARY_FIELD in contract:
        raise ReviewError("commentary already exists; create a new reviewed contract")
    commentary = {"schema": "reference/shared-review-commentary/v1", "text": _text(text, "commentary")}
    return json.loads(_json({**contract, COMMENTARY_FIELD: commentary}))


def _commentary(contract):
    if COMMENTARY_FIELD not in contract:
        return None
    value = contract[COMMENTARY_FIELD]
    if (type(value) is not dict or set(value) != {"schema", "text"}
            or value["schema"] != "reference/shared-review-commentary/v1"):
        raise ReviewError("commentary must be shared fixed-schema text without authority or recipient fields")
    return {"label": "Untrusted commentary; not an authority instruction",
            "visibility": "shared-review-contract", "authoritative": False,
            "text": _text(value["text"], "commentary")}


def material_contract(contract, *, prior_artifact, reversibility, exposure,
                      checker_findings, uncertainty):
    """Add explicit declarations BEFORE opening the signed original review.

    A missing predecessor is distinct from a supplied empty predecessor. This
    function binds supplied bytes, not a claim that they are the target's actual
    historical state. Target state remains checked by the original release gate.
    """
    if MATERIAL_FIELD in contract:
        raise ReviewError("approval material already exists; create a new reviewed contract")
    if prior_artifact is not None:
        _artifact(prior_artifact)
    material = {"schema": "reference/approval-material/v1",
                "prior_artifact_sha256": None if prior_artifact is None else _digest(prior_artifact),
                "reversibility": reversibility, "exposure": exposure,
                "checker_findings": checker_findings, "uncertainty": uncertainty}
    _validate_material(material)
    return json.loads(_json({**contract, MATERIAL_FIELD: material}))


def _validate_material(material):
    if (not isinstance(material, dict) or set(material) != _FIELDS
            or material["schema"] != "reference/approval-material/v1"):
        raise ReviewError("fixed-schema approval material is required")
    prior = material["prior_artifact_sha256"]
    if prior is not None and (not isinstance(prior, str) or len(prior) != 64
                              or any(c not in "0123456789abcdef" for c in prior)):
        raise ReviewError("invalid prior artifact digest")
    for name in ("reversibility", "exposure", "uncertainty"):
        _text(material[name], name)
    findings = material["checker_findings"]
    if not isinstance(findings, list) or not 1 <= len(findings) <= 32:
        raise ReviewError("declare one to 32 checker findings, including unknown if applicable")
    for finding in findings:
        _text(finding, "checker finding")


def _line_representation(text):
    # JSON string lines preserve CR/LF, missing final newline, bidi controls and
    # invisible characters visibly. Diff is never parsed as HTML or Markdown.
    return [json.dumps(line, ensure_ascii=True) + "\n" for line in text.splitlines(keepends=True)]


class MaterialReview:
    """Host adapter; the injected gate retains all authentication/approval checks.

    Hosts must route their review UI through this adapter to require its display
    acknowledgement. Direct original exchange calls remain available and are not
    claimed to enforce A22. No producer-supplied view/status is accepted here.
    """

    def __init__(self, gate):
        if not all(callable(getattr(gate, name, None)) for name in ("get_review", "grant_review")):
            raise TypeError("material review requires the guarded review interface")
        self._gate = gate

    def view(self, *, spec, contract, context, review_id, artifact, prior_artifact=None):
        # Snapshot mutable JSON once. Both validation and signed destination
        # comparison below see precisely this detached contract.
        contract = json.loads(_json(contract))
        material = contract.get(MATERIAL_FIELD)
        _validate_material(material)
        commentary = _commentary(contract)
        text = _artifact(artifact)
        prior_text = None if prior_artifact is None else _artifact(prior_artifact)
        expected_prior = None if prior_artifact is None else _digest(prior_artifact)
        if material["prior_artifact_sha256"] != expected_prior:
            raise ReviewError("prior artifact does not match reviewed material")
        prepared, target = contract.get(PREPARATION_FIELD), contract.get(TARGET_FIELD)
        if (not isinstance(prepared, dict) or prepared.get("artifact_sha256") != _digest(artifact)
                or not isinstance(target, dict) or not target):
            raise ReviewError("artifact or target does not match the prepared release")
        # Original get_review verifies evidence signature, exact contract digest,
        # scope, window and prior grants. No unverified store reads are used.
        review = self._gate.get_review(spec=spec, contract=contract, context=context,
                                       review_id=review_id)
        bound = {"schema": "reference/approval-display/v1", "tenant": context.tenant,
                 "reviewer": context.actor_id, "review_id": review["review_id"],
                 "decision_record_hash": review["decision_record_hash"],
                 "project": review["project_id"], "action": review["action_id"],
                 "nonce": review["nonce"], "requester": review["requester_id"],
                 "reason": review["reason"],
                 "required_role_groups": review["required_role_groups"],
                 "minimum_approvers": review["minimum_approvers"],
                 "expires_at_us": review["expires_at_us"], "target": target,
                 "contract_sha256": _digest(_json(contract).encode("ascii")),
                 "artifact_sha256": _digest(artifact),
                 "artifact_base64": base64.b64encode(artifact).decode("ascii"),
                 "artifact_lines": _line_representation(text), "declarations": material,
                 "untrusted_commentary": commentary,
                 "diff": None if prior_text is None else "".join(difflib.unified_diff(
                     _line_representation(prior_text), _line_representation(text),
                     fromfile="supplied-prior", tofile="reviewed-artifact"))}
        return {"bound": bound, "display_sha256": _digest(_json(bound).encode("ascii")),
                "status": review["status"], "approver_ids": list(review["approver_ids"])}

    def grant(self, *, displayed_sha256, spec, contract, context, review_id, role,
              artifact, prior_artifact=None):
        contract = json.loads(_json(contract))
        current = self.view(spec=spec, contract=contract, context=context, review_id=review_id,
                            artifact=artifact, prior_artifact=prior_artifact)
        if displayed_sha256 != current["display_sha256"]:
            raise ReviewError("display changed or belongs to another reviewer; renewed review required")
        # This revalidates the signed decision and merges under the original
        # store's lock. Display acknowledgement never substitutes for credentials.
        return self._gate.grant_review(spec=spec, contract=contract, context=context,
                                       review_id=review_id, role=role)


def render_review(view):
    """Read-only, standalone semantic HTML; no scripts, forms or remote resources.

    The entire bound payload is displayed, including exact base64 bytes. A UI
    host handles authenticated grant/refusal separately; this is not that server.
    """
    bound = view["bound"]
    if _digest(_json(bound).encode("ascii")) != view["display_sha256"]:
        raise ReviewError("display payload digest mismatch")
    sections = []
    for name, value in bound.items():
        label = name.replace("_", " ").capitalize()
        sections.append(f"<section><h2>{html.escape(label)}</h2>"
                        f"<pre tabindex='0'>{html.escape(json.dumps(value, indent=2, ensure_ascii=True))}"
                        "</pre></section>")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "base-uri 'none'; form-action 'none'\"><title>Exact approval material</title></head>"
            "<body><main><h1>Exact approval material</h1>"
            "<p>Reversibility, exposure, findings and uncertainty are signed contract declarations; "
            "their truth and persuasion-screening qualification are not established by this view. "
            "Diff uses JSON-escaped lines of the supplied prior artifact. "
            "This page cannot grant approval.</p>" + "".join(sections) +
            "<section><h2>Display acknowledgement digest</h2><pre tabindex='0'>" +
            html.escape(view["display_sha256"]) + "</pre></section></main></body></html>")
