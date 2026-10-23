"""Qualification-contract gate for approval screening, not a persuasion detector."""

from dataclasses import asdict
import json

from assurance_reference.qualified_engine import QualificationSet
from assurance_reference.review_material import MaterialReview, _digest, _json
from factory.projectos.governed_release import PREPARATION_FIELD
from regulated_core.approval_evidence import ReviewError
from regulated_core.clock import ClockError, read_clock
from regulated_core.qualification import QualificationError
from regulated_core.signing import Signature


SCREENING_FIELD = "approval_screening_v1"
VERIFICATION_CLASS = "approval:persuasion"


def screening_scope(contract):
    """Digest the full input contract, excluding only its resulting attestation.

    The original review subsequently signs the complete contract including that
    attestation. This exclusion avoids a self-referential digest; it does not
    exclude any target, artifact, declaration or commentary from screening.
    """
    return _digest(_json({k: v for k, v in contract.items() if k != SCREENING_FIELD}).encode("ascii"))


def screening_attestation(*, signer, contract, tenant, verifier_version,
                          qualification_digest, clock_domain, observed_us,
                          expires_us, result, evidence_kind):
    """Encode a checker's signed observation; this function runs no detector.

    Synthetic results must be explicitly labelled and never enable grants.
    Calling this function does not establish checker qualification or truth.
    """
    body = {"schema": "reference/approval-screening/v1", "tenant": tenant,
            "contract_scope_sha256": screening_scope(contract),
            "artifact_sha256": contract[PREPARATION_FIELD]["artifact_sha256"],
            "verification_class": VERIFICATION_CLASS, "verifier_version": verifier_version,
            "qualification_digest": qualification_digest, "clock_domain": clock_domain,
            "observed_us": observed_us, "expires_us": expires_us, "result": result,
            "evidence_kind": evidence_kind}
    _shape(body)
    return {"body": body, "signature": asdict(signer.sign(body))}


def _shape(body):
    fields = {"schema", "tenant", "contract_scope_sha256", "artifact_sha256",
              "verification_class", "verifier_version", "qualification_digest", "clock_domain",
              "observed_us", "expires_us", "result", "evidence_kind"}
    if (type(body) is not dict or set(body) != fields
            or body["schema"] != "reference/approval-screening/v1"
            or body["verification_class"] != VERIFICATION_CLASS
            or body["result"] not in {"clear", "flagged", "unknown"}
            or body["evidence_kind"] not in {"synthetic", "operational"}
            or any(not isinstance(body[k], str) or not body[k].strip() or len(body[k]) > 256
                   for k in ("tenant", "verifier_version", "clock_domain"))
            or any(not isinstance(body[k], str) or len(body[k]) != 64
                   or any(c not in "0123456789abcdef" for c in body[k])
                   for k in ("contract_scope_sha256", "artifact_sha256", "qualification_digest"))
            or type(body["observed_us"]) is not int or type(body["expires_us"]) is not int
            or not 0 <= body["observed_us"] < body["expires_us"]):
        raise ValueError("invalid screening attestation shape")


class ApprovalScreening:
    """Host-pinned authority, checker identity, report, clock and escalation route.

    `operational_admission` is a host decision, disabled by default. Enabling it
    requires separately established operational qualification; a valid report
    signature/metric contract alone does not establish scientific adequacy.
    """

    def __init__(self, *, trust, checker_key_id, qualification_authority, clock,
                 requirement, report, escalation_route, operational_admission=False):
        if (requirement.verification_class != VERIFICATION_CLASS
                or report.verification_class != VERIFICATION_CLASS
                or not isinstance(checker_key_id, str) or not checker_key_id
                or not isinstance(escalation_route, str) or not escalation_route.strip()
                or type(operational_admission) is not bool):
            raise ValueError("explicit persuasion requirement, checker and escalation route required")
        self._qualification = QualificationSet(trust=trust, authority=qualification_authority,
            clock_domain=clock.domain, required=(requirement,), reports=(report,))
        self._trust, self._checker, self._clock = trust, checker_key_id, clock
        self._report, self._version = report.digest(), requirement.verifier_version
        self._route, self._operational = escalation_route, operational_admission

    def assess(self, contract, *, tenant):
        """Return explicit incomplete/escalation for unknown or ineligible checks."""
        outcome = {"schema": "reference/approval-screening-disposition/v1",
                   "status": "ESCALATE", "eligible_for_grant": False,
                   "escalation_route": self._route,
                   "scientific_qualification_established_by_this_check": False}
        try:
            contract = json.loads(_json(contract))
            signed = contract.get(SCREENING_FIELD)
            if type(signed) is not dict or set(signed) != {"body", "signature"}:
                raise ValueError("missing screening evidence")
            body = signed["body"]
            _shape(body)
            signature = Signature(**signed["signature"])
            if signature.key_id != self._checker or not self._trust.verify(body, signature):
                raise ValueError("screening signature differs")
            reading = read_clock(self._clock)
            digests, deadline = self._qualification.check(reading)
            if (body["tenant"] != tenant or body["clock_domain"] != reading.domain
                    or body["contract_scope_sha256"] != screening_scope(contract)
                    or body["artifact_sha256"] != contract[PREPARATION_FIELD]["artifact_sha256"]
                    or body["verifier_version"] != self._version
                    or body["qualification_digest"] != self._report or digests != (self._report,)
                    or not body["observed_us"] <= reading.now_us < body["expires_us"] <= deadline):
                raise ValueError("screening scope, report or time differs")
            # Qualification must also have been valid when this check was made.
            self._qualification.check(type(reading)(reading.domain, body["observed_us"]))
        except (ValueError, TypeError, KeyError, QualificationError, ClockError, ReviewError):
            return {**outcome, "reason": "missing-invalid-or-unqualified-evidence"}
        if body["evidence_kind"] == "synthetic":
            return {**outcome, "reason": "synthetic-evidence-only"}
        if not self._operational:
            return {**outcome, "reason": "operational-qualification-not-admitted"}
        if body["result"] != "clear":
            return {**outcome, "reason": "screening-" + body["result"]}
        return {**outcome, "status": "CLEAR_BY_HOST_POLICY", "eligible_for_grant": True,
                "reason": "current-signed-result-and-host-admitted-report"}


class ScreenedMaterialReview(MaterialReview):
    """Opt-in host review route requiring screening as well as exact material.

    The original grant still decides authority. This pre-grant seam does not add
    transaction-coupled checker withdrawal or replace original Tier 4 controls.
    """

    def __init__(self, gate, *, screening):
        super().__init__(gate)
        if not isinstance(screening, ApprovalScreening):
            raise TypeError("a host-configured approval screening gate is required")
        self._screening = screening

    def view(self, **request):
        contract = json.loads(_json(request["contract"]))
        result = super().view(**{**request, "contract": contract})
        disposition = self._screening.assess(contract, tenant=request["context"].tenant)
        bound = {**result["bound"], "screening_attestation": contract.get(SCREENING_FIELD),
                 "screening_disposition": disposition}
        return {**result, "bound": bound, "display_sha256": _digest(_json(bound).encode("ascii"))}

    def grant(self, **request):
        contract = json.loads(_json(request["contract"]))
        disposition = self._screening.assess(contract, tenant=request["context"].tenant)
        if not disposition["eligible_for_grant"]:
            raise ReviewError("screening requires escalation: " + disposition["reason"])
        return super().grant(**{**request, "contract": contract})
