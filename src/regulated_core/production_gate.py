"""Fail-closed production-readiness gate over SIGNED, STRUCTURED assurance evidence.

Code is not compliance. This gate refuses a regulated release until an assurance authority
attests every mandatory control WITH structure the gate can check semantically — not booleans a
caller could flip. It is where the honest boundary (COMPLIANCE-BOUNDARY.md) becomes enforceable.
"""
from __future__ import annotations

from typing import Any, Protocol

from dataclasses import dataclass

from .canonical import canonical_bytes, digest_hex
from .clock import TrustedClock, read_clock
from .qualification import QualificationLookup, verify_report
from .resilience import DrillReport, verify_drill_report
from .signing import Signature, TrustDirectory, is_kms_backed
from .worm import WormReceipt, WormStore
from decimal import Decimal, InvalidOperation

MANDATORY = (
    "hsm_kms_custody", "worm_retention", "authoritative_identity", "validated_verifiers",
    "calibration_evidence", "resilience_drills", "regulatory_reporting", "model_governance",
    "management_system",
)


class ProductionReadinessError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AssuranceEvidence:
    scope: str
    attested_at_us: int
    controls: dict[str, bool]              # each mandatory control present + true
    worm_retention_days: int               # semantic: must meet the regime minimum
    model_owner_id: str                    # semantic: owner must differ from validator (SR 11-7)
    model_validator_id: str
    calibration_error: str                 # decimal string; must be <= tolerance
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/assurance/v1", "scope": self.scope, "attested_at_us": self.attested_at_us,
                "controls": {k: self.controls.get(k, False) for k in MANDATORY},
                "worm_retention_days": self.worm_retention_days, "model_owner_id": self.model_owner_id,
                "model_validator_id": self.model_validator_id, "calibration_error": self.calibration_error}


@dataclass(frozen=True, slots=True)
class ReadinessWindow:
    """Host-created proof deadline, checked again at the receiving effect."""

    clock: TrustedClock
    verified_at_us: int
    expires_at_us: int

    def check_current(self) -> None:
        """Refuse expiry, clock regression or an unavailable authority clock."""
        try:
            now_us = read_clock(self.clock).now_us
        except Exception as exc:
            raise ProductionReadinessError("readiness clock unavailable before release") from exc
        if not self.verified_at_us <= now_us < self.expires_at_us:
            raise ProductionReadinessError("readiness proof is no longer current")


class ProductionGate:
    """Check one host-declared scope against current, explicitly supplied proofs.

    Requirements and time come from the composition, never the attestation.
    Local provider adapters can test this contract; they do not establish deployed
    custody or storage guarantees.
    """

    def __init__(self, trust: TrustDirectory, assurance_key_id: str, *,
                 clock: TrustedClock, scope: str,
                 required_verifiers: tuple[str, ...], required_drills: tuple[str, ...],
                 qualification_authority: str, drill_authority: str,
                 max_attestation_age_us: int, min_worm_days: int = 2555, max_calibration_error: str = "0.05") -> None:
        for label, values in (("scope", (scope,)), ("verifiers", required_verifiers),
                              ("drills", required_drills),
                              ("authorities", (assurance_key_id, qualification_authority, drill_authority))):
            if (not values or any(not isinstance(v, str) or not v or v != v.strip() for v in values)
                    or (label in ("verifiers", "drills") and len(set(values)) != len(values))):
                raise ValueError(f"readiness requires explicit valid {label}")
        if type(min_worm_days) is not int or min_worm_days <= 0:
            raise ValueError("readiness retention must be a positive number of days")
        self._trust, self._authority, self._clock, self._scope = trust, assurance_key_id, clock, scope
        self._required_verifiers, self._required_drills = required_verifiers, required_drills
        self._qualification_authority, self._drill_authority = qualification_authority, drill_authority
        self._min_worm_days = min_worm_days
        if type(max_attestation_age_us) is not int or max_attestation_age_us <= 0:
            raise ValueError("readiness attestation age must be a positive number of microseconds")
        self._max_attestation_age_us = max_attestation_age_us
        try:
            maximum = Decimal(max_calibration_error)
        except InvalidOperation as exc:
            raise ValueError("invalid readiness calibration tolerance") from exc
        if not maximum.is_finite() or maximum < 0:
            raise ValueError("invalid readiness calibration tolerance")
        self._max_cal = maximum

    def check(self, e: AssuranceEvidence, *, evidence_signer: object | None = None,
              credential_verifier: object | None = None,
              qualifications: QualificationLookup | None = None,
              drill_report: DrillReport | None = None, worm_store: WormStore | None = None,
              worm_receipt: WormReceipt | None = None) -> ReadinessWindow:
        """Refuse missing, untrusted, stale or scope-mismatched readiness proofs.

        The host passes its actual approver verifier, not a request-supplied
        identity flag. Its provider marker and verification port identify the
        configured adapter; they do not independently prove deployed custody or
        contact the provider. Per-approval credential checks remain mandatory.
        """
        try:
            now_us = read_clock(self._clock).now_us
        except Exception as exc:
            raise ProductionReadinessError("readiness clock unavailable") from exc
        if e.scope != self._scope:
            raise ProductionReadinessError("assurance scope differs from the configured scope")
        if type(e.attested_at_us) is not int or not 0 <= e.attested_at_us <= now_us:
            raise ProductionReadinessError("assurance attestation time is invalid or in the future")
        if now_us - e.attested_at_us >= self._max_attestation_age_us:
            raise ProductionReadinessError("assurance attestation exceeds its configured maximum age")
        proof_deadline_us = e.attested_at_us + self._max_attestation_age_us
        if e.signature.key_id != self._authority or not self._trust.verify(e.signed_body(), e.signature):
            raise ProductionReadinessError("assurance evidence signature invalid or untrusted")
        missing = [c for c in MANDATORY if e.controls.get(c) is not True]
        if missing:
            raise ProductionReadinessError(f"controls not satisfied: {missing}")
        if type(e.worm_retention_days) is not int or e.worm_retention_days < self._min_worm_days:
            raise ProductionReadinessError("WORM retention is below the configured minimum")
        if not e.model_owner_id or not e.model_validator_id or e.model_owner_id == e.model_validator_id:
            raise ProductionReadinessError("model validator must be independent of the owner")
        try:
            calibration = Decimal(e.calibration_error)
        except InvalidOperation as exc:
            raise ProductionReadinessError("calibration error must be a finite decimal") from exc
        if not calibration.is_finite() or not 0 <= calibration <= self._max_cal:
            raise ProductionReadinessError("calibration error exceeds tolerance or is invalid")
        if evidence_signer is None or not is_kms_backed(evidence_signer):
            raise ProductionReadinessError("evidence signer must have KMS/HSM custody")
        try:
            provider_backed = (
                getattr(credential_verifier, "provider_backed", False) is True
                and callable(getattr(credential_verifier, "verify", None))
            )
        except Exception as exc:
            raise ProductionReadinessError("credential verifier is unavailable") from exc
        if not provider_backed:
            raise ProductionReadinessError("approvals require the composed provider-backed credential verifier")
        if qualifications is None:
            raise ProductionReadinessError("qualification proof is required")
        for verification_class in self._required_verifiers:
            try:
                report = qualifications.current(verification_class, now_us)
            except Exception as exc:
                raise ProductionReadinessError("qualification proof unavailable") from exc
            if (report is None or report.verification_class != verification_class
                    or report.qualified_by != self._qualification_authority
                    or not report.qualified_at_us <= now_us < report.expires_at_us
                    or not verify_report(self._trust, report, authority=self._qualification_authority)):
                raise ProductionReadinessError(f"verifier not currently qualified: {verification_class}")
            proof_deadline_us = min(proof_deadline_us, report.expires_at_us)
        if drill_report is None:
            raise ProductionReadinessError("drill report is required")
        if (drill_report.scope != self._scope or drill_report.executed_by != self._drill_authority
                or not verify_drill_report(self._trust, drill_report, authority=self._drill_authority)):
            raise ProductionReadinessError("drill report scope or authority differs")
        if not drill_report.executed_at_us <= now_us < drill_report.expires_at_us:
            raise ProductionReadinessError("drill report is not current")
        outcomes = {o.drill_id: o for o in drill_report.outcomes}
        if (len(outcomes) != len(drill_report.outcomes) or not drill_report.all_passed
                or any(d not in outcomes or outcomes[d].passed is not True for d in self._required_drills)):
            raise ProductionReadinessError("drill report is incomplete or records unsuccessful outcomes")
        if worm_store is None or worm_receipt is None:
            raise ProductionReadinessError("verified retention proof is required")
        if (worm_receipt.content_digest != digest_hex(e.signed_body())
                or not e.attested_at_us <= worm_receipt.stored_at_us <= now_us
                or worm_receipt.retained_until_us < worm_receipt.stored_at_us + e.worm_retention_days * 86_400_000_000
                or now_us >= worm_receipt.retained_until_us):
            raise ProductionReadinessError("retention proof content or validity differs")
        try:
            retained = worm_store.fetch(self._scope, worm_receipt.object_ref)
            verified = worm_store.verify(worm_receipt)
        except Exception as exc:
            raise ProductionReadinessError("retention proof unavailable") from exc
        if verified is not True or retained != canonical_bytes(e.signed_body()):
            raise ProductionReadinessError("retention proof could not be verified")
        try:
            completed_at_us = read_clock(self._clock).now_us
        except Exception as exc:
            raise ProductionReadinessError("readiness clock unavailable at completion") from exc
        if completed_at_us < now_us:
            raise ProductionReadinessError("readiness clock moved backwards during verification")
        deadline_us = min(proof_deadline_us, drill_report.expires_at_us, worm_receipt.retained_until_us)
        if completed_at_us >= deadline_us:
            raise ProductionReadinessError("readiness proof expired during verification")
        return ReadinessWindow(self._clock, completed_at_us, deadline_us)

    def is_ready(self, e: AssuranceEvidence, *, evidence_signer: object | None = None,
                 credential_verifier: object | None = None,
                 qualifications: QualificationLookup | None = None,
                 drill_report: DrillReport | None = None, worm_store: WormStore | None = None,
                 worm_receipt: WormReceipt | None = None) -> bool:
        """Return false for a failed readiness check without discarding its check API."""
        try:
            self.check(e, evidence_signer=evidence_signer, credential_verifier=credential_verifier,
                       qualifications=qualifications, drill_report=drill_report,
                       worm_store=worm_store, worm_receipt=worm_receipt)
            return True
        except ProductionReadinessError:
            return False


class ReleaseReadiness(Protocol):
    """Load and verify installation evidence for one actual release verifier."""

    def __call__(self) -> ReadinessWindow: ...


class PackReadiness(Protocol):
    """Bind installation readiness to a pack and its final credential adapter."""

    def bind(self, pack_id: str, verification_classes: tuple[str, ...],
             credential_verifier: object) -> ReleaseReadiness: ...
