"""Bind host-pinned qualification reports into the reference target permit."""

from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
import json

from assurance_reference.engine import ReferenceEngine
from regulated_core.clock import ClockReading, read_clock
from regulated_core.canonical import canonical_bytes
from regulated_core.engine import TargetAuthorization
from regulated_core.qualification import QualificationError, QualificationReport, verify_report
from regulated_core.signing import TrustDirectory
from regulated_core.target import SignedTargetPermit


def _fraction(value: str) -> Decimal:
    try:
        number = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise QualificationError("qualification threshold or metric is invalid") from exc
    if not number.is_finite() or not 0 <= number <= 1:
        raise QualificationError("qualification threshold or metric is outside [0,1]")
    return number


@dataclass(frozen=True)
class RequiredQualification:
    verification_class: str
    verifier_version: str
    dataset_digest: str
    jurisdiction: str
    language: str
    document_type: str
    min_precision: str
    min_recall: str

    def __post_init__(self):
        for value in (
            self.verification_class, self.verifier_version, self.jurisdiction,
            self.language, self.document_type,
        ):
            if not isinstance(value, str) or not value or value != value.strip():
                raise QualificationError("host qualification requirements must be explicit")
        if len(self.dataset_digest) != 64 or any(
            char not in "0123456789abcdef" for char in self.dataset_digest
        ):
            raise QualificationError("host must pin a SHA-256 dataset digest")
        _fraction(self.min_precision)
        _fraction(self.min_recall)


class QualificationSet:
    """Static host configuration, not a mutable or governed qualification registry.

    The host pins the reports' clock interpretation and applicability. This checks
    reports, not the identity of running checker code or a deployment's custody.
    """

    def __init__(
        self, *, trust: TrustDirectory, authority: str, clock_domain: str,
        required: tuple[RequiredQualification, ...], reports: tuple[QualificationReport, ...],
    ):
        if not authority or not clock_domain or not required:
            raise QualificationError("qualification authority, clock and requirements are required")
        if len({item.verification_class for item in required}) != len(required):
            raise QualificationError("duplicate required verification class")
        if len({report.verification_class for report in reports}) != len(reports):
            raise QualificationError("ambiguous report set")
        self._trust, self._authority, self._domain = trust, authority, clock_domain
        self._required, self._reports = tuple(required), tuple(reports)

    def check(self, reading: ClockReading) -> tuple[tuple[str, ...], int]:
        if reading.domain != self._domain:
            raise QualificationError("qualification clock interpretation differs")
        reports = {report.verification_class: report for report in self._reports}
        digests, deadlines = [], []
        for requirement in self._required:
            report = reports.get(requirement.verification_class)
            if report is None:
                raise QualificationError("required qualification report is missing")
            if not verify_report(self._trust, report, authority=self._authority):
                raise QualificationError("qualification report is untrusted")
            if report.qualified_by != self._authority:
                raise QualificationError("qualification authority label differs")
            if report.verifier_version != requirement.verifier_version:
                raise QualificationError("qualified verifier version differs")
            if report.dataset_digest != requirement.dataset_digest:
                raise QualificationError("qualified dataset differs")
            if (
                type(report.qualified_at_us) is not int or type(report.expires_at_us) is not int
                or not 0 <= report.qualified_at_us <= reading.now_us < report.expires_at_us
            ):
                raise QualificationError("qualification report is not current")
            metrics = report.characteristics
            if (
                requirement.jurisdiction not in metrics.jurisdictions
                or requirement.language not in metrics.languages
                or requirement.document_type not in metrics.document_types
            ):
                raise QualificationError("qualification applicability differs")
            if (
                _fraction(metrics.precision) < _fraction(requirement.min_precision)
                or _fraction(metrics.recall) < _fraction(requirement.min_recall)
            ):
                raise QualificationError("qualification metrics do not meet host thresholds")
            digests.append(report.digest())
            deadlines.append(report.expires_at_us)
        return tuple(sorted(digests)), min(deadlines)

    def retained_lineage(self, signed: SignedTargetPermit, *, permit_authority: str) -> dict:
        """Resolve an existing signed permit's exact report references for offline audit.

        The caller supplies the expected permit authority from host configuration,
        never from the permit itself. Verification is at the signed issuance instant,
        not the current time. This reads immutable reports, grants no authority and
        makes no claim about an effect, approval, revocation or current readiness.
        """
        permit = signed.permit
        if (not permit_authority or signed.signature.key_id != permit_authority
                or not self._trust.verify(permit.signed_body(), signed.signature)):
            raise QualificationError("retained permit signature is untrusted")
        if not permit.clock_domain:
            raise QualificationError("retained lineage requires a clock-qualified permit")
        digests, deadline = self.check(ClockReading(permit.clock_domain, permit.issued_at_us))
        if tuple(permit.qualification_digests) != digests:
            raise QualificationError("retained permit qualification references differ from host reports")
        if permit.expires_at_us > deadline:
            raise QualificationError("retained permit outlives its qualification")
        reports = {report.digest(): report for report in self._reports}
        return json.loads(canonical_bytes({
            "schema": "reference/retained-qualification-lineage/v1",
            "verification_basis": "host-pinned trust and requirements at signed permit issuance",
            "clock_domain": permit.clock_domain,
            "checked_at_issuance_us": permit.issued_at_us,
            "decision_record_id": permit.decision_record_id,
            "decision_record_hash": permit.decision_record_hash,
            "signed_target_permit": signed,
            "qualification_authority": self._authority,
            "required": self._required,
            "reports": [{"report_digest": digest, "report": reports[digest],
                         "dataset_reference": {"id": reports[digest].dataset_id,
                             "version": reports[digest].dataset_version,
                             "digest": reports[digest].dataset_digest}}
                        for digest in digests],
            "limits": ["Historical permit/report binding only; no new execution authority.",
                       "Decision-chain membership and approval-time credential lineage are separate checks.",
                       "Dataset bytes and running verifier identity are not established by report references.",
                       "No effect, current readiness, revocation, physical-expiry or deployment-custody verdict."],
        }))


class QualifiedReferenceEngine(ReferenceEngine):
    """Qualify this entry point before normal policy, approval and permit processing.

    Existing entry points inherited from the core are not qualified by this class.
    Early withdrawal and governed report replacement require further composition.
    """

    def __init__(self, *, qualifications: QualificationSet, **parameters):
        if not isinstance(qualifications, QualificationSet):
            raise TypeError("host qualification requirements are mandatory")
        self._qualifications = qualifications
        super().__init__(**parameters)

    def authorize_for_target(self, *, ctx, **parameters):
        reading = read_clock(self.targets.clock)
        current = replace(ctx, now_us=reading.now_us)
        try:
            # The original pack gate passes () when no registry supplied refs.
            # This conveys no authority; only the host-pinned reports below do.
            if type(parameters.get("qualification_digests")) is tuple and not parameters["qualification_digests"]:
                parameters.pop("qualification_digests")
            if "qualification_digests" in parameters:
                raise QualificationError("requests cannot supply qualification references")
            digests, deadline = self._qualifications.check(reading)
        except QualificationError as refused:
            envelope = self.record_refusal(
                assertion=parameters["assertion"], action=parameters["action"], ctx=current,
                code="QUALIFICATION_REFUSED", reason=str(refused),
            )
            return TargetAuthorization(
                False, str(refused), "deny", envelope, None, parameters["assertion"],
                parameters["action"], current, envelope.record.policy,
            )
        existing_deadline = parameters.get("not_after_us", 0)
        if type(existing_deadline) is not int or existing_deadline < 0:
            raise ValueError("not_after_us must be a non-negative integer")
        parameters["not_after_us"] = min(existing_deadline, deadline) if existing_deadline else deadline
        return super().authorize_for_target(
            ctx=current, qualification_digests=digests, **parameters,
        )
