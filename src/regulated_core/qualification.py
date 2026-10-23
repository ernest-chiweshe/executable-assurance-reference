"""Verifier qualification — the engineering-trust graph, orthogonal to the runtime decision graph.

The decision graph (assertion -> verification -> approval -> permit -> evidence) answers one question:
"was THIS decision allowed?" This module answers a different question on a different axis: "should this
verifier be trusted at all?" A verifier is QUALIFIED by measuring its operating characteristics
(precision/recall) against a NAMED, VERSIONED, content-addressed labeled dataset, producing an
immutable SIGNED QualificationReport. A decision then references that report BY DIGEST — a cryptographic
commitment to the exact qualification in force, the way a TLS certificate references its CA — rather than
copying the metrics into every result. (For deterministic verifiers a per-call `confidence` is a category
error; the operating characteristics belong to the verifier, not to the decision.)

The two graphs meet at exactly ONE seam: the evidence assembler binds the current qualification digest
into the (already hash-chained, recorder-signed) evidence pack, and the production gate refuses release
unless every required verifier is CURRENTLY qualified. Runtime verification stays pure — `run_verifiers`
never reads a dataset or computes a metric.

Pure core (no factory dependency); `import regulated_core.qualification` stays standalone. Local
deterministic datasets are for tests/dev; a real validated dataset + an accredited qualification lab drop
in behind the same shapes with no core change. Reports are IMMUTABLE and versioned forever: a new report
SUPERSEDES the previous one, nothing is edited (same philosophy as evidence/WORM), so reports compose
directly into the WORM store when durable retention is required.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .canonical import digest_hex
from .governance_guard import GovernanceGuard
from .signing import Signature, Signer, TrustDirectory


class QualificationError(Exception):
    """A qualification could not be produced, is invalid, or is untrusted — fail closed."""


@dataclass(frozen=True, slots=True)
class LabeledCase:
    """One ground-truth-labelled example. `expected_positive` = the verifier SHOULD flag this text
    (the unsafe condition it detects is actually present)."""
    text: str
    expected_positive: bool


@dataclass(frozen=True, slots=True)
class QualificationDataset:
    """A named, versioned, content-addressed labelled dataset. Tampering any case changes `.digest()`,
    so a report's bound dataset_digest detects a swapped-out validation set."""
    dataset_id: str
    version: str
    description: str
    cases: tuple[LabeledCase, ...]

    def digest(self) -> str:
        return digest_hex({"dataset_id": self.dataset_id, "version": self.version,
                           "cases": [{"text": c.text, "expected_positive": c.expected_positive} for c in self.cases]})

    @property
    def size(self) -> int:
        return len(self.cases)

    @property
    def positives(self) -> int:
        return sum(1 for c in self.cases if c.expected_positive)


@dataclass(frozen=True, slots=True)
class OperatingCharacteristics:
    """Measured behaviour under STATED conditions. Metrics are fixed decimal strings (never floats in a
    signed body); applicability names the conditions the qualification is valid for."""
    precision: str
    recall: str
    f1: str
    tp: int
    fp: int
    fn: int
    tn: int
    jurisdictions: tuple[str, ...]
    languages: tuple[str, ...]
    document_types: tuple[str, ...]

    def as_body(self) -> dict[str, Any]:
        return {"precision": self.precision, "recall": self.recall, "f1": self.f1,
                "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
                "jurisdictions": list(self.jurisdictions), "languages": list(self.languages),
                "document_types": list(self.document_types)}


@dataclass(frozen=True, slots=True)
class QualificationReport:
    """An immutable, signed attestation of a verifier's operating characteristics against one dataset.
    Identified downstream by `.digest()`; superseded (never edited) by a later report."""
    verification_class: str          # the verifier this qualifies (e.g. "pe:phi-boundary")
    verifier_version: str
    dataset_id: str
    dataset_version: str
    dataset_digest: str
    characteristics: OperatingCharacteristics
    qualified_at_us: int
    expires_at_us: int
    qualified_by: str                # the qualification-authority identity that signed this
    limitations: tuple[str, ...]
    supersedes: str                  # digest of the prior report version, or "" for the first
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/qualification-report/v1", "verification_class": self.verification_class,
                "verifier_version": self.verifier_version, "dataset_id": self.dataset_id,
                "dataset_version": self.dataset_version, "dataset_digest": self.dataset_digest,
                "characteristics": self.characteristics.as_body(), "qualified_at_us": self.qualified_at_us,
                "expires_at_us": self.expires_at_us, "qualified_by": self.qualified_by,
                "limitations": list(self.limitations), "supersedes": self.supersedes}

    def digest(self) -> str:
        return digest_hex({**self.signed_body(), "sig": self.signature.value})

    def summary(self) -> dict[str, Any]:
        """The small denormalized view bound into an evidence pack: digest is authoritative, the rest is
        auditor convenience so one pack is readable offline without resolving the chain."""
        c = self.characteristics
        return {"report_digest": self.digest(), "verification_class": self.verification_class,
                "dataset": f"{self.dataset_id}@{self.dataset_version}", "dataset_digest": self.dataset_digest,
                "precision": c.precision, "recall": c.recall, "expires_at_us": self.expires_at_us}


def _ratio(num: int, den: int) -> str:
    """Integer-rounded 4dp decimal string (no float in the signed surface, deterministic on every host)."""
    if den == 0:
        return "0.0000"
    scaled = (num * 10000 + den // 2) // den
    return f"{scaled // 10000}.{scaled % 10000:04d}"


def qualify(signer: Signer, *, verification_class: str, verifier_version: str, dataset: QualificationDataset,
            predicate: Callable[[str], bool], qualified_at_us: int, valid_for_us: int,
            jurisdictions: tuple[str, ...], languages: tuple[str, ...], document_types: tuple[str, ...],
            limitations: tuple[str, ...] = (), supersedes: str = "") -> QualificationReport:
    """Measure `predicate` (the verifier under test) over `dataset`, compute precision/recall, and issue a
    SIGNED, immutable QualificationReport. A valid qualification dataset must contain at least one positive
    and one negative case, else recall/precision are undefined."""
    if dataset.positives == 0 or dataset.positives == dataset.size:
        raise QualificationError("qualification dataset must contain both positive and negative cases")
    tp = fp = fn = tn = 0
    for case in dataset.cases:
        detected = bool(predicate(case.text))
        if case.expected_positive and detected:
            tp += 1
        elif case.expected_positive and not detected:
            fn += 1
        elif not case.expected_positive and detected:
            fp += 1
        else:
            tn += 1
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)
    chars = OperatingCharacteristics(precision, recall, f1, tp, fp, fn, tn, jurisdictions, languages, document_types)
    body = {"schema": "regulated/qualification-report/v1", "verification_class": verification_class,
            "verifier_version": verifier_version, "dataset_id": dataset.dataset_id,
            "dataset_version": dataset.version, "dataset_digest": dataset.digest(),
            "characteristics": chars.as_body(), "qualified_at_us": qualified_at_us,
            "expires_at_us": qualified_at_us + valid_for_us, "qualified_by": signer.key_id,
            "limitations": list(limitations), "supersedes": supersedes}
    return QualificationReport(
        verification_class=verification_class, verifier_version=verifier_version, dataset_id=dataset.dataset_id,
        dataset_version=dataset.version, dataset_digest=dataset.digest(), characteristics=chars,
        qualified_at_us=qualified_at_us, expires_at_us=qualified_at_us + valid_for_us, qualified_by=signer.key_id,
        limitations=tuple(limitations), supersedes=supersedes, signature=signer.sign(body))


def verify_report(trust: TrustDirectory, report: QualificationReport, *, authority: str | None = None) -> bool:
    """Trust-anchored check: signed by a known identity (optionally the expected qualification authority)."""
    if authority is not None and report.signature.key_id != authority:
        return False
    return trust.verify(report.signed_body(), report.signature)


class QualificationLookup(Protocol):
    def current(self, verification_class: str, now_us: int) -> QualificationReport | None: ...


class QualificationRegistry:
    """Append-only, trust-anchored history of qualification reports per verifier. Reports are immutable;
    a new report SUPERSEDES rather than overwrites. `current()` returns the latest non-expired TRUSTED
    report for a verifier — the single lookup the evidence assembler and production gate rely on."""

    def __init__(self, trust: TrustDirectory | None = None, *, authority: str | None = None,
                 guard: GovernanceGuard | None = None) -> None:
        self._trust = trust                # if set, reports are trust-verified at the boundary (fail closed)
        self._authority = authority
        self._guard = guard                # if set, only the governance target may add a report (A09)
        self._history: dict[str, list[QualificationReport]] = {}
        self._receipts: dict[tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    def add(self, report: QualificationReport) -> None:
        if self._guard is not None:
            self._guard.require("checker-qualification", report.verification_class)
        if self._trust is not None and not verify_report(self._trust, report, authority=self._authority):
            raise QualificationError("qualification report signature invalid or untrusted")
        hist = self._history.setdefault(report.verification_class, [])
        if any(r.digest() == report.digest() for r in hist):
            raise QualificationError("duplicate report; reports are immutable — supersede with a new version")
        hist.append(report)

    def add_governed(self, report: QualificationReport, governed: Any) -> None:
        """The governance target's entry (A09): under this registry's lock, compare the approved prior history, run the
        permit's final check, then add the report and its exact receiving receipt together."""
        with self._lock:
            current = digest_hex([r.digest() for r in self.history(report.verification_class)])
            if current != governed.approved_prior:
                raise QualificationError("the qualification history changed since the change was approved")
            governed.final_check()
            self.add(report)
            self._receipts[(governed.tenant_id, governed.operation, governed.nonce)] = governed.change_digest

    def governance_receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Any:
        """COMMITTED only for the exact receipt; written under the lock with the report, so an absent one is final."""
        from .target import Outcome
        with self._lock:
            held = self._receipts.get((tenant_id, operation, nonce))
        return Outcome.COMMITTED if held == change_digest else Outcome.NOT_COMMITTED

    def history(self, verification_class: str) -> tuple[QualificationReport, ...]:
        return tuple(self._history.get(verification_class, ()))

    def current(self, verification_class: str, now_us: int) -> QualificationReport | None:
        live = [r for r in self._history.get(verification_class, ()) if now_us < r.expires_at_us]
        return max(live, key=lambda r: r.qualified_at_us) if live else None

    def summaries(
        self, classes: tuple[str, ...], now_us: int
    ) -> dict[str, dict[str, Any] | None]:
        """The per-verifier qualification view for an evidence pack: current report summary, or None if a
        required verifier is not currently qualified (which the production gate refuses)."""
        return {c: (r.summary() if (r := self.current(c, now_us)) is not None else None) for c in classes}


__all__ = [
    "QualificationError", "LabeledCase", "QualificationDataset", "OperatingCharacteristics",
    "QualificationReport", "qualify", "verify_report", "QualificationLookup", "QualificationRegistry",
]
