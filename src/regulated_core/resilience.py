"""Operational assurance — resilience drills that prove the GOVERNANCE GUARANTEES survive failure.

Infrastructure tests ask "does the database come back?" This asks a different question: while things
are actively going wrong — KMS down, identity provider down, licence revoked mid-approval, WORM
unreachable, a permit replayed, an approval presented after expiry — do the assurance properties
remain true? Every drill names a failure mode (the trigger) and the guarantee that must survive it;
executing the drill injects the failure against real components and observes the outcome.

Drill results are collected into an IMMUTABLE, SIGNED, content-addressed, EXPIRING DrillReport — the
same discipline as QualificationReport and PolicyDocument. Expiry is the point: drills prove the
posture at a moment; a regulator (and the production gate) should refuse a stale one. The production
gate's `resilience_drills` control stops being a boolean and becomes "a trusted, current drill report
exists in which every required drill passed" — the same move made for hsm_kms_custody,
authoritative_identity, and validated_verifiers.

Pure core (no factory dependency); standalone import. The drill CATALOGUE lives here (what must be
proven); the drill IMPLEMENTATIONS live with the composition that runs them (tests/dev inject failures
into local mocks via their availability toggles; production runs the same drills against staging
replicas of real providers).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .canonical import digest_hex
from .signing import Signature, Signer, TrustDirectory


class DrillError(Exception):
    """A drill report could not be produced, is invalid, or is untrusted — fail closed."""


@dataclass(frozen=True, slots=True)
class FailureDrill:
    """One named failure mode and the assurance guarantee that must survive it."""
    drill_id: str
    failure_mode: str        # the trigger ("KMS backend unreachable during evidence signing")
    guarantee: str           # what must remain true ("no unsigned evidence exists; the action fails closed")


@dataclass(frozen=True, slots=True)
class DrillOutcome:
    drill_id: str
    passed: bool
    observed: str            # what actually happened, in one line — this is audit-facing


@dataclass(frozen=True, slots=True)
class DrillReport:
    """An immutable, signed attestation that a suite of failure drills was executed at a time, with
    outcomes. Identified downstream by `.digest()`; a re-run supersedes (new report), never edits."""
    scope: str
    executed_at_us: int
    expires_at_us: int       # drills prove a moment; stale reports must be refused
    outcomes: tuple[DrillOutcome, ...]
    executed_by: str         # the drill authority that signed this
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/drill-report/v1", "scope": self.scope,
                "executed_at_us": self.executed_at_us, "expires_at_us": self.expires_at_us,
                "outcomes": [{"drill_id": o.drill_id, "passed": o.passed, "observed": o.observed}
                             for o in self.outcomes],
                "executed_by": self.executed_by}

    def digest(self) -> str:
        return digest_hex({**self.signed_body(), "sig": self.signature.value})

    def passed_ids(self) -> frozenset[str]:
        return frozenset(o.drill_id for o in self.outcomes if o.passed)

    @property
    def all_passed(self) -> bool:
        return bool(self.outcomes) and all(o.passed for o in self.outcomes)


def run_drills(signer: Signer, *, scope: str,
               drills: Sequence[tuple[FailureDrill, Callable[[], str]]],
               executed_at_us: int, valid_for_us: int) -> DrillReport:
    """Execute each drill and issue a SIGNED report. A drill callable injects its failure and returns a
    one-line observation when the guarantee held; it raises AssertionError when the guarantee was
    VIOLATED (drills read like tests). A violated guarantee is recorded honestly as a failed outcome —
    the report never hides a failure; the production gate refuses on it."""
    outcomes = []
    for drill, execute in drills:
        try:
            observed = execute()
            outcomes.append(DrillOutcome(drill.drill_id, True, observed))
        except AssertionError as violation:
            outcomes.append(DrillOutcome(drill.drill_id, False, f"GUARANTEE VIOLATED: {violation}"))
    body = {"schema": "regulated/drill-report/v1", "scope": scope, "executed_at_us": executed_at_us,
            "expires_at_us": executed_at_us + valid_for_us,
            "outcomes": [{"drill_id": o.drill_id, "passed": o.passed, "observed": o.observed}
                         for o in outcomes],
            "executed_by": signer.key_id}
    return DrillReport(scope=scope, executed_at_us=executed_at_us,
                       expires_at_us=executed_at_us + valid_for_us, outcomes=tuple(outcomes),
                       executed_by=signer.key_id, signature=signer.sign(body))


def verify_drill_report(trust: TrustDirectory, report: DrillReport, *, authority: str | None = None) -> bool:
    """Trust-anchored check: signed by a known identity (optionally the expected drill authority)."""
    if authority is not None and report.signature.key_id != authority:
        return False
    return trust.verify(report.signed_body(), report.signature)


# --- the catalogue: what a regulated scope MUST prove it drilled --------------------------------
# Implementations live with the composition; these are the failure modes and guarantees themselves.

REGULATED_DRILLS: tuple[FailureDrill, ...] = (
    FailureDrill("kms-outage",
                 "KMS/HSM backend unreachable during evidence signing",
                 "fail closed: the action raises; NO unsigned evidence is ever recorded"),
    FailureDrill("identity-provider-outage",
                 "identity provider / licence registry unreachable during approval",
                 "fail closed: no credential receipt, no grant, no approval certificate"),
    FailureDrill("licence-revoked-mid-approval",
                 "approver's licence suspended between draft and approval",
                 "approval-time re-verification denies; the stale draft-time status never authorizes"),
    FailureDrill("qualification-expired",
                 "a required verifier's qualification expires during operation",
                 "the production gate refuses validated_verifiers; the expiry is visible, not silent"),
    FailureDrill("worm-outage",
                 "WORM store unreachable at release time",
                 "fail closed: release aborts BEFORE any byte is emitted; no retention receipt, no output"),
    FailureDrill("permit-replay",
                 "a consumed single-use emission permit is presented again",
                 "the replay is denied and the denial is recorded as evidence"),
    FailureDrill("policy-superseded",
                 "the policy document is superseded between approval and release",
                 "the divergence is detectable: the bound digest no longer matches the ledger's current"),
    FailureDrill("forged-evidence-signer",
                 "an attacker signs evidence with their own key under a trusted identity's name",
                 "trust is anchored by identity name in the directory; the forged envelope fails verification"),
    FailureDrill("evidence-chain-reordered",
                 "evidence log entries are reordered or dropped after the fact",
                 "the hash chain breaks visibly; verify_chain returns False"),
    FailureDrill("approval-clock-skew",
                 "an approval is presented after its requirement TTL (or from a skewed clock)",
                 "the approval binds to one decision instant; a re-timed decision is denied"),
)


__all__ = [
    "DrillError", "FailureDrill", "DrillOutcome", "DrillReport", "run_drills", "verify_drill_report",
    "REGULATED_DRILLS",
]
