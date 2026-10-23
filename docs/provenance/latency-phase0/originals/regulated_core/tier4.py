"""Tier 4 controls: two independent humans, different reporting lines, monitor clearance and a cooling-off period.

Paper A section 4.2, the consequence tiers; docs/ARCHITECTURE-OF-RECORD/08 row A03. Tier 4 covers the actions whose
misuse is hardest to undo: access to weights, training, self-modification, disabling a monitor, and changing policy,
checkers or approvers. The engine applies these controls to any action whose signed generation capability carries
risk tier 4, after the ordinary approval has been validated, so they only ever add to it:

* **two independent humans**: the approval certificate names at least two distinct approvers;
* **different reporting lines**: the host's organisational directory places them in at least two different lines, and
  an approver the directory cannot place refuses the action rather than counting as independent;
* **monitor clearance**: a monitor authority, whose key the trust directory registers, has signed a clearance of exactly
  this decision record after it was made;
* **cooling-off**: the action cannot proceed until the configured period has passed since the decision.

No historical signed record changes shape: the clearance is its own signed record, looked up by the decision it clears.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .approval import ApprovalCertificate
from .evidence import SignedDecisionEnvelope
from .signing import Signature, Signer, TrustDirectory

CLEARANCE_SCHEMA = "regulated/monitor-clearance/v1"
TIER3 = 3   # one verified human (the engine enforces it by tier, step 7)
TIER4 = 4


class ReportingLineDirectory(Protocol):
    def reporting_line(self, tenant_id: str, subject_id: str) -> str | None:
        """The approver's reporting line from the host's authoritative directory, or None when unknown."""
        ...


@dataclass(frozen=True, slots=True)
class MonitorClearance:
    tenant_id: str
    decision_record_id: str
    decision_record_hash: str
    monitor_id: str
    cleared_at_us: int
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": CLEARANCE_SCHEMA, "tenant_id": self.tenant_id,
                "decision_record_id": self.decision_record_id, "decision_record_hash": self.decision_record_hash,
                "monitor_id": self.monitor_id, "cleared_at_us": self.cleared_at_us}


def issue_clearance(monitor: Signer, envelope: SignedDecisionEnvelope, *, cleared_at_us: int) -> MonitorClearance:
    """A monitor's signed clearance of exactly this decision record."""
    body = MonitorClearance(envelope.record.tenant_id, envelope.record.record_id, envelope.record_hash,
                            monitor.key_id, cleared_at_us, Signature("", ""))
    return MonitorClearance(body.tenant_id, body.decision_record_id, body.decision_record_hash, body.monitor_id,
                            body.cleared_at_us, monitor.sign(body.signed_body()))


class ClearanceStore(Protocol):
    def put(self, clearance: MonitorClearance) -> None: ...

    def get(self, tenant_id: str, decision_record_id: str) -> MonitorClearance | None: ...


class InMemoryClearanceStore:
    """One process's clearances. Correct only while one process decides tier-4 actions."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], MonitorClearance] = {}
        self._lock = threading.Lock()

    def put(self, clearance: MonitorClearance) -> None:
        with self._lock:
            self._items.setdefault((clearance.tenant_id, clearance.decision_record_id), clearance)

    def get(self, tenant_id: str, decision_record_id: str) -> MonitorClearance | None:
        with self._lock:
            return self._items.get((tenant_id, decision_record_id))


class Tier4Controls:
    """The additional tier-4 checks, over an already validated approval of the decision."""

    def __init__(self, *, directory: ReportingLineDirectory, clearances: ClearanceStore, trust: TrustDirectory,
                 monitor_key_ids: frozenset[str] | Callable[[], frozenset[str]], cooling_off_us: int,
                 locked: Callable[[], str | None] | None = None) -> None:
        """`monitor_key_ids` may be a fixed set, checked here, or a callable read on EVERY check, so a governed change
        of the monitor takes effect at once and a removed monitor's clearance stops counting (source review 3286). `locked`,
        when given, is read first on every check; a stated reason refuses every tier-4 action."""
        if not callable(monitor_key_ids) and (not monitor_key_ids
                                              or not all(trust.is_known(k) for k in monitor_key_ids)):
            raise ValueError("tier-4 monitor clearance needs registered monitor keys")
        if type(cooling_off_us) is not int or cooling_off_us < 1:
            raise ValueError("tier-4 needs an explicit positive cooling-off period")
        self._directory, self._clearances, self._trust = directory, clearances, trust
        self._monitor_source, self._cooling_off, self._locked = monitor_key_ids, cooling_off_us, locked

    @property
    def _monitors(self) -> frozenset[str]:
        keys = self._monitor_source() if callable(self._monitor_source) else self._monitor_source
        # A live source is judged like a fixed one, every time: only registered keys count as monitors.
        return frozenset(k for k in keys if self._trust.is_known(k))

    def problem(self, approved: SignedDecisionEnvelope, cert: ApprovalCertificate, *,
                now_us: int) -> tuple[str, str] | None:
        """(code, reason) for the first control not met, or None when all are."""
        reason = self._locked() if self._locked is not None else None
        if reason:
            return "TIER4_GOVERNANCE_LOCKED", reason
        record = approved.record
        approvers = set(cert.approver_ids)
        if len(approvers) < 2:
            return "TIER4_DUAL_CONTROL", "tier 4 needs two independent human approvers"
        lines = {self._directory.reporting_line(record.tenant_id, a) for a in approvers}
        if None in lines:
            return "TIER4_REPORTING_LINE_UNKNOWN", "an approver's reporting line cannot be established"
        if len(lines) < 2:
            return "TIER4_SAME_REPORTING_LINE", "tier 4 approvers must come from different reporting lines"
        if now_us < self.cooling_off_ends_at_us(approved):
            return "TIER4_COOLING_OFF", "the tier-4 cooling-off period has not passed"
        return self.clearance_problem(approved, now_us=now_us)

    def cooling_off_ends_at_us(self, approved: SignedDecisionEnvelope) -> int:
        """When the cooling-off period after this decision ends."""
        return approved.record.decided_at_us + self._cooling_off

    def clearance_problem(self, approved: SignedDecisionEnvelope, *, now_us: int) -> tuple[str, str] | None:
        """The monitor-clearance control alone: a registered monitor's genuine signature over exactly this decision,
        given after it was made. A stored clearance that fails any of these is no clearance, including for display."""
        record = approved.record
        monitors = self._monitors
        clearance = self._clearances.get(record.tenant_id, record.record_id)
        if (not monitors or clearance is None or clearance.signature.key_id not in monitors
                or clearance.monitor_id != clearance.signature.key_id
                or not self._trust.verify(clearance.signed_body(), clearance.signature)
                or clearance.decision_record_hash != approved.record_hash
                or not record.decided_at_us <= clearance.cleared_at_us <= now_us):
            return "TIER4_MONITOR_NOT_CLEARED", "no valid monitor clearance of this exact decision"
        return None


__all__ = ["CLEARANCE_SCHEMA", "TIER3", "ClearanceStore", "InMemoryClearanceStore", "MonitorClearance",
           "ReportingLineDirectory", "TIER4", "Tier4Controls", "issue_clearance"]
