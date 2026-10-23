"""Unchanged authority helpers extracted from the frozen demonstration surface."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any, Protocol
from factory.projectos.regulated import EmissionContext
from factory.packs.demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from factory.packs.demonstrations import USES

class EvidenceUnavailable(ValueError):
    """A current host-reviewed case is unavailable; draft fields are never a fallback."""

class HostEvidence(Protocol):
    def current(self, tenant: str, use: str, case_id: str) -> EvidenceSnapshot: ...

def current_snapshot(source: HostEvidence, tenant: str, use: str, case_id: str) -> EvidenceSnapshot:
    if not tenant or use not in USES or not isinstance(case_id, str) or not case_id.strip():
        raise EvidenceUnavailable("A tenant and an existing reviewed case are required")
    try:
        snapshot = source.current(tenant, use, case_id)
    except Exception as exc:
        raise EvidenceUnavailable("The host-reviewed case is unavailable; contact its evidence custodian") from exc
    if not isinstance(snapshot, EvidenceSnapshot) or (snapshot.tenant, snapshot.case_id) != (tenant, case_id):
        raise EvidenceUnavailable("The host evidence does not match this tenant and case")
    return snapshot

class CurrentSnapshotVerifier:
    """Reread host custody on every check; never retain an earlier accepted revision."""
    def __init__(self, source: HostEvidence, use: str) -> None:
        if use not in USES:
            raise ValueError("Unknown D5 domain")
        self.source, self.use = source, use

    def __call__(self, draft: str, contract: Mapping[str, object]) -> Any:
        return SnapshotVerifier(()).__call__(draft, contract)

    def verify_context(self, draft: str, contract: Mapping[str, object], context: EmissionContext | None) -> Any:
        if context is None:
            return self(draft, contract)
        try:
            case_id = contract.get("case_id")
            if not isinstance(case_id, str):
                raise EvidenceUnavailable("Existing case required")
            snapshot = current_snapshot(self.source, context.tenant, self.use, case_id)
        except EvidenceUnavailable:
            # The existing verifier supplies the fail-closed unavailable verdict.
            return SnapshotVerifier(()).verify_context(draft, contract, context)
        return SnapshotVerifier((snapshot,)).verify_context(draft, contract, context)
