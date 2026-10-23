"""Retained-store clinical verifiers: a degraded store yields INDETERMINATE (X-12).

The inherited ``factory.health_ui.clinical_checks`` rules are used unchanged. The
original JSON store reports degradation through ``degraded``; the retained
PostgreSQL store (``RetainedClinicalStore``) instead raises ``StoreDegraded`` per
operation. This wrapper keeps every inherited outcome and reason code, and maps
only that typed per-operation failure to the frozen outcome: INDETERMINATE with
``STORE_DEGRADED``, never PASS and never an untyped exception at the gate.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from factory.health_ui.clinical_checks import ClinicalCheck, OwnerOf, VerifierResult, clinical_checks
from factory.health_ui.store import StoreDegraded
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome


class RetainedClinicalCheck:
    """One inherited clinical verifier over the retained store, with typed degraded-store handling."""

    def __init__(self, check: ClinicalCheck) -> None:
        if not isinstance(check, ClinicalCheck):
            raise TypeError("retained clinical check wraps an inherited clinical verifier")
        self._check = check

    def __call__(self, draft: str, contract: Mapping[str, Any]) -> VerifierResult:
        return self._check(draft, contract)

    def verify_context(self, draft: str, contract: Mapping[str, Any], context: EmissionContext) -> VerifierResult:
        try:
            return self._check.verify_context(draft, contract, context)
        except StoreDegraded:
            return Outcome.INDETERMINATE, ("STORE_DEGRADED",)


def retained_clinical_checks(store: Any, owner_of: OwnerOf) -> dict[str, RetainedClinicalCheck]:
    """The four inherited verifiers, by check id, each with retained-store degradation handling."""
    return {check_id: RetainedClinicalCheck(check) for check_id, check in clinical_checks(store, owner_of).items()}


__all__ = ["RetainedClinicalCheck", "retained_clinical_checks"]
