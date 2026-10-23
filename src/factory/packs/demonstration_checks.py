"""Host-owned evidence fixtures for the D5 offline pack demonstrations.

These bounded checks establish agreement with an independently supplied snapshot,
not the truth, clinical suitability or legal sufficiency of its source material.
They supply no production qualification, persistence or source-review authority.
The existing contextual verifier seam binds the trusted tenant and evaluation time.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome


@dataclass(frozen=True)
class EvidenceSnapshot:
    """One fictional case supplied by the host, never reconstructed from a draft."""

    tenant: str
    case_id: str
    revision: str
    title: str
    sources: tuple[tuple[str, str, str], ...]  # identifier, edition/as-of, exact source text
    statements: tuple[tuple[str, str], ...]  # source identifier, verbatim supported statement
    disclosures: tuple[str, ...]
    valid_from_us: int
    valid_until_us: int
    conflicts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.tenant, self.case_id, self.revision, self.title):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("evidence identity and title must be nonempty strings")
        for timestamp in (self.valid_from_us, self.valid_until_us):
            if isinstance(timestamp, bool) or not isinstance(timestamp, int):
                raise ValueError("evidence validity uses integer microseconds")
        if not 0 <= self.valid_from_us < self.valid_until_us:
            raise ValueError("evidence validity window is empty")
        if not isinstance(self.sources, tuple) or not self.sources:
            raise ValueError("at least one immutable source is required")
        source_map: dict[str, str] = {}
        for row in self.sources:
            if (not isinstance(row, tuple) or len(row) != 3
                    or any(not isinstance(v, str) or not v.strip() for v in row)):
                raise ValueError("sources require identifier, edition and exact text")
            identifier, _edition, text = row
            if identifier in source_map:
                raise ValueError("source identifiers must be unique")
            source_map[identifier] = text
        if not isinstance(self.statements, tuple) or not self.statements:
            raise ValueError("at least one source-grounded statement is required")
        for statement_row in self.statements:
            if (not isinstance(statement_row, tuple) or len(statement_row) != 2
                    or any(not isinstance(v, str) or not v.strip() for v in statement_row)):
                raise ValueError("statements require a source identifier and exact text")
            identifier, statement = statement_row
            if identifier not in source_map or statement not in source_map[identifier]:
                raise ValueError("statement is not supported by the identified source")
        for values in (self.disclosures, self.conflicts):
            if not isinstance(values, tuple) or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValueError("disclosures and conflicts must be immutable nonempty strings")
        if not self.disclosures:
            raise ValueError("the demonstration must disclose its limits")

    @property
    def digest(self) -> str:
        body = {name: getattr(self, name) for name in self.__dataclass_fields__}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def render(self) -> str:
        """A bounded projection: no model, new facts or inferred reconciliation."""
        lines = [self.title, "", "OFFLINE DEMONSTRATION — fictional evidence; not production-qualified.",
                 f"Case: {self.case_id} · revision {self.revision}", "", "Source-grounded statements"]
        lines.extend(f"- {statement} [{source}]" for source, statement in self.statements)
        lines.extend(["", "Sources and editions"])
        lines.extend(f"- {identifier}: {edition}" for identifier, edition, _text in self.sources)
        if self.conflicts:
            lines.extend(["", "Unresolved discrepancies — release refused"])
            lines.extend(f"- {conflict}" for conflict in self.conflicts)
        lines.extend(["", "Disclosures and limits", *self.disclosures])
        return "\n".join(lines) + "\n"

    def contract(self) -> dict[str, object]:
        return {"body": self.render(), "case_id": self.case_id, "evidence_revision": self.revision,
                "evidence_digest": self.digest}


class SnapshotVerifier:
    """An explicitly injected host verifier, not an installed pack executable.

    A caller's source lists, conflict flags and tenant fields confer no authority.
    Passing is only an offline evidence check; the existing gate still requires
    credentials, approvals, policy, activation and any production qualifications.
    """

    def __init__(self, snapshots: tuple[EvidenceSnapshot, ...]) -> None:
        self._snapshots: dict[tuple[str, str], EvidenceSnapshot] = {}
        for snapshot in snapshots:
            key = (snapshot.tenant, snapshot.case_id)
            if key in self._snapshots:
                raise ValueError("a case has one current host-supplied revision")
            self._snapshots[key] = snapshot

    def __call__(self, draft: str, contract: Mapping[str, object]) -> tuple[Outcome, tuple[str, ...]]:
        return Outcome.FAIL, ("TRUSTED_CONTEXT_REQUIRED",)

    def verify_context(self, draft: str, contract: Mapping[str, object],
                       context: EmissionContext | None) -> tuple[Outcome, tuple[str, ...]]:
        if context is None:
            return self(draft, contract)
        case_id = contract.get("case_id")
        if not isinstance(case_id, str):
            return Outcome.FAIL, ("CASE_ID_REQUIRED",)
        snapshot = self._snapshots.get((context.tenant, case_id))
        if snapshot is None:
            return Outcome.FAIL, ("HOST_EVIDENCE_UNAVAILABLE",)
        if (isinstance(context.now_us, bool) or not isinstance(context.now_us, int)
                or not snapshot.valid_from_us <= context.now_us < snapshot.valid_until_us):
            return Outcome.FAIL, ("SOURCE_OUTSIDE_REVIEW_WINDOW",)
        if (contract.get("evidence_revision") != snapshot.revision
                or contract.get("evidence_digest") != snapshot.digest):
            return Outcome.FAIL, ("EVIDENCE_REVISION_MISMATCH",)
        if snapshot.conflicts:
            return Outcome.FAIL, ("UNRESOLVED_EVIDENCE_CONFLICT",)
        if draft != snapshot.render() or contract.get("body") != draft:
            return Outcome.FAIL, ("OUTPUT_NOT_SUPPORTED_BY_HOST_EVIDENCE",)
        return Outcome.PASS, ()
