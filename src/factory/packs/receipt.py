"""The release receipt: what every governed release carries, so 'pinned by digest' is true of the authority.

A receipt names the pack (reference and digest), the ACTIVATION that authorized it, the rulebook in
force (reference and effective digest), the schema digest, the sources-lock digest, the verifier
profile digest, every check that ran with its version and outcome, the approvers, the human feedback
on the card, the artifact digest, the action id and the builder that produced the pack. That is
research gate 9 ("pack and policy digests, source-lock digest, verifier-profile digest and activation
identity on every decision and release receipt"): the same discipline as a SLSA statement binding a
subject digest to its builder, applied to the authority rather than the artifact.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .cards import Feedback

RECEIPT_SCHEMA = "lumiwright.release-receipt/v2"
PIN_FIELDS = ("pack", "pack_digest", "activation_id", "rulebook_ref", "rulebook_digest", "schema_digest",
              "sources_digest", "verifier_profile_digest", "builder_id")


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    check_id: str
    version: str
    outcome: str
    reasons: tuple[str, ...] = ()
    capability: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.check_id, "version": self.version, "outcome": self.outcome, "reasons": list(self.reasons),
                "capability": self.capability}


@dataclass(frozen=True, slots=True)
class ReleaseReceipt:
    pack: str
    pack_digest: str
    activation_id: str
    rulebook_ref: str
    rulebook_digest: str
    schema_digest: str
    sources_digest: str
    verifier_profile_digest: str
    builder_id: str
    action_id: str
    artifact_digest: str
    checks: tuple[CheckOutcome, ...]
    approvers: tuple[str, ...]
    feedback: tuple[Feedback, ...]
    issued_at: str

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA, "pack": self.pack, "pack_digest": self.pack_digest, "activation_id": self.activation_id,
            "rulebook_ref": self.rulebook_ref, "rulebook_digest": self.rulebook_digest, "schema_digest": self.schema_digest,
            "sources_digest": self.sources_digest, "verifier_profile_digest": self.verifier_profile_digest,
            "builder_id": self.builder_id, "action_id": self.action_id, "artifact_digest": self.artifact_digest,
            "checks": [c.to_dict() for c in self.checks], "approvers": list(self.approvers),
            "feedback": [f.to_dict() for f in self.feedback], "issued_at": self.issued_at,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.canonical(), "receipt_digest": self.digest}

    def pins(self) -> dict[str, str]:
        """The fields a decision's evidence must carry verbatim."""
        return {name: str(getattr(self, name)) for name in PIN_FIELDS}


def pin_evidence(evidence: Mapping[str, Any], receipt: ReleaseReceipt) -> dict[str, Any]:
    """Fold the receipt into an emission decision's evidence without losing anything the gate wrote."""
    return {**dict(evidence), **receipt.pins(), "release_receipt": receipt.to_dict()}


def pins_present(evidence: Mapping[str, Any]) -> tuple[str, ...]:
    """Which pin fields an evidence pack is missing or left empty (a bare gate leaves all nine)."""
    return tuple(name for name in PIN_FIELDS if not str(evidence.get(name, "")).strip())


__all__ = ["PIN_FIELDS", "RECEIPT_SCHEMA", "CheckOutcome", "ReleaseReceipt", "pin_evidence", "pins_present"]
