"""Policy documents — the governance graph: decisions bind to the EXACT policy content in force.

A decision record has always named its policy (`PolicyRef(vertical, policy_id, version)`), but a version
string is a mutable claim: nothing bound it to the policy's actual content. This closes that gap the same
way the qualification graph did for verifiers: a policy's declaration (intended use, prohibited uses,
required verifiers, approver roles, emission policy) becomes an IMMUTABLE, SIGNED, content-addressed
PolicyDocument with jurisdictions, an effective window, an issuing authority, and supersession — and a
decision's PolicyRef carries the document digest, so the (hash-chained, recorder-signed) decision record
is a cryptographic commitment to the exact policy text in force at decision time.

Same discipline as QualificationReport: versioned forever, superseded never edited, referenced by digest,
composable into the WORM store. Pure core (no factory dependency); standalone import. The digest field on
PolicyRef is OPTIONAL ("" = undocumented) so non-regulated and dev policies are untouched.
"""
from __future__ import annotations

from typing import Any

from dataclasses import dataclass

from .canonical import digest_hex
from .models import PolicyRef
from .signing import Signature, Signer, TrustDirectory


class PolicyDocumentError(Exception):
    """A policy document could not be issued, is invalid, or is untrusted — fail closed."""


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """An immutable, signed, content-addressed policy declaration. Identified downstream by `.digest()`;
    superseded (never edited) by a later version. `effective_until_us=0` means open-ended."""

    vertical: str
    policy_id: str
    version: str
    content: dict[str, Any]                     # the declaration itself (intended use, prohibitions, verifiers, ...)
    jurisdictions: tuple[str, ...]
    effective_from_us: int
    effective_until_us: int           # 0 = open-ended
    issued_by: str                    # the policy authority that signed this
    supersedes: str                   # digest of the prior version, or "" for the first
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/policy-document/v1", "vertical": self.vertical,
                "policy_id": self.policy_id, "version": self.version, "content": self.content,
                "jurisdictions": list(self.jurisdictions), "effective_from_us": self.effective_from_us,
                "effective_until_us": self.effective_until_us, "issued_by": self.issued_by,
                "supersedes": self.supersedes}

    def digest(self) -> str:
        return digest_hex({**self.signed_body(), "sig": self.signature.value})

    def ref(self) -> PolicyRef:
        """The PolicyRef a documented policy should carry: the version PLUS the content commitment."""
        return PolicyRef(vertical=self.vertical, policy_id=self.policy_id, version=self.version,
                         digest=self.digest())

    def effective_at(self, now_us: int) -> bool:
        if now_us < self.effective_from_us:
            return False
        return self.effective_until_us == 0 or now_us < self.effective_until_us


def document_policy(signer: Signer, *, vertical: str, policy_id: str, version: str, content: dict[str, Any],
                    jurisdictions: tuple[str, ...], effective_from_us: int, effective_until_us: int = 0,
                    supersedes: str = "") -> PolicyDocument:
    """Issue a signed, immutable policy document over a declaration."""
    body = {"schema": "regulated/policy-document/v1", "vertical": vertical, "policy_id": policy_id,
            "version": version, "content": content, "jurisdictions": list(jurisdictions),
            "effective_from_us": effective_from_us, "effective_until_us": effective_until_us,
            "issued_by": signer.key_id, "supersedes": supersedes}
    return PolicyDocument(vertical=vertical, policy_id=policy_id, version=version, content=content,
                          jurisdictions=jurisdictions, effective_from_us=effective_from_us,
                          effective_until_us=effective_until_us, issued_by=signer.key_id,
                          supersedes=supersedes, signature=signer.sign(body))


def verify_document(trust: TrustDirectory, doc: PolicyDocument, *, authority: str | None = None) -> bool:
    """Trust-anchored check: signed by a known identity (optionally the expected policy authority)."""
    if authority is not None and doc.signature.key_id != authority:
        return False
    return trust.verify(doc.signed_body(), doc.signature)


class PolicyLedger:
    """Append-only, trust-anchored history of policy documents per policy. Documents are immutable; a new
    version SUPERSEDES rather than overwrites. `current()` returns the latest EFFECTIVE trusted document —
    the single lookup a composition root uses to hand a documented ref to its policy."""

    def __init__(self, trust: TrustDirectory | None = None, *, authority: str | None = None) -> None:
        self._trust = trust               # if set, documents are trust-verified at the boundary (fail closed)
        self._authority = authority
        self._history: dict[str, list[PolicyDocument]] = {}

    def add(self, doc: PolicyDocument) -> None:
        if self._trust is not None and not verify_document(self._trust, doc, authority=self._authority):
            raise PolicyDocumentError("policy document signature invalid or untrusted")
        hist = self._history.setdefault(doc.policy_id, [])
        if any(d.digest() == doc.digest() for d in hist):
            raise PolicyDocumentError("duplicate document; documents are immutable — supersede with a new version")
        hist.append(doc)

    def history(self, policy_id: str) -> tuple[PolicyDocument, ...]:
        return tuple(self._history.get(policy_id, ()))

    def current(self, policy_id: str, now_us: int) -> PolicyDocument | None:
        live = [d for d in self._history.get(policy_id, ()) if d.effective_at(now_us)]
        return max(live, key=lambda d: d.effective_from_us) if live else None


__all__ = [
    "PolicyDocumentError", "PolicyDocument", "document_policy", "verify_document", "PolicyLedger",
]
