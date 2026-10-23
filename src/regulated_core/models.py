"""Merged domain model.

The model provides strict field validation, a data-sensitivity taxonomy (PHI/PII/PCI),
calibration-provenance-bearing confidence, producer lineage, structured reason codes.
It uses a LEAN base `Assertion` — lineage and confidence are OPTIONAL at the core
type and REQUIRED by the regulated policies. This is what lets one core carry a strict health
vertical and a forgiving course vertical without either deforming the base atom.

Time is integer microseconds since the epoch (injected, never wall-clock) so the signed surface
is small and reproducible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import digest_hex
from .signing import Signature

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9:._/-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCORE = re.compile(r"^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$")


def _id(name: str, v: str) -> None:
    if not _ID.fullmatch(v):
        raise ValueError(f"{name} is not a valid stable identifier")


def _sha(name: str, v: str) -> None:
    if not _SHA256.fullmatch(v):
        raise ValueError(f"{name} must be lowercase SHA-256 hex")


class ActionEffect(str, Enum):
    REVERSIBLE = "reversible"          # render/draft; no durable external state
    AUTHORITATIVE = "authoritative"    # mutate a system-of-record
    EXTERNAL = "external"              # send/transact outside the system


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    PHI = "phi"
    FINANCIAL = "financial"
    PCI = "pci"


class Outcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class DecisionKind(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_ANNOTATION = "allow-with-annotation"
    REQUIRE_APPROVAL = "require-approval"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Credential:
    """A signed attestation that an actor holds a role/licence, with jurisdiction and expiry.
    Signed by the identity authority; verified against the trust directory, never trusted raw."""

    kind: str                 # 'role:clinician', 'license:medical', 'role:compliance', ...
    jurisdiction: str         # e.g. 'US', 'US-CA', 'EU' ('*' = not jurisdiction-scoped)
    scope: str                # what it authorizes ('*' = general)
    subject_actor_id: str     # binds the credential to one actor
    tenant_id: str
    expires_at_us: int
    signature: Signature      # by the identity authority

    def __post_init__(self) -> None:
        _id("kind", self.kind)
        _id("subject_actor_id", self.subject_actor_id)
        _id("tenant_id", self.tenant_id)

    def signed_body(self) -> dict[str, Any]:
        return {
            "schema": "regulated/credential/v1", "kind": self.kind, "jurisdiction": self.jurisdiction,
            "scope": self.scope, "subject_actor_id": self.subject_actor_id,
            "tenant_id": self.tenant_id, "expires_at_us": self.expires_at_us,
        }


@dataclass(frozen=True, slots=True)
class Actor:
    actor_id: str
    tenant_id: str
    roles: frozenset[str]
    credentials: tuple[Credential, ...] = ()
    producer: bool = False    # a probabilistic producer may never take an authoritative/external action

    def __post_init__(self) -> None:
        _id("actor_id", self.actor_id)
        _id("tenant_id", self.tenant_id)


@dataclass(frozen=True, slots=True)
class PolicyContext:
    tenant_id: str
    actor: Actor
    purpose: str
    correlation_id: str
    now_us: int
    requested_scope: frozenset[str] = frozenset()   # minimum-necessary: data fields touched

    def __post_init__(self) -> None:
        _id("tenant_id", self.tenant_id)
        _id("purpose", self.purpose)
        _id("correlation_id", self.correlation_id)
        if self.actor.tenant_id != self.tenant_id:
            raise ValueError("actor tenant does not match policy context")


@dataclass(frozen=True, slots=True)
class Action:
    action_id: str
    effect: ActionEffect
    destination: str = ""

    def __post_init__(self) -> None:
        _id("action_id", self.action_id)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verification_class: str
    outcome: Outcome
    verifier_id: str          # the trusted identity that MUST have signed this (see verification.py)
    verifier_version: str
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id("verification_class", self.verification_class)
        _id("verifier_id", self.verifier_id)


@dataclass(frozen=True, slots=True)
class SignedVerification:
    """A verifier result bound to ONE assertion (id + content_digest + tenant) and signed by the
    verifier identity it names. Tenant binding prevents cross-tenant reuse of a signed verification."""

    assertion_id: str
    content_digest: str
    tenant_id: str
    result: VerificationResult
    verified_at_us: int
    signature: Signature

    def __post_init__(self) -> None:
        _id("assertion_id", self.assertion_id)
        _sha("content_digest", self.content_digest)
        _id("tenant_id", self.tenant_id)

    def signed_body(self) -> dict[str, Any]:
        return {
            "schema": "regulated/verification/v1", "assertion_id": self.assertion_id,
            "content_digest": self.content_digest, "tenant_id": self.tenant_id,
            "result": self.result, "verified_at_us": self.verified_at_us,
        }


@dataclass(frozen=True, slots=True)
class ConfidenceEvidence:
    """Confidence is accepted only WITH calibration provenance. A bare number is refused
    by the regulated policies; self-report and stale calibration are rejected there."""

    score: str                 # fixed decimal string in [0,1]
    method_id: str
    calibration_set_id: str
    calibrated_at_us: int

    def __post_init__(self) -> None:
        if not _SCORE.fullmatch(self.score):
            raise ValueError("score must be a decimal string in [0,1] with <=6 decimals")
        _id("method_id", self.method_id)
        _id("calibration_set_id", self.calibration_set_id)


@dataclass(frozen=True, slots=True)
class ProducerLineage:
    producer: str
    run_id: str
    model_id: str
    prompt_digest: str
    policy_digest: str
    gate_digest: str

    def __post_init__(self) -> None:
        _id("producer", self.producer)
        _id("run_id", self.run_id)
        _id("model_id", self.model_id)
        for n, v in (("prompt_digest", self.prompt_digest), ("policy_digest", self.policy_digest), ("gate_digest", self.gate_digest)):
            _sha(n, v)


@dataclass(frozen=True, slots=True)
class Assertion:
    """LEAN base atom. Only content_type/content_digest/tenant are structurally required.
    Provenance depth (lineage), confidence, and verifications are demanded by the REGULATED
    policies, not by the core — so a forgiving vertical adds without fabricating a lineage triple."""

    assertion_id: str
    tenant_id: str
    content_type: str
    content_digest: str
    data_classes: frozenset[DataClass] = frozenset()
    verifications: tuple[SignedVerification, ...] = ()
    lineage: ProducerLineage | None = None
    confidence: ConfidenceEvidence | None = None
    payload_ref: str = ""     # encrypted-store address; regulated policies require it for sensitive data
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _id("assertion_id", self.assertion_id)
        _id("tenant_id", self.tenant_id)
        _id("content_type", self.content_type)
        _sha("content_digest", self.content_digest)
        classes = [v.result.verification_class for v in self.verifications]
        if len(set(classes)) != len(classes):
            raise ValueError("verification classes must be unique")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    def outcome_for(self, verification_class: str) -> Outcome | None:
        for v in self.verifications:
            if v.result.verification_class == verification_class:
                return v.result.outcome
        return None


@dataclass(frozen=True, slots=True)
class Annotation:
    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    """Each role group must be satisfied by at least one credentialed approver; `minimum_approvers`
    distinct people total. `requester_may_approve=False` and distinctness give dual control."""

    role_groups: tuple[frozenset[str], ...]
    minimum_approvers: int
    scope: str
    reason: str
    expires_after_us: int
    requester_may_approve: bool = False

    def __post_init__(self) -> None:
        if not self.role_groups or any(not g for g in self.role_groups):
            raise ValueError("at least one non-empty role group is required")
        if self.minimum_approvers < len(self.role_groups):
            raise ValueError("minimum_approvers cannot be below the number of role groups")
        _id("scope", self.scope)

    def digest(self) -> str:
        """Fingerprint the exact requirement so a weaker approval cannot be
        reused for a stricter action even if the action id matched."""
        return digest_hex({
            "role_groups": sorted(sorted(g) for g in self.role_groups),
            "minimum_approvers": self.minimum_approvers,
            "scope": self.scope,
            "requester_may_approve": self.requester_may_approve,
        })


@dataclass(frozen=True, slots=True)
class Decision:
    kind: DecisionKind
    reason_codes: tuple[str, ...]
    rationale: str
    annotations: tuple[Annotation, ...] = ()
    approval: ApprovalRequirement | None = None

    def __post_init__(self) -> None:
        if not self.reason_codes:
            raise ValueError("every decision needs at least one stable reason code")
        if not self.rationale:
            raise ValueError("decision rationale is required")
        if self.kind is DecisionKind.REQUIRE_APPROVAL and self.approval is None:
            raise ValueError("require-approval needs an approval requirement")
        if self.kind is not DecisionKind.REQUIRE_APPROVAL and self.approval is not None:
            raise ValueError("only require-approval may carry an approval requirement")
        if self.kind is DecisionKind.ALLOW_WITH_ANNOTATION and not self.annotations:
            raise ValueError("annotated allow requires annotations")

    @staticmethod
    def allow(code: str, why: str) -> "Decision":
        return Decision(DecisionKind.ALLOW, (code,), why)

    @staticmethod
    def allow_with(code: str, why: str, *annotations: Annotation) -> "Decision":
        return Decision(DecisionKind.ALLOW_WITH_ANNOTATION, (code,), why, annotations=tuple(annotations))

    @staticmethod
    def require_approval(code: str, why: str, req: ApprovalRequirement) -> "Decision":
        return Decision(DecisionKind.REQUIRE_APPROVAL, (code,), why, approval=req)

    @staticmethod
    def deny(code: str, why: str) -> "Decision":
        return Decision(DecisionKind.DENY, (code,), why)

    @property
    def is_allow_class(self) -> bool:
        return self.kind in (DecisionKind.ALLOW, DecisionKind.ALLOW_WITH_ANNOTATION)


@dataclass(frozen=True, slots=True)
class PolicyRef:
    vertical: str
    policy_id: str
    version: str
    digest: str = ""       # content digest of the signed PolicyDocument in force ("" = undocumented);
                           # flows into the signed decision record, binding decisions to exact policy content

    def __post_init__(self) -> None:
        _id("vertical", self.vertical)
        _id("policy_id", self.policy_id)


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    record_id: str
    tenant_id: str
    assertion_id: str
    assertion_digest: str
    action: Action
    actor_id: str
    purpose: str
    correlation_id: str
    policy: PolicyRef
    decision: Decision
    decided_at_us: int
