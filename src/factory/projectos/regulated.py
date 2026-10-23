"""The Project OS regulated emission seam — an INJECTED interface, not an import of `regulated_core`.

Project OS owns vertical EXECUTION; the authority plane (`regulated_core`) owns PERMISSION TO EMIT.
When a vertical declares a `RegulatedBlock`, the engine consults this gate at the emission boundary
(`ProjectEngine.release`). The gate is implemented in `regulated_core` and wired at the composition
root, so the dependency stays one-way: `factory` defines the seam here; `regulated_core` fills it.
`factory` core never imports `regulated_core`.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .spec import VerticalSpec


@dataclass(frozen=True, slots=True)
class ReceiptPinSource:
    """The authority pins a regulated release must carry, supplied by the composition root.

    `fields` names every pin the source guarantees and `resolve` returns them for a tenant. The source
    declares its own fields so the engine can refuse an incomplete receipt without importing the pack
    code that defines them (invariant I1); a source that declares no fields is refused outright, so the
    completeness check can never pass vacuously.
    """

    fields: tuple[str, ...]
    resolve: Callable[[str], Mapping[str, str]]

    def missing(self, pins: Mapping[str, Any]) -> tuple[str, ...]:
        """The declared fields that `pins` omits or leaves blank."""
        return tuple(name for name in self.fields if not str(pins.get(name, "")).strip())


class ReleaseAuthorityUnavailable(ValueError):
    """Trusted release authority could not be resolved; an ordinary mission is not a fallback."""


@dataclass(frozen=True, slots=True)
class ReleaseAuthorityBinding:
    """References resolved by the host, then independently verified by the authority core.

    This value carries no credential and grants nothing by construction. Its entire
    payload is included in the reviewed contract, including the inherited root mission.
    """

    grant_digest: str
    chain_digest: str
    root_digest: str
    mission: str

    def __post_init__(self) -> None:
        for name in ("grant_digest", "chain_digest", "root_digest"):
            value = getattr(self, name)
            if (not isinstance(value, str) or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)):
                raise ReleaseAuthorityUnavailable(f"invalid delegated {name}")
        if not isinstance(self.mission, str) or not self.mission.strip() or len(self.mission) > 1024:
            raise ReleaseAuthorityUnavailable("delegated authority requires a bounded root mission")

    def as_fields(self) -> dict[str, str]:
        return {"schema": "regulated/release-authority/v1", "grant_digest": self.grant_digest,
                "chain_digest": self.chain_digest, "root_digest": self.root_digest, "mission": self.mission}


class ReleaseAuthoritySource(Protocol):
    """Read authenticated project/goal admission, never project-authored authority fields.

    None means a positively resolved ordinary root. Missing delegated state, denied
    access and lookup failures raise ReleaseAuthorityUnavailable; they never return None.
    The receiving core still verifies every grant and refuses a delegate stripping it.
    """

    def resolve(self, *, tenant: str, actor_id: str, vertical: str,
                project_id: str) -> ReleaseAuthorityBinding | None: ...


@dataclass(frozen=True, slots=True)
class EmissionContext:
    """Who is releasing, and the approval they bring. `approval` is opaque to Project OS (a
    `regulated_core` approval certificate); the gate interprets it."""

    tenant: str
    actor_id: str
    actor_roles: tuple[str, ...] = ()
    is_producer: bool = False          # a probabilistic producer may never release an external action
    now_us: int = 0
    action_id: str = ""
    approval: Any = None               # opaque: a regulated_core approval certificate
    nonce: str = ""
    project_id: str = ""              # authenticated surface binds the logical artifact destination
    vertical_name: str = ""           # public surface namespace, distinct from the policy's domain
    review_producer_id: str = ""      # server-derived retained run; never a client-supplied identity
    release_target: str = ""          # the destination review, approval and release all bind (Paper A 4.2)
    not_after_us: int = 0             # host-set: no authority issued for this request may outlive this instant
    retained_state: Mapping[str, Any] | None = field(default=None, repr=False, compare=False)
    # Ephemeral server snapshot. ProjectEngine overwrites it from its store; never serialized as authority.


@dataclass(frozen=True, slots=True)
class EmissionDecision:
    """The gate's answer. `evidence` is the audit/evidence pack to persist; `permit` is opaque."""

    allowed: bool
    reason: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)
    permit: Any = None


class RegulatedEmissionGate(Protocol):
    """Implemented in `regulated_core` (over its consequence policy + verifiers + approval + permit),
    injected into `ProjectEngine`. Gates BOTH the draft (assemble) and the release (emit) boundaries,
    so unsafe content is blocked before it is ever assembled as a governed draft, not only at emission."""

    def review_draft(
        self, *, spec: VerticalSpec, contract: Mapping[str, Any], context: EmissionContext,
    ) -> EmissionDecision:
        """Assemble-time gate: run the content verifiers over the draft. Allowed => a governed draft
        (reversible, review-queue); denied => unsafe content blocked before release."""
        ...

    def authorize_release(
        self, *, spec: VerticalSpec, contract: Mapping[str, Any], out_path: str, context: EmissionContext,
        artifact: bytes,
    ) -> EmissionDecision:
        """Emission-time gate: deny-by-default, requires approval, and on allow returns a permit bound to these
        exact `artifact` bytes and to `out_path` as the target. Nothing is written here."""
        ...

    def describe_target(
        self, *, spec: VerticalSpec, out_path: str, context: EmissionContext,
    ) -> Mapping[str, str]:
        """The release target as the governance side sees it: `kind`, `identity` and `expected_state`, its current
        state. Project OS never inspects a target itself; this is what review and approval freeze."""
        ...

    def commit_release(
        self, *, spec: VerticalSpec, contract: Mapping[str, Any], decision: EmissionDecision, artifact: bytes,
        out_path: str, context: EmissionContext,
    ) -> ReleaseOutcome:
        """Commit the permitted bytes through the target adapter, which rechecks the permit at the target."""
        ...

    def reconcile_release(
        self, *, spec: VerticalSpec, artifact_sha256: str, out_path: str, context: EmissionContext, nonce: str,
    ) -> ReleaseOutcome:
        """Resolve an unknown or unrecorded outcome from the target's durable receipts for this exact permit
        nonce: never from the target's content, never by re-sending. The outcome's evidence carries
        `target_holds`: whether the target still holds the permitted bytes, a separate fact from whether the
        commit happened."""
        ...


@dataclass(frozen=True, slots=True)
class ReleaseObservation:
    """Read-only evidence of one exact release attempt, for a host's retained qualification record (review 3189).

    `decision` is the ONE signed decision the attempt recorded, verified when read, whose signed destination names
    this vertical, project and action and whose bound effect names these bytes and target; `outcome` is the receiving
    target's own answer, with `target_holds`; `receiving_record` is the signed OUTCOME/RECONCILED_COMMITTED record for
    that exact signed action (None when no commit was recorded); `receipt` is the target's durable committed receipt
    naming this tenant, target, operation and bytes (None when absent). A host retains all of them. Observing issues no approval, render, permit or delivery, writes nothing,
    and never renews an expired execution."""

    tenant: str
    project_id: str
    action_id: str
    nonce: str
    destination: str
    artifact_sha256: str
    outcome: ReleaseOutcome
    decision: Any
    receiving_record: Any = None
    receipt: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ReleaseOutcome:
    """What the target adapter observed, recorded after the effect as a separate event.

    `state` is `committed` (the target holds exactly the permitted bytes), `failed` (the target was not
    changed), `unknown` (the acknowledgement was lost), `not_committed` (a reconciliation query found the
    target without the permitted bytes, or the recorded decision refused) or `not_attempted` (reconciliation found
    no recorded decision for that action and nonce)."""

    state: str
    detail: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)
