"""The v1 governance extension and the PURE A2A-shaped mappings.

The extension is how governance receipts travel over an A2A boundary: a
versioned, CLOSED schema — unknown fields are refused, not ignored, because an
unrecognized authority claim must never ride along silently. The mappings here
are pure functions over dicts; no SDK type appears (the exact-pinned SDK is
admitted only inside the experimental Half B spike package).

Direction of authority: outbound mappings PROJECT our records into A2A-shaped
data; inbound mappings treat every remote id (task, context, tenant) as opaque
correlation. Nothing that arrives on the wire can become internal identity,
trust, or approval.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from factory.collaboration.contracts import (
    ContractViolation,
    ParticipantRole,
    RemoteTaskProjection,
    RemoteTaskState,
    ReviewVerdict,
    TrustClass,
    VisibilityPhase,
    WorkTicket,
    _require_digest,
    _require_money,
    canonical_digest,
)

GOVERNED_COLLABORATION_EXTENSION_URI = "urn:agent-factory:a2a:governed-collaboration:v1"

# The ONE named wire representation these pure mappings speak: A2A 1.0
# PROTO-JSON, as empirically proven against the pinned official SDK (revision
# 86c6b0d7dd3ea83efb808de348a0021677b2f0b2; Half B disproof, channel §14):
# lowerCamel field names (messageId, contextId), SCREAMING_SNAKE_CASE enum
# names (TASK_STATE_*, ROLE_*), member-based Parts where {"data": facts} is
# the JSON form of protobuf Value, and Message.extensions as extension URI
# strings. NOT the Python constructor spelling (snake_case); the two are
# never mixed. Half B instantiates this exact dict via the protobuf
# json_format ParseDict path and converts responses with MessageToDict; it
# must not diverge from this module.
A2A_1_0_ROLE_USER = "ROLE_USER"

# A2A 1.0 wire task states -> internal projection: all NINE SDK enum values
# (UNSPECIFIED grants no lifecycle authority — it is a projection value only).
# Anything absent fails closed.
_WIRE_STATES: Mapping[str, RemoteTaskState] = {
    "TASK_STATE_UNSPECIFIED": RemoteTaskState.UNSPECIFIED,
    "TASK_STATE_SUBMITTED": RemoteTaskState.SUBMITTED,
    "TASK_STATE_WORKING": RemoteTaskState.WORKING,
    "TASK_STATE_INPUT_REQUIRED": RemoteTaskState.INPUT_REQUIRED,
    "TASK_STATE_AUTH_REQUIRED": RemoteTaskState.AUTH_REQUIRED,
    "TASK_STATE_COMPLETED": RemoteTaskState.COMPLETED,
    "TASK_STATE_CANCELED": RemoteTaskState.CANCELED,
    "TASK_STATE_FAILED": RemoteTaskState.FAILED,
    "TASK_STATE_REJECTED": RemoteTaskState.REJECTED,
}


@dataclass(frozen=True, slots=True)
class GovernedCollaborationExtension:
    """The governance facts a governed A2A exchange must carry, digested.

    ``verdict_type`` is present only on review-bearing messages; its absence is
    a fact, not a default to be filled in.
    """

    ticket_digest: str
    frozen_context_digest: str
    correlation: str
    role: ParticipantRole
    visibility: VisibilityPhase
    grants: tuple[str, ...]
    ceiling_usd: float
    receipt_digest: str
    verdict_type: ReviewVerdict | None = None

    def __post_init__(self) -> None:
        for name in ("ticket_digest", "frozen_context_digest", "receipt_digest"):
            _require_digest(getattr(self, name), name)
        if not isinstance(self.correlation, str) or not self.correlation.strip():
            raise ContractViolation("correlation must be non-blank")
        if not isinstance(self.role, ParticipantRole):
            raise ContractViolation("role must be a ParticipantRole instance")
        if not isinstance(self.visibility, VisibilityPhase):
            raise ContractViolation("visibility must be a VisibilityPhase instance")
        if not isinstance(self.grants, tuple):
            raise ContractViolation("grants must be an immutable tuple")
        for grant in self.grants:
            if not isinstance(grant, str) or not grant.strip():
                raise ContractViolation("grants must be non-blank strings")
        if len(set(self.grants)) != len(self.grants):
            raise ContractViolation("grants must not contain duplicates")
        _require_money(self.ceiling_usd, "ceiling_usd")
        if self.verdict_type is not None and not isinstance(self.verdict_type, ReviewVerdict):
            raise ContractViolation("verdict_type must be a ReviewVerdict when present")

    @property
    def extension_digest(self) -> str:
        return canonical_digest(extension_payload(self))


_EXTENSION_KEYS = frozenset({
    "uri", "ticket_digest", "frozen_context_digest", "correlation", "role",
    "visibility", "grants", "ceiling_usd", "receipt_digest", "verdict_type",
})
_REQUIRED_KEYS = _EXTENSION_KEYS - {"verdict_type"}


def extension_payload(ext: GovernedCollaborationExtension) -> dict[str, object]:
    """The wire shape of the extension: plain data, canonical field order by digest."""
    payload: dict[str, object] = {
        "uri": GOVERNED_COLLABORATION_EXTENSION_URI,
        "ticket_digest": ext.ticket_digest,
        "frozen_context_digest": ext.frozen_context_digest,
        "correlation": ext.correlation,
        "role": ext.role.value,
        "visibility": ext.visibility.value,
        "grants": list(ext.grants),
        "ceiling_usd": ext.ceiling_usd,
        "receipt_digest": ext.receipt_digest,
    }
    if ext.verdict_type is not None:
        payload["verdict_type"] = ext.verdict_type.value
    return payload


def parse_extension(payload: Mapping[str, object]) -> GovernedCollaborationExtension:
    """Parse an inbound extension, failing closed on anything unexpected.

    Missing required fields, unknown fields, a wrong URI, or malformed values
    all refuse — a governed exchange without a complete, exact governance
    envelope is not a governed exchange (WO-CD-0 laws 5-6).
    """
    unknown = set(payload) - _EXTENSION_KEYS
    if unknown:
        raise ContractViolation(f"extension carries unknown authority fields: {sorted(unknown)}")
    missing = _REQUIRED_KEYS - set(payload)
    if missing:
        raise ContractViolation(f"extension missing required fields: {sorted(missing)}")
    if payload["uri"] != GOVERNED_COLLABORATION_EXTENSION_URI:
        raise ContractViolation(f"unsupported extension uri: {payload['uri']!r}")
    role_raw, visibility_raw = payload["role"], payload["visibility"]
    if not isinstance(role_raw, str) or not isinstance(visibility_raw, str):
        raise ContractViolation("role and visibility must be strings")
    try:
        role = ParticipantRole(role_raw)
        visibility = VisibilityPhase(visibility_raw)
    except ValueError as exc:
        raise ContractViolation(f"unknown role or visibility: {exc}") from exc
    grants_raw = payload["grants"]
    if not isinstance(grants_raw, list) or not all(isinstance(g, str) for g in grants_raw):
        raise ContractViolation("grants must be a list of strings")
    ceiling_raw = payload["ceiling_usd"]
    if isinstance(ceiling_raw, bool) or not isinstance(ceiling_raw, (int, float)):
        raise ContractViolation("ceiling_usd must be a number")
    verdict_raw = payload.get("verdict_type")
    verdict: ReviewVerdict | None = None
    if verdict_raw is not None:
        if not isinstance(verdict_raw, str):
            raise ContractViolation("verdict_type must be a string when present")
        try:
            verdict = ReviewVerdict(verdict_raw)
        except ValueError as exc:
            raise ContractViolation(f"unknown verdict_type: {verdict_raw!r}") from exc
    fields: dict[str, str] = {}
    for name in ("ticket_digest", "frozen_context_digest", "correlation", "receipt_digest"):
        value = payload[name]
        if not isinstance(value, str):
            raise ContractViolation(f"{name} must be a string")
        fields[name] = value
    return GovernedCollaborationExtension(
        ticket_digest=fields["ticket_digest"],
        frozen_context_digest=fields["frozen_context_digest"],
        correlation=fields["correlation"],
        role=role,
        visibility=visibility,
        grants=tuple(grants_raw),
        ceiling_usd=float(ceiling_raw),
        receipt_digest=fields["receipt_digest"],
        verdict_type=verdict,
    )


def ticket_to_a2a_payload(ticket: WorkTicket, ext: GovernedCollaborationExtension) -> dict[str, object]:
    """Project a ticket into an A2A 1.0 message dict (digests only, no content).

    The extension must be bound to THIS ticket — a mismatched ticket digest is
    refused so an envelope can never be reused across tickets. The shape is
    the named A2A 1.0 proto-JSON representation: required deterministic
    ``messageId`` (idempotent retries send the identical message),
    ``ROLE_USER``, one member-based DataPart, ``extensions`` DECLARING the
    governance URI, and the governance payload CARRIED in namespaced message
    metadata (an extension object may not occupy the URI list).
    """
    if ext.ticket_digest != ticket.ticket_digest:
        raise ContractViolation("extension is not bound to this ticket")
    message_id = "msg-" + canonical_digest({
        "ticket_digest": ticket.ticket_digest,
        "correlation": ext.correlation,
    })[:32]
    return {
        "message": {
            "messageId": message_id,
            "role": A2A_1_0_ROLE_USER,
            "parts": [{
                "data": {
                    "ticket_id": ticket.ticket_id,
                    "ticket_digest": ticket.ticket_digest,
                    "expected_artifact": ticket.expected_artifact,
                    "acceptance_gate": ticket.acceptance_gate,
                },
            }],
            "extensions": [GOVERNED_COLLABORATION_EXTENSION_URI],
            "metadata": {GOVERNED_COLLABORATION_EXTENSION_URI: extension_payload(ext)},
        },
    }


def extension_from_message(message: Mapping[str, object]) -> GovernedCollaborationExtension:
    """Extract the governance extension from an inbound A2A 1.0 message.

    Fails closed unless the URI is DECLARED in ``extensions`` AND the payload
    is present in the namespaced metadata — a governed exchange requires both
    the declaration and the facts (WO-CD-0 law 6).
    """
    declared = message.get("extensions")
    if not isinstance(declared, list) or GOVERNED_COLLABORATION_EXTENSION_URI not in declared:
        raise ContractViolation("governance extension uri is not declared on the message")
    metadata = message.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ContractViolation("message metadata missing")
    payload = metadata.get(GOVERNED_COLLABORATION_EXTENSION_URI)
    if not isinstance(payload, Mapping):
        raise ContractViolation("governance extension payload missing from metadata")
    return parse_extension(payload)


def project_remote_task(payload: Mapping[str, object], *, ticket: WorkTicket) -> RemoteTaskProjection:
    """Project a remote task response onto OUR ticket.

    Internal identity comes only from ``ticket``; the remote ``id``/``contextId``
    are stored as opaque correlation. A remote ``tenant`` value is ignored as
    authority by construction — the projection has no tenant field to write
    (WO-CD-0 law 7). Unknown states fail closed; no mapping can manufacture an
    ACK, approval, or ruling (law 8) — the return type is a projection, never
    an event record.
    """
    task_id = payload.get("id")
    context_id = payload.get("contextId")  # proto-JSON spelling, never context_id
    if not isinstance(task_id, str) or not isinstance(context_id, str):
        raise ContractViolation("remote task requires string id and contextId")
    status = payload.get("status")
    state_raw = status.get("state") if isinstance(status, Mapping) else payload.get("state")
    if not isinstance(state_raw, str):
        raise ContractViolation("remote task state missing")
    state = _WIRE_STATES.get(state_raw)
    if state is None:
        raise ContractViolation(f"unknown remote task state fails closed: {state_raw!r}")
    return RemoteTaskProjection(
        ticket_id=ticket.ticket_id,
        ticket_digest=ticket.ticket_digest,
        remote_task_id=task_id,
        remote_context_id=context_id,
        state=state,
    )


def classify_inbound_trust(*, authenticated: bool) -> TrustClass:
    """Trust class for work arriving over a remote boundary.

    Never OWNER (WO-CD-0 law 9): owner trust originates only from the owner's
    authenticated platform surfaces, not from any wire.
    """
    return TrustClass.AUTHENTICATED_OPERATOR if authenticated else TrustClass.UNTRUSTED_EXTERNAL
