"""The door's three choke points: egress, credential issuance and inter-agent channels (Paper A section 4.2, row A02).

Paper A names three choke points the door mediates: egress, credential issuance and inter-agent channels. This module
supplies all three as effect boundaries of the SAME receiving transaction that governs policy changes
(regulated_core/governance_targets.py), not a parallel mechanism. That transaction is already the one "adapter at an
effect boundary" that A06 and A15 describe for any host-owned state:

* the permit binds the exact request bytes, the boundary's identity and the state approved as prior;
* the target verifies the permit and claims its nonce, then, under the lock of the scope, compares the state,
  records PREPARED, re-checks freshness, lets the host apply the change in its own transaction (with a last freshness
  check just before its write) and records COMMITTED;
* a lost acknowledgement is UNKNOWN and fences the scope until the host's exact receiving receipt resolves it; a repeat
  of the same permit is answered from the log and never applied twice;
* every attempt lands in a per-tenant, Merkle-rooted log that can be anchored to write-once storage.

**Credential issuance.** The approved change names who receives a credential (`holder`), for what (`scope`,
`purpose`) and for how long (`ttl_us`), and NOTHING else: the request may not carry key material, and the change
is refused before its nonce is claimed if it has any other field. The host's issuer mints the credential inside its
own transaction and hands the secret to the holder itself; neither the core nor the evidence ever sees it. The
governed state is the credential slot's current lease, so an issuance approved against one lease cannot land on
another.

**Inter-agent channels.** The approved change is one exact message: `sender`, `recipient` and `body`. The governed
state is the channel's head, so the approver sees the conversation as it stands and a message approved against one
head cannot be slotted in after another message; the head moving refuses it, and it is decided again.

A host composes these by implementing the small ports below, and routes its real issuers and channels through them;
a host whose issuer or channel is also composed with a `GovernanceGuard` refuses any write not admitted by the
target, the same way governed registries do. Which host paths are routed is recorded in
docs/ARCHITECTURE-OF-RECORD/effect-boundaries.json; this module does not claim any of them.

**Egress.** The approved change is one exact outbound payload to one allow-listed endpoint. The governed state is the
endpoint's registered configuration (address and credential reference, as a digest), so a permit approved for one
endpoint cannot be sent after the endpoint is repointed, and nothing is sent to an unregistered endpoint. An outside
system neither shares our lock nor writes our receipt in its own transaction, so the gateway sends under an
IDEMPOTENCY KEY derived from the permit (tenant, operation, nonce, payload digest; opaque), and the destination's status
for that key is the receipt: a lost acknowledgement is UNKNOWN and fences the endpoint until the destination's status
resolves it. The target never resends; presenting the same permit again is answered from the log. A destination that
cannot report status by key leaves an unknown send UNKNOWN for an operator, which is the honest answer.

**Honest limit, as for the governance guard.** This closes every composed path. It does not stop hostile code in the
same process from reaching the host's issuer directly; separating custody by operating-system permissions is row A01.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
from typing import Any, Protocol

from .canonical import canonical_bytes
from .governance_guard import GovernanceGuard
from .governance_targets import FinalCheckRefused, GovernanceLog, GovernanceTarget, GovernedChange
from .models import Action, ApprovalRequirement, Assertion, Decision, PolicyContext, PolicyRef
from .permit import EmissionError, PermitUseStore
from .target import ABSENT, Outcome, TargetAuthority

CREDENTIAL_BOUNDARY = "credential"
CREDENTIAL_CONTENT_TYPE = "credential:issuance"
CREDENTIAL_SCHEMA = "regulated/credential-issuance/v1"
CREDENTIAL_ROLE = "credential-custodian"
CREDENTIAL_OPERATION = "credential:issue"
EGRESS_BOUNDARY = "egress"
EGRESS_CONTENT_TYPE = "egress:payload"
EGRESS_SCHEMA = "regulated/egress-payload/v1"
EGRESS_ROLE = "release-approver"
EGRESS_OPERATION = "egress:send"
MAX_EGRESS_BYTES = 256 * 1024
_EGRESS_FIELDS = frozenset({"media_type", "payload"})
CHANNEL_BOUNDARY = "inter-agent"
CHANNEL_CONTENT_TYPE = "channel:message"
CHANNEL_SCHEMA = "regulated/agent-message/v1"
CHANNEL_ROLE = "channel-supervisor"
CHANNEL_OPERATION = "channel:deliver"
HOUR_US = 3_600 * 1_000_000
#: The longest credential the default policy lets anyone approve; a host may lower it, never raise it silently.
MAX_CREDENTIAL_TTL_US = HOUR_US
MAX_MESSAGE_BYTES = 64 * 1024
_CREDENTIAL_FIELDS = frozenset({"holder", "scope", "purpose", "ttl_us"})
_CHANNEL_FIELDS = frozenset({"sender", "recipient", "body"})


def _text(change: Mapping[str, Any], name: str) -> str:
    value = change.get(name)
    if not isinstance(value, str) or not value.strip():
        raise EmissionError(f"the change must name a non-empty {name}")
    return value


def credential_change_check(max_ttl_us: int = MAX_CREDENTIAL_TTL_US) -> Callable[[Mapping[str, Any]], None]:
    """Refuse an issuance change unless it is exactly holder, scope, purpose and a bounded lifetime: no key material,
    no unnamed field, no unbounded credential."""
    def check(change: Mapping[str, Any]) -> None:
        if set(change) != _CREDENTIAL_FIELDS:
            raise EmissionError("a credential issuance names exactly holder, scope, purpose and ttl_us; "
                                "key material or any other field never enters the approved request")
        _text(change, "holder")
        _text(change, "purpose")
        scope = change["scope"]
        if (not isinstance(scope, list) or not scope
                or any(not isinstance(item, str) or not item.strip() for item in scope)
                or len(set(scope)) != len(scope)):
            raise EmissionError("a credential's scope is a non-empty list of distinct named permissions")
        ttl = change["ttl_us"]
        if type(ttl) is not int or not 0 < ttl <= max_ttl_us:
            raise EmissionError(f"a credential's lifetime must be positive and at most {max_ttl_us} microseconds")
    return check


def message_change_check(max_bytes: int = MAX_MESSAGE_BYTES) -> Callable[[Mapping[str, Any]], None]:
    """Refuse a channel change unless it is exactly one bounded message between two different named agents."""
    def check(change: Mapping[str, Any]) -> None:
        if set(change) != _CHANNEL_FIELDS:
            raise EmissionError("an agent message names exactly sender, recipient and body")
        if _text(change, "sender") == _text(change, "recipient"):
            raise EmissionError("an agent message goes between two different agents")
        body = change["body"]
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > max_bytes:
            raise EmissionError(f"an agent message body is non-empty text of at most {max_bytes} bytes")
    return check


def egress_change_check(max_bytes: int = MAX_EGRESS_BYTES) -> Callable[[Mapping[str, Any]], None]:
    """Refuse an egress change unless it is exactly one bounded text payload with its media type."""
    def check(change: Mapping[str, Any]) -> None:
        if set(change) != _EGRESS_FIELDS:
            raise EmissionError("an outbound payload names exactly media_type and payload")
        _text(change, "media_type")
        payload = change["payload"]
        if not isinstance(payload, str) or not payload or len(payload.encode("utf-8")) > max_bytes:
            raise EmissionError(f"an outbound payload is non-empty text of at most {max_bytes} bytes")
    return check


def egress_bytes(endpoint_id: str, *, media_type: str, payload: str) -> bytes:
    """The exact bytes one outbound payload is approved and sent as."""
    return canonical_bytes({"schema": EGRESS_SCHEMA, "kind": EGRESS_BOUNDARY, "subject": endpoint_id,
                            "change": {"media_type": media_type, "payload": payload}})


def idempotency_key(tenant_id: str, operation: str, nonce: str, change_digest: str) -> str:
    """The key an outbound send carries and the destination's status is asked by: one per permit, opaque (it
    discloses neither the tenant nor the nonce), and the same on every presentation of that permit."""
    return sha256(canonical_bytes({"schema": "regulated/egress-idempotency/v1", "tenant_id": tenant_id,
                                   "operation": operation, "nonce": nonce,
                                   "change_digest": change_digest})).hexdigest()


def credential_request_bytes(credential_ref: str, *, holder: str, scope: tuple[str, ...], purpose: str,
                             ttl_us: int) -> bytes:
    """The exact bytes an issuance is approved and released as. Never contains the credential itself."""
    return canonical_bytes({"schema": CREDENTIAL_SCHEMA, "kind": CREDENTIAL_BOUNDARY, "subject": credential_ref,
                            "change": {"holder": holder, "scope": list(scope), "purpose": purpose, "ttl_us": ttl_us}})


def message_bytes(channel_id: str, *, sender: str, recipient: str, body: str) -> bytes:
    """The exact bytes one inter-agent message is approved and delivered as."""
    return canonical_bytes({"schema": CHANNEL_SCHEMA, "kind": CHANNEL_BOUNDARY, "subject": channel_id,
                            "change": {"sender": sender, "recipient": recipient, "body": body}})


class CredentialIssuer(Protocol):
    """The host's credential issuer, as the receiving transaction needs it.

    `lease` reports the slot's current lease digest (or "absent"). `issue` follows the GovernedChange contract: inside
    its own lock and transaction, refuse unless the lease is `approved_prior`, call `final_check()`, then mint the
    credential, deliver it to the holder and write a receipt keyed (tenant, operation, nonce, change digest),
    atomically with the new lease. It returns nothing: the secret never comes back through the core. `receipt`
    answers from that receipt only (ReceiptLookup)."""

    def lease(self, tenant_id: str, credential_ref: str) -> str: ...

    def issue(self, change: GovernedChange) -> None: ...

    def receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Outcome: ...


class EgressTransport(Protocol):
    """The host's outbound gateway, as the receiving transaction needs it.

    `endpoint` reports the allow-listed endpoint's configuration digest, or "absent" if it is not registered. `send`
    sends `change.change["payload"]` to that endpoint carrying `key`: it re-reads the endpoint and refuses unless it is
    `approved_prior`, calls `final_check()` immediately before the bytes leave, and raises if the acknowledgement is
    not received. `status` answers what the DESTINATION reports for `key`: COMMITTED if it received it, NOT_COMMITTED
    only if it can prove it never will, otherwise UNKNOWN."""

    def endpoint(self, tenant_id: str, endpoint_id: str) -> str: ...

    def send(self, change: GovernedChange, key: str) -> None: ...

    def status(self, tenant_id: str, key: str) -> Outcome: ...


class AgentChannel(Protocol):
    """The host's inter-agent channel, as the receiving transaction needs it.

    `head` reports the channel's current head digest (or "absent" before its first message). `deliver` follows the
    GovernedChange contract: under its own lock, refuse unless the head is `approved_prior`, call `final_check()`,
    then append the message and a receipt keyed (tenant, operation, nonce, change digest) atomically."""

    def head(self, tenant_id: str, channel_id: str) -> str: ...

    def deliver(self, change: GovernedChange) -> None: ...

    def receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Outcome: ...


def credential_issuance_target(issuer: CredentialIssuer, credential_ref: str, *, tenant_id: str,
                               authority: TargetAuthority, uses: PermitUseStore, log: GovernanceLog,
                               guard: GovernanceGuard | None = None,
                               max_ttl_us: int = MAX_CREDENTIAL_TTL_US) -> GovernanceTarget:
    """The only way a composed issuer mints a credential for `credential_ref`: under a permit for the exact issuance.

    Credentials belong to one tenant, so the scope is per tenant, unlike a global pack registry."""
    if not credential_ref.strip():
        raise ValueError("a credential slot needs a name")
    return GovernanceTarget(tenant_id=tenant_id, kind=CREDENTIAL_BOUNDARY, subject=credential_ref,
                            authority=authority, uses=uses, state=lambda: issuer.lease(tenant_id, credential_ref),
                            apply=_host_transaction_only, log=log, operation_name=CREDENTIAL_OPERATION, guard=guard,
                            transact=issuer.issue, scope=f"{CREDENTIAL_BOUNDARY}:{tenant_id}:{credential_ref}",
                            receipt=issuer.receipt, boundary=CREDENTIAL_BOUNDARY, schema=CREDENTIAL_SCHEMA,
                            validate=credential_change_check(max_ttl_us))


def egress_target(transport: EgressTransport, endpoint_id: str, *, tenant_id: str, authority: TargetAuthority,
                  uses: PermitUseStore, log: GovernanceLog, guard: GovernanceGuard | None = None,
                  max_bytes: int = MAX_EGRESS_BYTES) -> GovernanceTarget:
    """The only way a composed gateway sends bytes out: under a permit for the exact payload to this endpoint as
    registered, with an idempotency key, resolved only from the destination's status."""
    if not endpoint_id.strip():
        raise ValueError("an endpoint needs a name")

    def send(change: GovernedChange) -> None:
        if change.approved_prior == ABSENT:
            # Refused before any byte leaves; the host contract says a final-check refusal wrote nothing.
            raise FinalCheckRefused("the endpoint is not registered; nothing was sent")
        transport.send(change, idempotency_key(change.tenant_id, change.operation, change.nonce, change.change_digest))

    def receipt(tenant: str, operation: str, nonce: str, change_digest: str) -> Outcome:
        return transport.status(tenant, idempotency_key(tenant, operation, nonce, change_digest))

    return GovernanceTarget(tenant_id=tenant_id, kind=EGRESS_BOUNDARY, subject=endpoint_id, authority=authority,
                            uses=uses, state=lambda: transport.endpoint(tenant_id, endpoint_id),
                            apply=_host_transaction_only, log=log, operation_name=EGRESS_OPERATION, guard=guard,
                            transact=send, scope=f"{EGRESS_BOUNDARY}:{tenant_id}:{endpoint_id}", receipt=receipt,
                            boundary=EGRESS_BOUNDARY, schema=EGRESS_SCHEMA, validate=egress_change_check(max_bytes))


def channel_target(channel: AgentChannel, channel_id: str, *, tenant_id: str, authority: TargetAuthority,
                   uses: PermitUseStore, log: GovernanceLog, guard: GovernanceGuard | None = None,
                   max_bytes: int = MAX_MESSAGE_BYTES) -> GovernanceTarget:
    """The only way a composed channel carries a message between agents: under a permit for the exact message, against
    the head the approver saw."""
    if not channel_id.strip():
        raise ValueError("a channel needs a name")
    return GovernanceTarget(tenant_id=tenant_id, kind=CHANNEL_BOUNDARY, subject=channel_id, authority=authority,
                            uses=uses, state=lambda: channel.head(tenant_id, channel_id),
                            apply=_host_transaction_only, log=log, operation_name=CHANNEL_OPERATION, guard=guard,
                            transact=channel.deliver, scope=f"{CHANNEL_BOUNDARY}:{tenant_id}:{channel_id}",
                            receipt=channel.receipt, boundary=CHANNEL_BOUNDARY, schema=CHANNEL_SCHEMA,
                            validate=message_change_check(max_bytes))


def _host_transaction_only(change: Mapping[str, Any]) -> None:
    raise EmissionError("this boundary applies only through the host's own transaction")


def _requirement(role: str, approvers: int, action: Action, what: str, window_us: int) -> ApprovalRequirement:
    return ApprovalRequirement((frozenset({role}),), approvers, action.action_id, what, window_us)


def _configured(approvers: object, window_us: object, *, least: int) -> tuple[int, int]:
    """Validate a policy's configuration: whole numbers only (never a bool), at least `least` approvers, a window."""
    if type(approvers) is not int or approvers < least:
        raise ValueError(f"approvers must be a whole number of at least {least}")
    if type(window_us) is not int or window_us <= 0:
        raise ValueError("the approval window must be a positive whole number of microseconds")
    return approvers, window_us


def _policy_ref(vertical: str, policy_id: str, text: str, approvers: int, window_us: int) -> PolicyRef:
    """The signed identity of a configured policy. EVERY parameter that changes behaviour is in the digest, so two
    configurations can never share an identity in the evidence (source review 3227); the text alone is not enough."""
    return PolicyRef(vertical=vertical, policy_id=policy_id, version="1.0.0", digest=sha256(canonical_bytes(
        {"text": text, "approvers": approvers, "window_us": window_us})).hexdigest())


class CredentialIssuancePolicy:
    """The core policy for issuing a credential: a named custodian approves the exact issuance.

    A deployment may require more custodians; it may not require none, because a credential is authority."""

    content_types = frozenset({CREDENTIAL_CONTENT_TYPE})

    def __init__(self, *, approvers: int = 1, window_us: int = HOUR_US) -> None:
        # A credential is authority: the policy cannot be configured to need no custodian.
        self._approvers, self._window = _configured(approvers, window_us, least=1)
        self._text = (f"Issuing a credential is authority: {approvers} credential custodian(s) approve the exact "
                      f"holder, scope, purpose and lifetime, within {window_us} microseconds.")
        self.ref = _policy_ref("credentials", "issuance", self._text, self._approvers, self._window)

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        return Decision.require_approval("CREDENTIAL_ISSUANCE", self._text, _requirement(
            CREDENTIAL_ROLE, self._approvers, action, "a credential custodian approves the exact issuance",
            self._window))


class EgressPolicy:
    """The core policy for bytes leaving the system: by default a release approver signs off on the exact payload.

    A deployment may set `approvers=0` for a machine endpoint it has chosen to trust: every send then still needs a
    permit, is bound to the registered endpoint, is sent once under its key and is logged, but no human signs each."""

    content_types = frozenset({EGRESS_CONTENT_TYPE})

    def __init__(self, *, approvers: int = 1, window_us: int = HOUR_US) -> None:
        self._approvers, self._window = _configured(approvers, window_us, least=0)
        self._text = ("Bytes leave the system only under a permit for the exact payload and the registered endpoint; "
                      + (f"{approvers} release approver(s) sign off on it within {window_us} microseconds."
                         if approvers else
                         "this deployment requires no human for this endpoint, and every send is recorded."))
        self.ref = _policy_ref("egress", "outbound", self._text, self._approvers, self._window)

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if not self._approvers:
            return Decision.allow("EGRESS_MEDIATED", self._text)
        return Decision.require_approval("EGRESS_APPROVAL", self._text, _requirement(
            EGRESS_ROLE, self._approvers, action, "a release approver signs off on the exact outbound payload",
            self._window))


class AgentMessagePolicy:
    """The core policy for a message between agents.

    With `approvers=0` (the default) every message still needs a permit, is checked against the channel head, claimed
    once and logged, but no human signs each one: mediation, not a queue of approvals. A deployment that wants a
    supervisor on a channel sets `approvers` to one or more."""

    content_types = frozenset({CHANNEL_CONTENT_TYPE})

    def __init__(self, *, approvers: int = 0, window_us: int = HOUR_US) -> None:
        self._approvers, self._window = _configured(approvers, window_us, least=0)
        self._text = ("An inter-agent message passes the door under a permit for its exact bytes and the channel head; "
                      + (f"{approvers} channel supervisor(s) approve it within {window_us} microseconds."
                         if approvers else "no human approval is required, and every message is recorded."))
        self.ref = _policy_ref("channels", "agent-message", self._text, self._approvers, self._window)

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if not self._approvers:
            return Decision.allow("AGENT_MESSAGE_MEDIATED", self._text)
        return Decision.require_approval("AGENT_MESSAGE_SUPERVISED", self._text, _requirement(
            CHANNEL_ROLE, self._approvers, action, "a channel supervisor approves the exact message", self._window))


__all__ = [
    "AgentChannel", "AgentMessagePolicy", "CHANNEL_BOUNDARY", "CHANNEL_CONTENT_TYPE", "CHANNEL_OPERATION",
    "CHANNEL_ROLE", "CHANNEL_SCHEMA", "CREDENTIAL_BOUNDARY", "CREDENTIAL_CONTENT_TYPE", "CREDENTIAL_OPERATION",
    "CREDENTIAL_ROLE", "CREDENTIAL_SCHEMA", "CredentialIssuancePolicy", "CredentialIssuer", "EGRESS_BOUNDARY",
    "EGRESS_CONTENT_TYPE", "EGRESS_OPERATION", "EGRESS_ROLE", "EGRESS_SCHEMA", "EgressPolicy", "EgressTransport",
    "MAX_CREDENTIAL_TTL_US", "MAX_EGRESS_BYTES", "MAX_MESSAGE_BYTES", "channel_target", "credential_change_check",
    "credential_issuance_target", "credential_request_bytes", "egress_bytes", "egress_change_check", "egress_target",
    "idempotency_key", "message_bytes", "message_change_check",
]
