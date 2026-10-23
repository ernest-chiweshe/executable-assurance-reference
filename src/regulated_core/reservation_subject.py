"""Canonical request association for mission budget reservations.

Only fields retained in existing decisions participate. Decision time and result
do not exist at reservation time. This digest associates records; it does not
authenticate a caller or authorize effects.
"""
from __future__ import annotations

from .budget import BudgetError
from .canonical import digest_hex
from .models import Action, Assertion, DecisionRecord, PolicyContext, PolicyRef
from .target import effect_of


def _subject(
    *, tenant_id: str, mission: str, nonce: str, assertion_id: str,
    assertion_digest: str, action: Action, actor_id: str, purpose: str,
    correlation_id: str, policy: PolicyRef,
) -> str:
    effect = effect_of(action.destination)
    if effect is None or effect.mission != mission:
        raise BudgetError("reservation mission must match the bound action")
    if (
        not nonce or not tenant_id or len(policy.digest) != 64
        or any(c not in "0123456789abcdef" for c in policy.digest)
    ):
        raise BudgetError("reservation requires tenant, nonce and exact policy digest")
    return digest_hex({
        "schema": "regulated/reservation-subject/v1",
        "tenant_id": tenant_id, "mission": mission, "nonce": nonce,
        "assertion_id": assertion_id, "assertion_digest": assertion_digest,
        "action": action, "actor_id": actor_id, "purpose": purpose,
        "correlation_id": correlation_id, "policy": policy,
    })


def request_subject(
    assertion: Assertion, action: Action, ctx: PolicyContext,
    policy: PolicyRef, *, mission: str, nonce: str,
) -> str:
    """Associate a reserve-time request with its resolved exact policy."""
    if assertion.tenant_id != ctx.tenant_id:
        raise BudgetError("assertion tenant differs from request tenant")
    return _subject(
        tenant_id=ctx.tenant_id, mission=mission, nonce=nonce,
        assertion_id=assertion.assertion_id, assertion_digest=assertion.content_digest,
        action=action, actor_id=ctx.actor.actor_id, purpose=ctx.purpose,
        correlation_id=ctx.correlation_id, policy=policy,
    )


def retained_subject(record: DecisionRecord, *, mission: str, nonce: str) -> str:
    """Derive the association from a previously authenticated retained record."""
    return _subject(
        tenant_id=record.tenant_id, mission=mission, nonce=nonce,
        assertion_id=record.assertion_id, assertion_digest=record.assertion_digest,
        action=record.action, actor_id=record.actor_id, purpose=record.purpose,
        correlation_id=record.correlation_id, policy=record.policy,
    )
