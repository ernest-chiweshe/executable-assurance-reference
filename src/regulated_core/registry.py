"""The fail-closed policy registry: the seam where one core becomes many verticals.

A vertical registers a `ConsequencePolicy` that owns content types. Unknown content type ->
denied. Adding a vertical (regulated or forgiving) never edits this file. The same registry
carries a strict health policy and a forgiving course policy side by side.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from .models import Action, Assertion, Decision, PolicyContext, PolicyRef


class ConsequencePolicy(Protocol):
    ref: PolicyRef
    content_types: frozenset[str]
    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision: ...


@runtime_checkable
class DeclaresMissionBudget(Protocol):
    """A signed policy that bounds how much authority one mission may draw for an action (Paper A 4.2).

    The core reserves exactly what the policy declares, before deciding. Nothing a caller passes can remove,
    raise or lower it: the budget is policy, and the mission it applies to is named inside the signed action."""

    def mission_budget(self, action_id: str) -> Mapping[str, int] | None: ...


class PolicyRegistry:
    def __init__(self) -> None:
        self._by_type: dict[str, ConsequencePolicy] = {}

    def register(self, policy: ConsequencePolicy) -> None:
        if not policy.content_types:
            raise ValueError("a policy must own at least one content type")
        for ct in policy.content_types:
            if ct in self._by_type:
                raise ValueError(f"content type already owned: {ct}")
        for ct in policy.content_types:
            self._by_type[ct] = policy

    def resolve(self, content_type: str) -> ConsequencePolicy | None:
        return self._by_type.get(content_type)
