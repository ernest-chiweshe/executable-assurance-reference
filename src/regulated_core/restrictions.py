"""Restriction policies a delegated child adds, evaluated at release (Paper A 4.2; ARCHITECTURE-OF-RECORD 13).

A child grant keeps every policy its ancestors are bound by and may add restrictions of its own. A restriction is a
signed policy addressed by its exact reference, `vertical/policy_id@digest`; it owns no content type and never
replaces the policy in force, it only narrows what that policy allows. The engine evaluates every added restriction
on the exact assertion and action being released:

* a restriction this engine does not hold refuses, because an unevaluated policy is never carried as metadata;
* a restriction that denies refuses, with its own reason;
* a restriction that asks for an approval of its own refuses, because one approval certificate binds one requirement
  and composed approval requirements are not supported yet;
* a restriction that allows, with or without annotation, lets the release proceed to the policy in force.
"""
from __future__ import annotations

import threading

from .registry import ConsequencePolicy


def policy_ref(policy: ConsequencePolicy) -> str:
    """The exact address a grant names a policy by."""
    return f"{policy.ref.vertical}/{policy.ref.policy_id}@{policy.ref.digest}"


class RestrictionRegistry:
    """Signed restriction policies by exact reference. Registration is by the host's composition, never a caller."""

    def __init__(self) -> None:
        self._by_ref: dict[str, ConsequencePolicy] = {}
        self._lock = threading.Lock()

    def register(self, policy: ConsequencePolicy) -> str:
        if not policy.ref.digest:
            raise ValueError("a restriction must be a signed policy with a digest")
        ref = policy_ref(policy)
        with self._lock:
            if ref in self._by_ref and self._by_ref[ref] is not policy:
                raise ValueError(f"restriction already registered: {ref}")
            self._by_ref[ref] = policy
        return ref

    def get(self, ref: str) -> ConsequencePolicy | None:
        with self._lock:
            return self._by_ref.get(ref)


__all__ = ["RestrictionRegistry", "policy_ref"]
