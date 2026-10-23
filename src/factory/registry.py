"""Selecting a provider by what a task needs, never by who makes it.

The registry is how the factory core stays provider-agnostic in practice. The
core asks for a *capability set* ("I need parallel sub-agents and a browser") and
gets back an adapter that satisfies it. No provider name appears in core code.
Swap, add, or retire a provider by changing what's registered, nothing else.
"""
from __future__ import annotations

from factory.harness import Capability, HarnessAdapter


class UnknownHarnessError(KeyError):
    """No adapter is registered under that name."""


class NoCapableHarnessError(RuntimeError):
    """No registered adapter satisfies the required capabilities."""


class HarnessRegistry:
    """An in-memory catalog of harness adapters, keyed by name."""

    def __init__(self) -> None:
        self._adapters: dict[str, HarnessAdapter] = {}

    def register(self, adapter: HarnessAdapter) -> None:
        self._adapters[adapter.info.name] = adapter

    def get(self, name: str) -> HarnessAdapter:
        try:
            return self._adapters[name]
        except KeyError:
            raise UnknownHarnessError(name) from None

    def all(self) -> list[HarnessAdapter]:
        return list(self._adapters.values())

    def select(self, required: frozenset[Capability]) -> HarnessAdapter:
        """Return the first adapter that satisfies every required capability.

        Selection is deliberately simple, first match wins. Policy-driven
        selection (cheapest-capable, per-tenant preference, fallback ordering) is
        a later concern. What matters now is the shape of the question: the core
        asks for capabilities, and the registry answers with a provider.
        """
        for adapter in self._adapters.values():
            if adapter.supports(required):
                return adapter
        raise NoCapableHarnessError(sorted(c.value for c in required))
