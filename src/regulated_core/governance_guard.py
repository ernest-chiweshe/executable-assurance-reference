"""The governance guard: a governed registry refuses every write that is not the governance target applying a change.

Paper A section 4.2; docs/ARCHITECTURE-OF-RECORD/08 row A09. Routing an administrative API through the governance
target is not enough on its own (review 3125): a direct call to the registry would still change governance state. A
registry composed with a guard therefore calls `require(kind, subject)` at the top of every mutating method, and the
guard admits the call only while the governance target (regulated_core/governance_targets.py) is applying exactly that
change, on the same thread, after it has verified and claimed a current permit.

**Honest limit.** This closes every composed code path, including a direct call to the registry. It does not stop
hostile code running inside the same Python process, which can reach any object; separating custody by operating-system
permissions is Paper A row A01.

This module is tiny and imports nothing from the registries, so any registry, core or host, can depend on it.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager


class GovernanceRefused(PermissionError):
    """A governance registry was written to outside the governance target."""


class GovernanceGuard:
    """Admits a registry write only inside the governance target's application of the exact (kind, subject)."""

    def __init__(self) -> None:
        self._local = threading.local()

    @contextmanager
    def _admitting(self, kind: str, subject: str) -> Iterator[None]:
        """Used only by GovernanceTarget, around applying a verified change. Not a public entrance."""
        prior = getattr(self._local, "admitted", None)
        self._local.admitted = (kind, subject)
        try:
            yield
        finally:
            self._local.admitted = prior

    def require(self, kind: str, subject: str) -> None:
        """Refuse unless this thread is applying exactly this governance change under a permit."""
        if getattr(self._local, "admitted", None) != (kind, subject):
            raise GovernanceRefused(
                f"{kind} for {subject!r} changes only through the governance target, under a tier-4 permit")


__all__ = ["GovernanceGuard", "GovernanceRefused"]
