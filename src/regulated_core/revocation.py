"""Revocation that reaches outstanding authority (Paper A 5.3; the owner's approved property, ledger 2971).

Every target permit carries the tenant's revocation epoch at issuance, and the target refuses a permit whose
epoch is no longer current. This module is the source of that epoch: an append-only ledger in which a supervisor
revokes a tenant's outstanding authority by raising its epoch, with who did it and why. After a revocation no
permit issued before it can commit, whichever host, worker or restart holds it; decisions and effects already
committed stay committed and are never rewritten.

The engine uses an in-memory ledger by default, which is correct for one process and says so. Deployed hosts
inject the durable Postgres ledger (`persistence_pg.PostgresRevocationLedger`) so every host reads one epoch.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol


class RevocationError(Exception):
    """A revocation was refused: no actor, no reason, or no tenant."""


@dataclass(frozen=True, slots=True)
class Revocation:
    tenant_id: str
    epoch: int            # the new epoch; permits carrying any earlier epoch are revoked
    actor: str
    reason: str
    at_us: int


class RevocationLedger(Protocol):
    def epoch(self, tenant_id: str) -> int:
        """The tenant's current revocation epoch; 0 until the first revocation."""
        ...

    def revoke(self, tenant_id: str, *, actor: str, reason: str, now_us: int) -> Revocation:
        """Raise the tenant's epoch by one, atomically, recording who revoked and why."""
        ...


def _checked(tenant_id: str, actor: str, reason: str) -> None:
    if not tenant_id.strip() or not actor.strip() or not reason.strip():
        raise RevocationError("a revocation names its tenant, the revoking actor and the reason")


class InMemoryRevocationLedger:
    """One process's revocation ledger. Correct only while a single process issues and commits permits."""

    durable = False

    def __init__(self) -> None:
        self._events: dict[str, list[Revocation]] = {}
        self._lock = threading.Lock()

    def epoch(self, tenant_id: str) -> int:
        with self._lock:
            return len(self._events.get(tenant_id, ()))

    def revoke(self, tenant_id: str, *, actor: str, reason: str, now_us: int) -> Revocation:
        _checked(tenant_id, actor, reason)
        with self._lock:
            events = self._events.setdefault(tenant_id, [])
            event = Revocation(tenant_id, len(events) + 1, actor, reason, now_us)
            events.append(event)
            return event

    def history(self, tenant_id: str) -> tuple[Revocation, ...]:
        with self._lock:
            return tuple(self._events.get(tenant_id, ()))


__all__ = ["InMemoryRevocationLedger", "Revocation", "RevocationError", "RevocationLedger"]
