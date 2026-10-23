"""Aggregate mission budgets: reserved before authority is issued, consumed at the target (Paper A 4.2, 6.1).

Paper A, section 4.2: "Aggregate budgets are reserved in shared state before authority is issued; delegated
authority is always a subset of its parent and draws on the same mission budget." Proposition 2: if each unit of
effect consumes a unique reservation from a linearisable mission budget, and reservations are not reclaimed while
usable authority exists, committed consumption cannot exceed the budget. The model checker's protocol is exactly
reserve, record, permit, commit; removing the reservation guard exceeds the budget in eight steps (Table 2).

This module is that reservation ledger:

* `reserve` admits a reservation only while reserved plus consumed units stay within the mission's limit; the
  check and the admission are one atomic step, so two reservations can never both take the last unit;
* `consume` turns a live reservation into consumption exactly once, at the target, under the target's lock;
* `release` returns a reservation only when no usable authority was issued against it (a refused decision, or a
  permit that never existed), or after the target has durably retired its permit nonce and
  confirmed no effect; usable authority must never outlive its reservation.

A mission with no declared limit has no reservation at all and is recorded as UNBUDGETED in the permit and the
evidence: the budget claim holds exactly where a limit is declared and is never implied where one is not.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

UNBUDGETED = "unbudgeted"


class BudgetError(Exception):
    """A reservation was refused or a consumption was not backed by a live reservation."""


@dataclass(frozen=True, slots=True)
class Reservation:
    tenant_id: str
    mission: str
    reservation_id: str
    units: int
    limit: int


class MissionBudget(Protocol):
    def reserve(self, tenant_id: str, mission: str, *, reservation_id: str, units: int, limit: int) -> Reservation:
        """Admit the reservation atomically, or raise `BudgetError` if it would exceed the limit."""
        ...

    def consume(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        """Turn a live reservation into consumption exactly once, or raise `BudgetError`."""
        ...

    def release(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        """Return an unconsumed reservation only after usable authority has been excluded."""
        ...

    def committed(self, tenant_id: str, mission: str) -> int:
        """Units consumed so far."""
        ...


class InMemoryMissionBudget:
    """One process's linearisable ledger: a single lock orders every reservation, consumption and release."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._live: dict[tuple[str, str], dict[str, int]] = {}
        self._consumed: dict[tuple[str, str], dict[str, int]] = {}

    def reserve(self, tenant_id: str, mission: str, *, reservation_id: str, units: int, limit: int) -> Reservation:
        if units < 1 or limit < 0:
            raise BudgetError("a reservation needs at least one unit against a non-negative limit")
        key = (tenant_id, mission)
        with self._lock:
            live, consumed = self._live.setdefault(key, {}), self._consumed.setdefault(key, {})
            if reservation_id in live or reservation_id in consumed:
                raise BudgetError("reservation id already used")
            if sum(live.values()) + sum(consumed.values()) + units > limit:
                raise BudgetError(f"mission budget exceeded: {limit} unit(s) allowed")
            live[reservation_id] = units
        return Reservation(tenant_id, mission, reservation_id, units, limit)

    def consume(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        key = (tenant_id, mission)
        with self._lock:
            live = self._live.get(key, {})
            if reservation_id not in live:
                raise BudgetError("no live reservation backs this effect")
            self._consumed.setdefault(key, {})[reservation_id] = live.pop(reservation_id)

    def release(self, tenant_id: str, mission: str, reservation_id: str) -> None:
        with self._lock:
            self._live.get((tenant_id, mission), {}).pop(reservation_id, None)

    def committed(self, tenant_id: str, mission: str) -> int:
        with self._lock:
            return sum(self._consumed.get((tenant_id, mission), {}).values())


__all__ = ["UNBUDGETED", "BudgetError", "InMemoryMissionBudget", "MissionBudget", "Reservation"]
