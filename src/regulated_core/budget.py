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

UNBUDGETED remains a historical representation understood by receivers. RegulatedEngine target issuance
requires resolved signed-policy terms or an explicit host fallback; unresolved terms refuse new authority.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol
from collections.abc import Mapping
from types import MappingProxyType
from .canonical import digest_hex

UNBUDGETED = "unbudgeted"


def host_budget_terms(value: Mapping[str, int] | None) -> Mapping[str, int] | None:
    """Validate and snapshot explicit host fallback terms; never invent a quota."""
    if value is None:
        return None
    if (not isinstance(value, Mapping) or set(value) != {"limit", "units"}
            or type(value["limit"]) is not int or type(value["units"]) is not int
            or value["limit"] < 0 or value["units"] < 1):
        raise ValueError("host budget needs integer limit >= 0 and units >= 1")
    return MappingProxyType({"limit": value["limit"], "units": value["units"]})


def reservation_attempt_id(request_id: str, ordinal: int) -> str:
    """Preserve the first id; bind later attempts to an unambiguous stable tuple."""
    if ordinal == 0:
        return request_id
    return "attempt:" + digest_hex({"request_id": request_id, "attempt": ordinal})


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
        self._released: dict[tuple[str, str], set[str]] = {}

    def reserve(self, tenant_id: str, mission: str, *, reservation_id: str, units: int, limit: int) -> Reservation:
        if units < 1 or limit < 0:
            raise BudgetError("a reservation needs at least one unit against a non-negative limit")
        key = (tenant_id, mission)
        with self._lock:
            live, consumed = self._live.setdefault(key, {}), self._consumed.setdefault(key, {})
            requested, ordinal = reservation_id, 0
            released = self._released.setdefault(key, set())
            while True:
                reservation_id = reservation_attempt_id(requested, ordinal)
                if reservation_id in live or reservation_id in consumed:
                    raise BudgetError("reservation id already used")
                if reservation_id not in released:
                    break
                ordinal += 1
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
            key = (tenant_id, mission)
            if self._live.get(key, {}).pop(reservation_id, None) is not None:
                self._released.setdefault(key, set()).add(reservation_id)

    def committed(self, tenant_id: str, mission: str) -> int:
        with self._lock:
            return sum(self._consumed.get((tenant_id, mission), {}).values())


__all__ = ["UNBUDGETED", "BudgetError", "InMemoryMissionBudget", "MissionBudget", "Reservation", "host_budget_terms", "reservation_attempt_id"]
