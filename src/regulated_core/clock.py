"""Named authority time sources and absolute, non-extending validity checks."""
from __future__ import annotations

import weakref
from dataclasses import dataclass
import time
from typing import Any, Protocol, runtime_checkable


class ClockError(ValueError):
    """Authority time is unavailable, unqualified or outside its signed window."""


@dataclass(frozen=True)
class ClockReading:
    """An absolute microsecond reading bound to a configured clock domain."""

    domain: str
    now_us: int

    def __post_init__(self) -> None:
        if (not isinstance(self.domain, str) or not self.domain or self.domain != self.domain.strip()
                or len(self.domain) > 256 or type(self.now_us) is not int or self.now_us < 0):
            raise ClockError("invalid authority clock reading")

    def require_live(self, *, domain: str, issued_at_us: int, expires_at_us: int) -> None:
        """Refuse a different domain, future issuance or elapsed absolute expiry."""
        if (domain != self.domain or type(issued_at_us) is not int or type(expires_at_us) is not int
                or not 0 <= issued_at_us < expires_at_us
                or not issued_at_us <= self.now_us < expires_at_us):
            raise ClockError("authority clock domain or validity window differs")


@runtime_checkable
class TrustedClock(Protocol):
    """A host-configured source; requests never choose its identity or reading."""

    @property
    def domain(self) -> str: ...

    def read(self) -> ClockReading: ...

    def now_us(self) -> int: ...


@runtime_checkable
class ConnectionClock(TrustedClock, Protocol):
    """A clock that can read on the transaction owning an effect."""

    def read_on(self, connection: Any) -> ClockReading: ...


def read_clock(clock: TrustedClock, *, connection: Any = None) -> ClockReading:
    """Preserve the configured domain and the caller's transaction boundary."""
    if connection is None:
        reading = clock.read()
    elif isinstance(clock, ConnectionClock):
        reading = clock.read_on(connection)
    else:
        raise ClockError("effect transaction requires a connection-bound clock")
    if not isinstance(reading, ClockReading) or reading.domain != clock.domain:
        raise ClockError("clock reading differs from its configured domain")
    return reading


def system_time_us() -> int:
    """Return unqualified local wall time for explicit local composition."""
    return time.time_ns() // 1_000


class SystemClock:
    """Local system clock; it does not establish a PostgreSQL clock domain."""

    domain = "system:utc"

    def read(self) -> ClockReading:
        return ClockReading(self.domain, system_time_us())

    def now_us(self) -> int:
        return self.read().now_us


def require_bounded_lifetime(clock: object, *, issued_at_us: int, expires_at_us: int) -> None:
    """Refuse a permit whose lifetime exceeds the receiving clock's configured maximum.

    The bound is enforced where permits are received, so it binds permits issued before it was
    configured. A recovery quarantine relies on it: once the bound has elapsed after a hold, every
    permit issued before the hold has expired. A clock without a bound imposes none.
    """
    bound = getattr(clock, "max_permit_lifetime_us", None)
    if bound is not None and expires_at_us - issued_at_us > bound:
        raise ClockError("permit lifetime exceeds the receiving clock's maximum")


# Rollback detection after rare negative-authority writes (revocations, withdrawals). A host's recovery-capable
# clock registers a hook; stores call ``authority_write_committed`` after their write commits. The write has
# already committed, so a hook never undoes it; a rollback it detects still sets the recovery hold.
_WRITE_HOOKS: "weakref.WeakSet[object]" = weakref.WeakSet()


def register_authority_write_hook(owner: object) -> None:
    """Register an object whose ``sentinel_tick()`` runs after each committed negative-authority write."""
    _WRITE_HOOKS.add(owner)


def authority_write_committed() -> None:
    for owner in list(_WRITE_HOOKS):
        try:
            owner.sentinel_tick()
        except Exception:
            # The write committed: raising now would report a committed write as failed and invite a retry. A
            # detected rollback is recorded as the hold in the floor row; any other failure (an unavailable or
            # closed floor pool, a sentinel file error) loses only this tick. Best effort by design.
            pass
