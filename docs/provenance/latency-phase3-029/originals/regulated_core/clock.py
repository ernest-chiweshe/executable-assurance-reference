"""Named authority time sources and absolute, non-extending validity checks."""
from __future__ import annotations

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
