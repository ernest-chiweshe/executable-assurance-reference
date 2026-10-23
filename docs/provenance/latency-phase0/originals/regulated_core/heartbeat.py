"""Monitor heartbeat: losing the independent monitor pauses new high-consequence authority (Paper A 5.3, row A17).

The monitor is the independent system that watches the door's evidence and clears tier-4 decisions. If it goes silent,
the door must not keep issuing high-consequence authority as though someone were still watching. The monitor signs a
heartbeat at a regular interval with its own key; the engine refuses new authority for any action at or above the
configured tier unless some monitor key in force NOW has a latest heartbeat that verifies and is fresh on the engine's
trusted clock. A silent, stale, unverifiable or retired-key heartbeat refuses, and the refusal is a recorded denial
with a stable reason code; the host's optional alarm hook is told, so the silence is raised, never merely absorbed.

Heartbeats are kept per monitor: a retired monitor's high sequence number never hides its replacement's beats. They
enter only through `HeartbeatIngress`, which verifies before it stores (source review 3307), so an untrusted beat can neither
be persisted nor shadow a later valid one.

Effects already authorized are not revoked by a missing heartbeat: stopping authority already issued is revocation's
job (regulated_core/revocation.py). A heartbeat grants nothing on its own; it only allows the other checks to proceed.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .outage import OutageAlarm, OutageEvent, Severity
from .signing import Signature, Signer, TrustDirectory

HEARTBEAT_SCHEMA = "regulated/monitor-heartbeat/v1"
DEFAULT_MAX_AGE_US = 5 * 60 * 1_000_000
STALE = "MONITOR_HEARTBEAT_STALE"


@dataclass(frozen=True, slots=True)
class MonitorHeartbeat:
    installation: str
    monitor_id: str
    sequence: int
    beat_at_us: int
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        return {"schema": HEARTBEAT_SCHEMA, "installation": self.installation, "monitor_id": self.monitor_id,
                "sequence": self.sequence, "beat_at_us": self.beat_at_us}


def issue_heartbeat(monitor: Signer, *, installation: str, sequence: int, beat_at_us: int) -> MonitorHeartbeat:
    """The monitor's signed statement that it was watching this installation at `beat_at_us`."""
    body = {"schema": HEARTBEAT_SCHEMA, "installation": installation, "monitor_id": monitor.key_id,
            "sequence": sequence, "beat_at_us": beat_at_us}
    return MonitorHeartbeat(installation, monitor.key_id, sequence, beat_at_us, monitor.sign(body))


class HeartbeatStore(Protocol):
    def put(self, beat: MonitorHeartbeat) -> None: ...

    def latest(self, installation: str, monitor_id: str) -> MonitorHeartbeat | None: ...


class InMemoryHeartbeatStore:
    """Keeps each monitor's highest-sequence heartbeat; an older or equal sequence never replaces it."""

    def __init__(self) -> None:
        self._beats: dict[tuple[str, str], MonitorHeartbeat] = {}
        self._lock = threading.Lock()

    def put(self, beat: MonitorHeartbeat) -> None:
        with self._lock:
            key = (beat.installation, beat.monitor_id)
            current = self._beats.get(key)
            if current is None or beat.sequence > current.sequence:
                self._beats[key] = beat

    def latest(self, installation: str, monitor_id: str) -> MonitorHeartbeat | None:
        with self._lock:
            return self._beats.get((installation, monitor_id))


MonitorKeys = frozenset[str] | Callable[[], frozenset[str]]


class _Monitors:
    """The monitor keys in force now: configured (or read live) AND registered in the trust directory."""

    def __init__(self, trust: TrustDirectory, installation: str, monitor_key_ids: MonitorKeys) -> None:
        if not installation:
            raise ValueError("a heartbeat check needs the installation it watches")
        self._trust, self._installation, self._keys = trust, installation, monitor_key_ids

    def in_force(self) -> frozenset[str]:
        keys = self._keys() if callable(self._keys) else self._keys
        return frozenset(k for k in keys if self._trust.is_known(k))

    def problem(self, beat: MonitorHeartbeat, *, now_us: int, max_age_us: int) -> str | None:
        if (beat.installation != self._installation or beat.monitor_id not in self.in_force()
                or beat.signature.key_id != beat.monitor_id
                or not self._trust.verify(beat.signed_body(), beat.signature)):
            return "the latest monitor heartbeat does not verify against a monitor in force"
        if beat.beat_at_us > now_us:
            return "the latest monitor heartbeat is dated in the future"
        if now_us - beat.beat_at_us > max_age_us:
            return "the monitor has been silent longer than the freshness window"
        return None


def _checked_window(max_age_us: int) -> int:
    if type(max_age_us) is not int or max_age_us < 1:
        raise ValueError("a heartbeat check needs a positive freshness window")
    return max_age_us


class HeartbeatGate:
    """Refuses new authority at or above `min_tier` while no monitor is demonstrably watching."""

    def __init__(self, *, store: HeartbeatStore, trust: TrustDirectory, installation: str,
                 monitor_key_ids: MonitorKeys, max_age_us: int = DEFAULT_MAX_AGE_US,
                 min_tier: int = 3, on_stale: Callable[[str], None] | None = None) -> None:
        if type(min_tier) is not int or not 1 <= min_tier <= 4:
            raise ValueError("a heartbeat gate needs a tier from 1 to 4")
        self._max_age = _checked_window(max_age_us)
        self._store, self._installation, self.min_tier, self._on_stale = store, installation, min_tier, on_stale
        self._monitors = _Monitors(trust, installation, monitor_key_ids)

    def problem(self, tier: int, *, now_us: int) -> tuple[str, str] | None:
        """(code, reason) when an action at `tier` must be refused for want of a live monitor, else None."""
        if tier < self.min_tier:
            return None
        reason = "no monitor heartbeat has been received"
        newest = -1
        for key in sorted(self._monitors.in_force()):
            beat = self._store.latest(self._installation, key)
            if beat is None:
                continue
            found = self._monitors.problem(beat, now_us=now_us, max_age_us=self._max_age)
            if found is None:
                return None
            if beat.beat_at_us > newest:        # report on the most recent evidence of a monitor
                newest, reason = beat.beat_at_us, found
        if self._on_stale is not None:
            try:
                self._on_stale(reason)
            except Exception:   # noqa: BLE001 - raising the alarm must never turn a refusal into an error
                pass
        return STALE, reason


class HeartbeatRefused(ValueError):
    """A heartbeat the ingress will not store; the reason is fixed text, never the submitted content."""


class HeartbeatIngress:
    """The only way a heartbeat reaches the store: verified against a monitor in force BEFORE it is persisted.

    A beat for another installation, from a key not in force, with a signature that does not verify, dated in the
    future or already older than the freshness window is refused and never stored (source review 3307)."""

    def __init__(self, *, store: HeartbeatStore, trust: TrustDirectory, installation: str,
                 monitor_key_ids: MonitorKeys, clock_us: Callable[[], int],
                 max_age_us: int = DEFAULT_MAX_AGE_US) -> None:
        self._store, self._clock = store, clock_us
        self._max_age = _checked_window(max_age_us)
        self._monitors = _Monitors(trust, installation, monitor_key_ids)

    def receive(self, beat: MonitorHeartbeat) -> None:
        if type(beat.sequence) is not int or beat.sequence < 0 or type(beat.beat_at_us) is not int:
            raise HeartbeatRefused("a heartbeat needs a non-negative integer sequence and time")
        problem = self._monitors.problem(beat, now_us=self._clock(), max_age_us=self._max_age)
        if problem is not None:
            raise HeartbeatRefused(problem)
        self._store.put(beat)


def heartbeat_alarm(alarm: OutageAlarm, *, installation: str, clock_us: Callable[[], int],
                    every_us: int = 60 * 1_000_000) -> Callable[[str], None]:
    """The gate's `on_stale` hook over the host's outage alarm: HIGH (contained: nothing was issued), at most once per
    `every_us` for the same reason, so a silent monitor raises the alarm without one alarm per refused request."""
    last: dict[str, int] = {}
    lock = threading.Lock()

    def raise_stale(reason: str) -> None:
        now = clock_us()
        with lock:
            if reason in last and now - last[reason] < every_us:
                return
            last[reason] = now
        alarm.raise_alarm(OutageEvent(tenant_id=installation, component="monitor-heartbeat",
                                      operation="authorize_high_tier", detail=reason, at_us=now,
                                      severity=Severity.HIGH, phase="contained"))

    return raise_stale


__all__ = ["DEFAULT_MAX_AGE_US", "HEARTBEAT_SCHEMA", "STALE", "HeartbeatGate", "HeartbeatIngress", "HeartbeatRefused",
           "HeartbeatStore", "InMemoryHeartbeatStore", "MonitorHeartbeat", "heartbeat_alarm", "issue_heartbeat"]
