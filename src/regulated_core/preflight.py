"""Before generation: intended-use registry and risk tier, issued as a signed capability.

The engine verifies this capability on the emission path. The preflight authority
signs it, and verification resolves the signer through the trust directory.
"""
from __future__ import annotations

from typing import Any

from dataclasses import dataclass
import threading

from .clock import ClockError, TrustedClock, read_clock
from .signing import Signature, Signer, TrustDirectory


class PreflightError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class IntendedUse:
    vertical: str
    action_id: str
    max_risk_tier: int          # 1 (low) .. 4 (highest)


@dataclass(frozen=True, slots=True)
class GenerationCapability:
    tenant_id: str
    vertical: str
    action_id: str
    risk_tier: int
    correlation_id: str
    expires_at_us: int
    nonce: str
    signature: Signature
    clock_domain: str = ""
    issued_at_us: int = 0

    def signed_body(self) -> dict[str, Any]:
        body = {"schema": "regulated/capability/v1", **{k: getattr(self, k) for k in
                ("tenant_id", "vertical", "action_id", "risk_tier", "correlation_id", "expires_at_us", "nonce")}}
        if self.clock_domain:
            body.update(schema="regulated/capability/v2", clock_domain=self.clock_domain,
                        issued_at_us=self.issued_at_us)
        return body


class IntendedUseRegistry:
    def __init__(self) -> None:
        self._allowed: dict[tuple[str, str], IntendedUse] = {}

    def declare(self, use: IntendedUse) -> None:
        self._allowed[(use.vertical, use.action_id)] = use

    def get(self, vertical: str, action_id: str) -> IntendedUse | None:
        return self._allowed.get((vertical, action_id))


class PreflightAuthority:
    """Issue and accept current capabilities only after named-clock composition.

    An unbound instance is inert assembly state. Historical capability bodies
    remain verifiable as records, but cannot authorize new generation.
    """

    def __init__(self, signer: Signer, registry: IntendedUseRegistry, trust: TrustDirectory,
                 *, clock: TrustedClock | None = None) -> None:
        self._signer = signer
        self._registry = registry
        self._trust = trust
        self._clock: TrustedClock | None = None
        self._clock_lock = threading.Lock()
        if clock is not None:
            self.bind_clock(clock)

    @property
    def clock(self) -> TrustedClock | None:
        """The host-owned issuance and verification clock, if qualified."""
        return self._clock

    def bind_clock(self, clock: TrustedClock) -> None:
        """Bind once during host composition; never replace a different source."""
        if not isinstance(clock, TrustedClock):
            raise ValueError("preflight authority requires a named trusted clock")
        with self._clock_lock:
            if self._clock is not None and self._clock is not clock:
                raise ValueError("preflight authority is already bound to a different clock")
            self._clock = clock

    def for_uses(self, uses: IntendedUseRegistry) -> PreflightAuthority:
        """The same signing identity and trust, over another set of declared intended uses."""
        return PreflightAuthority(self._signer, uses, self._trust, clock=self._clock)

    def authorize(self, *, tenant_id: str, vertical: str, action_id: str, risk_tier: int,
                  correlation_id: str, now_us: int, ttl_us: int, nonce: str,
                  connection: Any = None) -> GenerationCapability:
        clock = self._clock
        if clock is None:
            raise PreflightError("preflight authority requires a named trusted clock")
        use = self._registry.get(vertical, action_id)
        if use is None:
            raise PreflightError(f"intended use not declared: {vertical}/{action_id}")
        if risk_tier > use.max_risk_tier:
            raise PreflightError(f"risk tier {risk_tier} exceeds declared max {use.max_risk_tier}")
        if use.max_risk_tier >= 4:
            # A tier-4 use is classified by its declaration, never by the caller (review 3103): its capability is always
            # issued at the declared tier, so no request for a lower tier can produce one that skips tier-4 controls.
            risk_tier = use.max_risk_tier
        if type(ttl_us) is not int or ttl_us <= 0:
            raise PreflightError("capability requires a positive integer lifetime")
        try:
            reading = read_clock(clock, connection=connection)
        except ClockError as exc:
            raise PreflightError("capability clock unavailable") from exc
        now_us = reading.now_us
        domain = reading.domain
        body = {"schema": "regulated/capability/v2", "tenant_id": tenant_id, "vertical": vertical,
                "action_id": action_id, "risk_tier": risk_tier, "correlation_id": correlation_id,
                "expires_at_us": now_us + ttl_us, "nonce": nonce,
                "clock_domain": domain, "issued_at_us": now_us}
        capability = GenerationCapability(
            tenant_id, vertical, action_id, risk_tier, correlation_id,
            now_us + ttl_us, nonce, self._signer.sign(body), domain, now_us)
        try:
            read_clock(clock, connection=connection).require_live(
                domain=domain, issued_at_us=now_us, expires_at_us=capability.expires_at_us)
        except ClockError as exc:
            raise PreflightError("capability clock changed or lifetime elapsed during signing") from exc
        return capability

    def declared_tier(self, vertical: str, action_id: str) -> int | None:
        """The consequence tier the intended use declares, the authoritative classification of the action."""
        use = self._registry.get(vertical, action_id)
        return use.max_risk_tier if use is not None else None

    def verify(self, cap: GenerationCapability, *, tenant_id: str, vertical: str, action_id: str,
               correlation_id: str, now_us: int, connection: Any = None) -> bool:
        clock = self._clock
        if clock is None or not cap.clock_domain:
            return False
        try:
            reading = read_clock(clock, connection=connection)
        except ClockError:
            return False
        return self._verify_at_reading(cap, tenant_id=tenant_id, vertical=vertical,
            action_id=action_id, correlation_id=correlation_id, reading=reading)

    def _verify_at_reading(self, cap, *, tenant_id, vertical, action_id, correlation_id, reading):
        """Internal host composition: evaluate an already-owned decision reading.

        Public verify always samples the configured clock. A transaction owner
        must establish the reading and check its lifecycle before calling here.
        """
        if self._clock is None or reading.domain != self._clock.domain or not cap.clock_domain:
            return False
        try:
            reading.require_live(domain=cap.clock_domain, issued_at_us=cap.issued_at_us,
                                 expires_at_us=cap.expires_at_us)
            now_us = reading.now_us
        except ClockError:
            return False
        return (
            cap.tenant_id == tenant_id and cap.vertical == vertical and cap.action_id == action_id
            and cap.correlation_id == correlation_id and now_us < cap.expires_at_us
            and cap.signature.key_id == self._signer.key_id and self._trust.verify(cap.signed_body(), cap.signature)
        )
