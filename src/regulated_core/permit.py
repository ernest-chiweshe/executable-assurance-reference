"""Output-bound, single-use, expiring emission permits.

Even a fully approved decision cannot emit different bytes than were reviewed, cannot be
replayed, cannot outlive its window, and cannot cross a tenant. The permit binds the emission
to tenant + decision record + exact output digest + expiry + one-time nonce, signed by the
EMISSION authority (a distinct identity from decision/approval), and is the only path out.
"""
from __future__ import annotations

from collections.abc import Callable

import threading
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from .clock import ClockError, ClockReading, TrustedClock, read_clock, require_bounded_lifetime
from .evidence import SignedDecisionEnvelope
from .signing import Signature, Signer, TrustDirectory


class EmissionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class EmissionPermit:
    tenant_id: str
    decision_record_id: str
    decision_record_hash: str
    approval_ref: str
    assertion_id: str
    action_id: str
    output_digest: str
    expires_at_us: int
    nonce: str

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/permit/v1", **{k: getattr(self, k) for k in
                ("tenant_id", "decision_record_id", "decision_record_hash", "approval_ref",
                 "assertion_id", "action_id", "output_digest", "expires_at_us", "nonce")}}


@dataclass(frozen=True, slots=True)
class ClockedEmissionPermit(EmissionPermit):
    """Current permission binds its named source without changing historical v1."""

    clock_domain: str
    issued_at_us: int

    def signed_body(self) -> dict[str, Any]:
        body = EmissionPermit.signed_body(self)
        body.update(schema="regulated/permit/v2", clock_domain=self.clock_domain,
                    issued_at_us=self.issued_at_us)
        return body


@dataclass(frozen=True, slots=True)
class SignedEmissionPermit:
    permit: EmissionPermit
    signature: Signature


class PermitUseStore(Protocol):
    def consume(self, tenant_id: str, nonce: str) -> None: ...

    def used(self, tenant_id: str, nonce: str) -> bool:
        """Whether the nonce is already spent: a read for an early, recorded refusal, never a claim."""
        ...


class InMemoryPermitUseStore:
    def __init__(self) -> None:
        self._used: set[tuple[str, str]] = set()
        self._lock = threading.Lock()   # check-and-claim must be atomic, as the Postgres store's insert is

    def consume(self, tenant_id: str, nonce: str) -> None:
        key = (tenant_id, nonce)
        with self._lock:
            if key in self._used:
                raise EmissionError("permit already used (single-use)")
            self._used.add(key)

    def used(self, tenant_id: str, nonce: str) -> bool:
        with self._lock:
            return (tenant_id, nonce) in self._used


class EmissionAuthority:
    """Issues emission permits and, as the receiving authority, returns permitted bytes once.

    A named source is fixed during composition. Unbound instances are inert:
    neither issuance nor emission can use caller time or implicit wall time.
    """

    def __init__(self, emission_signer: Signer, trust: TrustDirectory, uses: PermitUseStore, *,
                 clock: TrustedClock | None = None) -> None:
        self._signer = emission_signer
        self._trust = trust
        self._uses = uses
        self._trusted_clock: TrustedClock | None = None
        self._clock_lock = threading.Lock()
        if clock is not None:
            self.bind_trusted_clock(clock)

    def bind_clock(self, clock: TrustedClock) -> None:
        """Bind an explicit named source; plain time callbacks are not accepted."""
        self.bind_trusted_clock(clock)

    def bind_trusted_clock(self, clock: TrustedClock) -> None:
        """Bind one named source across sibling engines without replacing it."""
        if not isinstance(clock, TrustedClock):
            raise ValueError("emission authority requires a named trusted clock")
        with self._clock_lock:
            if self._trusted_clock is not None and self._trusted_clock is not clock:
                raise ValueError("receiving emission authority already has a different clock")
            self._trusted_clock = clock

    def _reading(self) -> ClockReading:
        clock = self._trusted_clock
        if clock is None:
            raise EmissionError("emission authority requires a named trusted clock")
        try:
            return read_clock(clock)
        except ClockError as exc:
            raise EmissionError("emission authority clock unavailable") from exc

    def now_us(self) -> int:
        """Read the receiving authority's configured source, without fallback."""
        return self._reading().now_us

    def _require_live(self, permit: EmissionPermit) -> None:
        if not isinstance(permit, ClockedEmissionPermit):
            raise EmissionError("historical emission permit cannot authorize current output")
        try:
            self._reading().require_live(domain=permit.clock_domain, issued_at_us=permit.issued_at_us,
                                         expires_at_us=permit.expires_at_us)
            require_bounded_lifetime(self._trusted_clock, issued_at_us=permit.issued_at_us,
                                     expires_at_us=permit.expires_at_us)
        except ClockError as exc:
            raise EmissionError("emission permit clock domain or absolute window differs") from exc

    @property
    def signer(self) -> Signer:
        return self._signer

    @property
    def trust(self) -> TrustDirectory:
        return self._trust

    @property
    def uses(self) -> PermitUseStore:
        return self._uses

    def issue(self, envelope: SignedDecisionEnvelope, output: bytes, *, approval_ref: str,
              now_us: int, ttl_us: int, nonce: str, not_after_us: int | None = None) -> SignedEmissionPermit:
        """Sign a current permit without extending a supplied authority deadline.

        The compatibility timestamp is informational. Only the configured source
        selects issuance time, and the absolute ceiling can only shorten its TTL.
        """
        del now_us
        reading = self._reading()
        if envelope.clock_domain != reading.domain or envelope.record.decided_at_us > reading.now_us:
            raise EmissionError("decision and emission clock domain or time differs")
        if type(ttl_us) is not int or ttl_us <= 0:
            raise EmissionError("emission permit requires a positive integer lifetime")
        expiry = reading.now_us + ttl_us
        if not_after_us is not None:
            if type(not_after_us) is not int:
                raise EmissionError("emission deadline must be an integer")
            expiry = min(expiry, not_after_us)
        permit = ClockedEmissionPermit(
            tenant_id=envelope.record.tenant_id, decision_record_id=envelope.record.record_id,
            decision_record_hash=envelope.record_hash, approval_ref=approval_ref,
            assertion_id=envelope.record.assertion_id, action_id=envelope.record.action.action_id,
            output_digest=sha256(output).hexdigest(), expires_at_us=expiry, nonce=nonce,
            clock_domain=reading.domain, issued_at_us=reading.now_us,
        )
        self._require_live(permit)
        signed = SignedEmissionPermit(permit, self._signer.sign(permit.signed_body()))
        self._require_live(permit)
        return signed

    def emit(self, signed: SignedEmissionPermit, output: bytes, *, tenant_id: str, now_us: int | None = None,
             clock_us: Callable[[], int] | None = None) -> bytes:
        """Return the permitted bytes once, judged only on this authority's own clock (review 3126). The clock is read
        before the claim and again after the single-use claim, the last blocking step, so returning the bytes is the
        point of decision (review 3120): a permit that lapsed while it was being claimed is spent and returns nothing.

        `now_us` and `clock_us` are accepted from older callers and decide nothing: a presenter never chooses how old
        a permit is."""
        del now_us, clock_us
        p = signed.permit
        if signed.signature.key_id != self._signer.key_id or not self._trust.verify(p.signed_body(), signed.signature):
            raise EmissionError("permit signature invalid or untrusted")
        if p.tenant_id != tenant_id:
            raise EmissionError("permit tenant mismatch")
        self._require_live(p)
        if sha256(output).hexdigest() != p.output_digest:
            raise EmissionError("output does not match the authorized digest")
        self._uses.consume(tenant_id, p.nonce)   # single-use, raises on replay
        self._require_live(p)
        return output
