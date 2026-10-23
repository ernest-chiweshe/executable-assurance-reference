"""Signed, hash-chained decision evidence. Every outcome, including denials, is recorded.

Each entry is signed by the evidence authority and chained to its predecessor per tenant, so
removing or reordering an entry breaks the chain visibly. Record ids are derived from content
(deterministic, replayable), not random. This recorder is in memory; the injected-pool
adapter in persistence_pg provides append-only, FORCE-RLS Postgres storage. A host
may additionally anchor tenant chain heads through the WORM interface.
"""
from __future__ import annotations

from typing import Any

from dataclasses import dataclass

from .canonical import digest_hex
from .clock import ClockError, ClockReading, TrustedClock, read_clock
from .models import Action, Assertion, Decision, DecisionRecord, PolicyContext, PolicyRef
from .signing import Signature, Signer, TrustDirectory

GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class SignedDecisionEnvelope:
    record: DecisionRecord
    record_hash: str
    prev_hash: str
    seq: int
    signature: Signature

    @property
    def clock_domain(self) -> str:
        """Legacy evidence makes no clock-domain claim."""
        return ""

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/evidence/v1", "seq": self.seq, "prev_hash": self.prev_hash, "record_hash": self.record_hash}

    def chain_hash(self) -> str:
        """Preserve legacy chain bytes; qualified links also bind their domain."""
        body: dict[str, Any] = {"seq": self.seq, "prev_hash": self.prev_hash, "record_hash": self.record_hash}
        if self.clock_domain:
            body.update(schema="regulated/evidence-chain/v2", clock_domain=self.clock_domain)
        return digest_hex(body)


@dataclass(frozen=True, slots=True)
class ClockedDecisionEnvelope(SignedDecisionEnvelope):
    """Versioned envelope; adding it does not change legacy dataclass bytes."""

    domain: str

    def __post_init__(self) -> None:
        ClockReading(self.domain, self.record.decided_at_us)

    @property
    def clock_domain(self) -> str:
        return self.domain

    def signed_body(self) -> dict[str, Any]:
        body = SignedDecisionEnvelope.signed_body(self)
        body.update(schema="regulated/evidence/v2", clock_domain=self.domain)
        return body


class DecisionRecorder:
    def __init__(self, evidence_signer: Signer, trust: TrustDirectory, *,
                 clock: TrustedClock | None = None) -> None:
        self._signer = evidence_signer
        self._trust = trust
        self._clock = clock
        self._heads: dict[str, tuple[int, str]] = {}   # tenant -> (seq, head_hash)
        self._log: list[SignedDecisionEnvelope] = []

    @property
    def clock(self) -> TrustedClock | None:
        """Host-configured clock for newly signed evidence."""
        return self._clock

    def bind_clock(self, clock: TrustedClock) -> None:
        """Bind during composition without replacing a configured source."""
        if self._clock is not None and self._clock is not clock:
            raise ValueError("decision recorder is already bound to a different clock")
        self._clock = clock

    def _sign_entry(self, record: DecisionRecord, record_hash: str, prev: str, seq: int,
                    *, connection: Any = None) -> SignedDecisionEnvelope:
        """Sign on the writer's clock and recheck after a potentially slow signer."""
        if record_hash != digest_hex(record):
            raise ValueError("record hash does not match the decision")
        domain = ""
        if self._clock is not None:
            reading = read_clock(self._clock, connection=connection)
            if (type(record.decided_at_us) is not int
                    or not 0 <= record.decided_at_us <= reading.now_us):
                raise ClockError("decision time is outside the configured clock")
            domain = reading.domain
        body: dict[str, Any] = {"schema": "regulated/evidence/v1", "seq": seq,
                                "prev_hash": prev, "record_hash": record_hash}
        if domain:
            body.update(schema="regulated/evidence/v2", clock_domain=domain)
        signature = self._signer.sign(body)
        if self._clock is not None:
            reading = read_clock(self._clock, connection=connection)
            if reading.domain != domain or reading.now_us < record.decided_at_us:
                raise ClockError("decision clock changed during signing")
            return ClockedDecisionEnvelope(record, record_hash, prev, seq, signature, domain)
        return SignedDecisionEnvelope(record, record_hash, prev, seq, signature)

    def make_record(
        self, assertion: Assertion, action: Action, ctx: PolicyContext,
        policy: PolicyRef, decision: Decision,
    ) -> tuple[DecisionRecord, str]:
        """Pure: compute the decision record and its hash WITHOUT appending. Lets a caller bind
        an approval to the exact record the engine will emit under (deterministic id/hash)."""
        record_id = digest_hex({
            "assertion_digest": assertion.content_digest, "action": action,
            "correlation_id": ctx.correlation_id, "decided_at_us": ctx.now_us, "decision": decision,
        })[:40]
        record = DecisionRecord(
            record_id=record_id, tenant_id=ctx.tenant_id, assertion_id=assertion.assertion_id,
            assertion_digest=assertion.content_digest, action=action, actor_id=ctx.actor.actor_id,
            purpose=ctx.purpose, correlation_id=ctx.correlation_id, policy=policy,
            decision=decision, decided_at_us=ctx.now_us,
        )
        return record, digest_hex(record)

    def append(self, record: DecisionRecord, record_hash: str) -> SignedDecisionEnvelope:
        seq, prev = self._heads.get(record.tenant_id, (0, GENESIS))
        env = self._sign_entry(record, record_hash, prev, seq)
        self._heads[record.tenant_id] = (seq + 1, env.chain_hash())
        self._log.append(env)
        return env

    def record(
        self, assertion: Assertion, action: Action, ctx: PolicyContext,
        policy: PolicyRef, decision: Decision,
    ) -> SignedDecisionEnvelope:
        record, record_hash = self.make_record(assertion, action, ctx, policy, decision)
        return self.append(record, record_hash)

    def verify_chain(self, tenant_id: str) -> bool:
        prev, seq = GENESIS, 0
        for env in (e for e in self._log if e.record.tenant_id == tenant_id):
            if env.seq != seq or env.prev_hash != prev:
                return False
            if not verify_envelope(env, self._trust):
                return False
            prev = env.chain_hash()
            seq += 1
        return True

    def verify_entry(self, envelope: SignedDecisionEnvelope) -> bool:
        """Accept only an intact entry signed by this recorder's authority."""
        return (isinstance(envelope, SignedDecisionEnvelope)
                and envelope.clock_domain == (self._clock.domain if self._clock is not None else "")
                and envelope.signature.key_id == self._signer.key_id
                and verify_envelope(envelope, self._trust))

    def entries(self, tenant_id: str | None = None) -> tuple[SignedDecisionEnvelope, ...]:
        return tuple(e for e in self._log if tenant_id is None or e.record.tenant_id == tenant_id)


def verify_envelope(env: SignedDecisionEnvelope, trust: TrustDirectory) -> bool:
    return (
        env.record_hash == digest_hex(env.record)
        and trust.verify(env.signed_body(), env.signature)
    )
