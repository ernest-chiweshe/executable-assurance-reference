"""Classify retained completion observations; never authorize or invoke an effect.

The observer's signed interval must describe completion, not the time at which
somebody later noticed a file. Its accuracy and custody need separate host
qualification. Synthetic observations remain synthetic in the retained record.
"""

from dataclasses import dataclass
import uuid

from assurance_reference.alerts import AlertUnavailable
from regulated_core.canonical import digest_hex
from regulated_core.clock import ClockReading
from regulated_core.signing import Signature


@dataclass(frozen=True)
class CompletionObservation:
    tenant_id: str
    permit_hash: str
    clock_domain: str
    earliest_completion_us: int
    latest_completion_us: int
    synthetic: bool

    def body(self):
        return {"schema": "executable-assurance/completion-observation/v1",
                **self.__dict__}


@dataclass(frozen=True)
class SignedCompletionObservation:
    observation: CompletionObservation
    signature: Signature


class TimingObservationRecorder:
    """An explicit host reporting port, separate from receiving authority.

    A signature establishes the configured observer's assertion, not physical
    timing accuracy. Even a BEFORE_EXPIRY observation is not a receiving receipt
    and never upgrades UNKNOWN to COMMITTED. Every record requires reconciliation.
    The local signed outbox does not establish delivery to an operator.
    """

    def __init__(self, *, journal, permit_key_ids, observer_key_ids):
        self.journal = journal
        self.permit_key_ids = frozenset(permit_key_ids)
        self.observer_key_ids = frozenset(observer_key_ids)
        if (not self.permit_key_ids or not self.observer_key_ids
                or self.permit_key_ids & self.observer_key_ids):
            raise ValueError("distinct explicit permit and observer signer sets are required")

    def record(self, signed_permit, signed_observation):
        p = signed_permit.permit
        event = signed_observation.observation
        trust = self.journal.trust
        if (signed_permit.signature.key_id not in self.permit_key_ids
                or not trust.verify(p.signed_body(), signed_permit.signature)):
            raise ValueError("permit signature is not authorized")
        if (signed_observation.signature.key_id not in self.observer_key_ids
                or not trust.verify(event.body(), signed_observation.signature)):
            raise ValueError("completion observer signature is not authorized")
        if event.tenant_id != p.tenant_id or event.permit_hash != digest_hex(p.signed_body()):
            raise ValueError("completion observation is not bound to this tenant and permit")
        if not p.clock_domain or event.clock_domain != p.clock_domain:
            raise ValueError("completion observation clock domain differs")
        ClockReading(event.clock_domain, event.earliest_completion_us)
        ClockReading(event.clock_domain, event.latest_completion_us)
        if (type(event.synthetic) is not bool
                or event.earliest_completion_us > event.latest_completion_us
                or event.earliest_completion_us < p.issued_at_us):
            raise ValueError("invalid completion interval or provenance")
        if event.earliest_completion_us >= p.expires_at_us:
            classification = "LATE"
        elif event.latest_completion_us < p.expires_at_us:
            classification = "BEFORE_EXPIRY"
        else:
            classification = "UNCERTAIN"
        alert_id = uuid.uuid4().hex
        payload = {
            "schema": "executable-assurance/timing-observation-alert/v1",
            "alert_id": alert_id, "tenant_id": p.tenant_id,
            "decision_hash": p.decision_record_hash, "permit_hash": event.permit_hash,
            "code": "SYNTHETIC_COMPLETION_" + classification if event.synthetic
                    else "OBSERVED_COMPLETION_" + classification,
            "classification": classification, "synthetic": event.synthetic,
            "observation": event.body(), "observation_signature": signed_observation.signature,
            "expires_at_us": p.expires_at_us, "authority_time_us": None,
            "outcome": "unknown", "requires_reconciliation": True,
            "effect_invoked": False,
        }
        try:
            signature = self.journal.signer.sign(payload)
            if not trust.verify(payload, signature):
                raise ValueError("timing alert signer is not trusted")
            self.journal.retain_signed(payload, signature)
        except Exception as exc:
            raise AlertUnavailable("signed timing observation was not confirmed durable") from exc
        return alert_id
