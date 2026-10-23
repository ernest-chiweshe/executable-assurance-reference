"""Authority-stamped, age-bounded evidence for the reference composition."""

from __future__ import annotations

from typing import Any

from regulated_core.clock import ClockError, read_clock
from regulated_core.persistence_pg import PostgresDecisionRecorder


class ReferenceDecisionRecorder(PostgresDecisionRecorder):
    """Keep the inherited storage format while tightening recording-time checks.

    The inherited append transaction holds its tenant advisory lock before calling
    _sign_entry. The predecessor check therefore survives recorder reconstruction
    and serializes competing writers. It does not establish a cluster-wide clock
    floor, physical UTC accuracy, or the time at which a policy was evaluated.
    """

    def __init__(self, *args: Any, max_record_age_us: int = 5_000_000, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.clock is None:
            raise ValueError("reference evidence requires an authority clock")
        if type(max_record_age_us) is not int or max_record_age_us <= 0:
            raise ValueError("record age bound must be a positive integer")
        self.max_record_age_us = max_record_age_us

    def _require_recent(self, record, connection) -> None:
        reading = read_clock(self.clock, connection=connection)
        age = reading.now_us - record.decided_at_us
        if not 0 <= age <= self.max_record_age_us:
            raise ClockError("recording time exceeds the configured evidence age bound")

    def _sign_entry(self, record, record_hash, prev, seq, *, connection=None):
        """Check age and the durable predecessor while the append lock is held."""
        if connection is None:
            raise ClockError("reference evidence requires the append transaction")
        self._require_recent(record, connection)
        row = connection.execute(
            "SELECT seq, entry_hash, envelope FROM regulated_decision_evidence_v1"
            " WHERE tenant = %s ORDER BY seq DESC LIMIT 1",
            (record.tenant_id,),
        ).fetchone()
        if row is not None:
            previous = self._checked(row, record.tenant_id)
            if previous.clock_domain != self.clock.domain:
                raise ClockError("evidence clock domain differs from the durable head")
            if previous.seq + 1 != seq or previous.chain_hash() != prev:
                raise ClockError("evidence predecessor changed during append")
            if record.decided_at_us < previous.record.decided_at_us:
                raise ClockError("recording time precedes the durable evidence head")
        elif seq != 0:
            raise ClockError("evidence predecessor is missing")
        envelope = super()._sign_entry(record, record_hash, prev, seq, connection=connection)
        self._require_recent(record, connection)
        return envelope
