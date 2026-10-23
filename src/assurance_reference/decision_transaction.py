"""Owned decision transactions for the reference PostgreSQL recorder.

This primitive does not issue authority. The caller must finish the context
successfully before retention or permit signing can observe its result.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from threading import get_ident

from psycopg.pq import TransactionStatus

from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core.clock import ClockError, read_clock


class DecisionTransaction:
    """A tenant-bound recorder view valid only on its owning thread and transaction."""

    def __init__(self, recorder, connection, tenant, reading):
        self._recorder, self._connection = recorder, connection
        self._tenant, self.reading = tenant, reading
        self._owner, self._active = get_ident(), True

    def _require_active(self):
        if (not self._active or get_ident() != self._owner
                or self._connection.info.transaction_status != TransactionStatus.INTRANS):
            raise ClockError("decision transaction is not active on its owning thread")

    def context(self, ctx):
        """Choose authority time before any policy evaluation or record construction."""
        self._require_active()
        if ctx.tenant_id != self._tenant:
            raise ClockError("decision context tenant differs from the locked tenant")
        return replace(ctx, now_us=self.reading.now_us)

    def now_us(self):
        self._require_active()
        return self.reading.now_us

    def verify_preflight(self, authority, cap, **parameters):
        self._require_active()
        if authority.clock is not self._recorder.clock:
            raise ClockError("preflight and decision transaction clocks differ")
        if parameters.get("tenant_id") != self._tenant:
            raise ClockError("preflight tenant differs from locked tenant")
        parameters.pop("now_us", None)
        return authority._verify_at_reading(cap, reading=self.reading, **parameters)

    def record(self, assertion, action, ctx, policy, decision):
        self._require_active()
        if ctx.tenant_id != self._tenant or ctx.now_us != self.reading.now_us:
            raise ClockError("decision context differs from the locked reading")
        record, record_hash = self._recorder.make_record(assertion, action, ctx, policy, decision)
        # The parent's hash, signature, domain, age and predecessor checks run
        # unchanged on this same connection; no prepared record is restamped.
        return self._recorder._append_on(self._connection, record, record_hash)

    def verify_entry(self, envelope):
        self._require_active()
        return self._recorder.verify_entry(envelope)


@contextmanager
def locked_decision_transaction(recorder, tenant):
    """Own a fresh READ COMMITTED transaction and sample time after its tenant lock."""
    if not isinstance(recorder, ReferenceDecisionRecorder):
        raise TypeError("locked decisions require the reference PostgreSQL recorder")
    if not isinstance(tenant, str) or not tenant or tenant != tenant.strip():
        raise ValueError("a nonempty exact tenant is required")
    with recorder._pool.connection() as connection:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise ClockError("decision transaction requires an idle owned connection")
        with connection.transaction():
            if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
                raise ClockError("decision transaction requires READ COMMITTED")
            connection.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
            connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                               ("regulated-evidence-v1:" + tenant,))
            reading = read_clock(recorder.clock, connection=connection)
            scope = DecisionTransaction(recorder, connection, tenant, reading)
            try:
                yield scope
            finally:
                scope._active = False
