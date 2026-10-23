"""Owned lock-time decisions and fresh outcome recording for PostgreSQL."""

from dataclasses import replace
from copy import copy

from assurance_reference.alerts import AlertJournal
from assurance_reference.decision_transaction import locked_decision_transaction
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.governance_targets import require_governance_composition
from regulated_core.budget import UNBUDGETED
from regulated_core.clock import ClockError
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresDecisionRecorder
from regulated_core.canonical import digest_hex
from regulated_core.engine import RegulatedEngine, TargetAuthorization
from regulated_core.target import Outcome
from regulated_core.worm import WormUnavailable, anchor_evidence_chain


class ReferenceEngine(RegulatedEngine):
    """Bind PostgreSQL target decisions to their owned evidence transaction.

    Decision checks use lock-time authority; retention follows commit, and
    issuance and effects still evaluate current time. Other recorder kinds
    retain their existing local semantics without PostgreSQL qualification.
    """

    def __init__(self, *, alerts: AlertJournal, retention=None, retention_us=7 * 365 * 86_400_000_000,
                 **parameters):
        if not isinstance(alerts, AlertJournal):
            raise TypeError("a durable alert journal is required")
        recorder = parameters.get("recorder")
        if isinstance(recorder, PostgresDecisionRecorder) and not isinstance(recorder, ReferenceDecisionRecorder):
            raise TypeError("PostgreSQL reference composition requires ReferenceDecisionRecorder")
        self._alerts = alerts
        if type(retention_us) is not int or retention_us <= 0:
            raise ValueError("retention duration must be a positive integer")
        if retention is not None and not all(callable(getattr(retention, name, None))
                                             for name in ("anchor", "verify")):
            raise TypeError("retention requires anchor and verification operations")
        self._retention, self._retention_us = retention, retention_us
        super().__init__(**parameters)

    def for_policy(self, *, registry, preflight):
        """Preserve reference guards and shared services in a pack-version sibling.

        Copy the configured composition, including subclass qualification gates,
        rather than reconstructing a base engine that loses reference behavior.
        Only policy resolution and intended uses vary between these siblings.
        """
        sibling = copy(self)
        sibling._registry = registry
        sibling._preflight = preflight
        preflight.bind_clock(self.targets.clock)
        return sibling

    def authorize_for_target(self, *, ctx, **parameters):
        require_governance_composition(parameters.get("target"), self._budget)
        current = replace(ctx, now_us=self.targets.now_us())
        if parameters.get("retain_before_permit") is None and self._retention is not None:
            def retain():
                receipt = anchor_evidence_chain(self._retention, self._recorder, current.tenant_id,
                    retain_us=self._retention_us, now_us=self.targets.now_us())
                if not self._retention.verify(receipt):
                    raise WormUnavailable("anchored evidence did not verify; no permit is issued")
            parameters["retain_before_permit"] = retain
        return super().authorize_for_target(ctx=current, **parameters)

    def commit(self, authorization, output, target):
        require_governance_composition(target, self._budget)
        return super().commit(authorization, output, target)

    def _decision_now_us(self):
        scope = getattr(self, "_decision_scope", None)
        return scope.now_us() if scope is not None else super()._decision_now_us()

    def _verify_decision_capability(self, capability, **parameters):
        scope = getattr(self, "_decision_scope", None)
        if scope is not None:
            return scope.verify_preflight(self._preflight, capability, **parameters)
        return super()._verify_decision_capability(capability, **parameters)

    def _prepare_target_authorization(self, *, ctx, **parameters):
        if not isinstance(self._recorder, ReferenceDecisionRecorder):
            # Preserve local non-PostgreSQL compositions; they do not acquire
            # the reference PostgreSQL transaction qualification.
            return super()._prepare_target_authorization(ctx=ctx, **parameters)
        prepared = None
        try:
            with locked_decision_transaction(self._recorder, ctx.tenant_id) as scope:
                local = copy(self)
                local._decision_scope, local._recorder = scope, scope
                prepared = super(ReferenceEngine, local)._prepare_target_authorization(
                    ctx=scope.context(ctx), **parameters)
            return prepared
        except BaseException:
            # The decision transaction could fail at commit after reserve
            # succeeded. No permit has been issued, so release that reservation.
            if (prepared is not None and not isinstance(prepared, TargetAuthorization)
                    and prepared.reservation != UNBUDGETED):
                try:
                    self._budget.release(ctx.tenant_id, prepared.mission, prepared.reservation)
                except Exception:
                    pass  # Conservatively held if cleanup itself is unavailable.
            raise

    def record_refusal(self, *, ctx, **parameters):
        if not isinstance(self._recorder, ReferenceDecisionRecorder):
            return super().record_refusal(ctx=ctx, **parameters)
        with locked_decision_transaction(self._recorder, ctx.tenant_id) as scope:
            local = copy(self)
            local._recorder = scope
            return super(ReferenceEngine, local).record_refusal(ctx=scope.context(ctx), **parameters)

    def _record_outcome(self, authorization, result, *, reconciled):
        # Retain uncertainty before asking the potentially unavailable clock.
        # A failed append propagates; it cannot be reported as retained evidence.
        alerted = result.outcome is Outcome.UNKNOWN
        if alerted:
            self._alert(authorization, result, "TARGET_UNKNOWN")
        try:
            if isinstance(self._recorder, ReferenceDecisionRecorder):
                with locked_decision_transaction(self._recorder, authorization.ctx.tenant_id) as scope:
                    local = copy(self)
                    local._recorder = scope
                    current = replace(authorization, ctx=scope.context(authorization.ctx))
                    return super(ReferenceEngine, local)._record_outcome(current, result, reconciled=reconciled)
            current = replace(authorization,
                              ctx=replace(authorization.ctx, now_us=self.targets.now_us()))
            return super()._record_outcome(current, result, reconciled=reconciled)
        except Exception as exc:
            if not alerted:
                self._alert(authorization, result, "OUTCOME_RECORDING_FAILED")
            if isinstance(exc, ClockError):
                # Owned transaction clock reads preserve the public authority
                # error contract after the independent alert has been retained.
                raise EmissionError("authority clock unavailable") from exc
            raise

    def _alert(self, authorization, result, code):
        if authorization.permit is None:
            raise ValueError("outcome alerts require an exact permit reference")
        return self._alerts.append(
            tenant_id=authorization.ctx.tenant_id,
            decision_hash=authorization.envelope.record_hash,
            permit_hash=digest_hex(authorization.permit.permit.signed_body()),
            code=code,
            outcome=result.outcome.value,
        )
