"""Governed outbound delivery for the reference: the only way publication and messaging bytes leave (X-8).

Composes the verbatim receipt-bound HTTP transport (``factory.governed_http`` at 6bba989a) behind a budget-bound
egress governance target, registered as a supported reference governance factory:

* Every send needs a permit for the exact payload to the registered endpoint, under the mandatory durable budget.
* The mission budget is consumed in the same PostgreSQL transaction that durably records the delivery attempt,
  with authority re-checked last, all before any byte leaves (spend-at-dispatch). An HTTP send cannot share a database
  transaction with the destination, so the conservative order is: commit the claim and the spend, then send.
* A send with no bound destination receipt stays UNKNOWN, keeps its spent unit, and is resolved only by the
  destination's receipt API. Nothing here re-POSTs.
* A duplicate send is refused at egress (X-8, candidate 061): once a permit has been dispatched (its nonce is spent),
  presenting it again raises ``DuplicateSendRefused`` before any request, budget spend or outcome record. Its
  outcome is resolved only through the bound receipt (``reconcile``), never by sending again. A different nonce for
  the same change is a new, separately authorized send.

The request port is an explicit argument with no default, so a composition names its transport; the reference
tests inject a synthetic port and make no network call. Absence of an ungoverned path rests on the stated
assumption that agents receive no raw network or provider credentials (frozen X-8 coverage limit).
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from assurance_reference.governance_targets import _options, _register
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from factory.governed_http import DeliveryUnconfirmed, HttpEgressTransport, HttpEndpoint, RequestPort
from factory.governed_http_pg import PostgresHttpAttempts
from regulated_core.choke_points import (EGRESS_BOUNDARY, EGRESS_OPERATION, EGRESS_SCHEMA, _host_transaction_only,
                                         egress_change_check, idempotency_key)
from regulated_core.governance_targets import FinalCheckRefused, GovernanceTarget, GovernedChange
from regulated_core.governance_transaction import GovernanceTransactionCheck, run_governance_check
from regulated_core.budget import BudgetError
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import _tenant
from regulated_core.target import ABSENT, Outcome, SignedTargetPermit

_INSERT = (
    "INSERT INTO regulated_http_attempts_v1 "
    "(tenant,delivery_key,endpoint_id,endpoint_digest,request_digest,payload_digest,nonce) "
    "SELECT %s,%s,%s,%s,%s,%s,%s WHERE EXISTS ("
    "SELECT 1 FROM regulated_governance_events_v1 WHERE tenant=%s AND nonce=%s "
    "AND phase='prepared' AND body::jsonb->>'subject'=%s AND body::jsonb->>'prior_state'=%s "
    "AND body::jsonb->>'change_digest'=%s AND body::jsonb->>'operation'=%s) "
    "ON CONFLICT DO NOTHING RETURNING delivery_key")


class DuplicateSendRefused(Exception):
    """A permit that was already dispatched was presented for sending again; nothing was sent, spent or recorded."""


_DUPLICATE = ("duplicate send refused at egress: this permit was already dispatched;"
              " resolve its outcome by receipt, never by sending again")


class _RefusingClaims:
    """The target's permit-use store, where losing the nonce claim to an earlier or concurrent holder is a refusal."""

    def __init__(self, uses: Any) -> None:
        self._uses = uses

    def consume(self, tenant_id: str, nonce: str) -> None:
        try:
            self._uses.consume(tenant_id, nonce)
        except EmissionError as claimed:
            raise DuplicateSendRefused(_DUPLICATE) from claimed

    def __getattr__(self, name: str) -> Any:
        return getattr(self._uses, name)


class EgressGovernanceTarget(GovernanceTarget):
    """The recovered governance target at the egress boundary, where a duplicate send is refused (C060-PRE-R2).

    Every path by which the recovered target would answer a permit already received is a refusal here: the stored
    COMMITTED or UNKNOWN replay, before or after a lost claim, and the losing nonce claim itself. A permit whose earlier
    delivery was refused still answers FAILED (nothing is sent, and its held budget can settle). The outcome of a
    dispatched permit stays observable only through reconcile and the bound receipt."""

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self._uses = _RefusingClaims(self._uses)

    def _replayed(self, signed: SignedTargetPermit, output: bytes) -> Any:
        stored = super()._replayed(signed, output)
        if stored is not None and stored.outcome in (Outcome.COMMITTED, Outcome.UNKNOWN):
            raise DuplicateSendRefused(_DUPLICATE)
        return stored


class BudgetedHttpAttempts(PostgresHttpAttempts):
    """Record one attempt and consume its budget unit in one transaction, authority re-checked last."""

    def __init__(self, pool: Any, participant: Any) -> None:
        super().__init__(pool)
        self._participant = participant

    def record(self, attempt: Any) -> bool:
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, attempt.tenant_id)
            row = conn.execute(_INSERT, (
                attempt.tenant_id, attempt.key, attempt.endpoint_id, attempt.endpoint_digest,
                attempt.request_digest, attempt.payload_digest, attempt.nonce,
                attempt.tenant_id, attempt.nonce, attempt.endpoint_id, attempt.endpoint_digest,
                attempt.request_digest, EGRESS_OPERATION)).fetchone()
            if row is None:
                held = conn.execute("SELECT 1 FROM regulated_http_attempts_v1 WHERE tenant=%s AND delivery_key=%s",
                                    (attempt.tenant_id, attempt.key)).fetchone()
                if held is not None:
                    # An earlier attempt may have reached the destination: never send again, resolve by receipt.
                    raise DeliveryUnconfirmed("an attempt with this delivery key is already recorded")
                raise FinalCheckRefused("no matching prepared governance event; nothing was sent")
            # Consume the unit and re-check authority last, inside the transaction that retains the attempt. A refusal
            # here rolls back the attempt and the spend together: nothing was sent.
            try:
                run_governance_check(self._participant, conn)
            except (BudgetError, EmissionError, ValueError) as refused:
                raise FinalCheckRefused(str(refused)) from refused
        return True


class _BudgetedTransport:
    """The egress transport the target calls; it builds the verbatim HTTP transport per send."""

    def __init__(self, endpoint: HttpEndpoint, pool: Any, request: RequestPort) -> None:
        self._endpoint, self._pool, self._request = endpoint, pool, request

    def _plain(self) -> HttpEgressTransport:
        return HttpEgressTransport(self._endpoint, PostgresHttpAttempts(self._pool), self._request)

    def endpoint(self, tenant_id: str, endpoint_id: str) -> str:
        return self._plain().endpoint(tenant_id, endpoint_id)

    def send(self, change: GovernedChange, key: str) -> None:
        participant = change.final_check
        if not isinstance(participant, GovernanceTransactionCheck):
            raise FinalCheckRefused("reference egress requires the durable budget participant")
        # The verbatim transport re-checks authority before recording and again before the request; give it the
        # connection-free authority check, and spend the budget where the attempt is recorded.
        inner = HttpEgressTransport(self._endpoint, BudgetedHttpAttempts(self._pool, participant), self._request)
        inner.send(replace(change, final_check=participant.final_check), key)

    def status(self, tenant_id: str, key: str) -> Outcome:
        return self._plain().status(tenant_id, key)


def egress_delivery_target(endpoint: HttpEndpoint, *, pool: Any, request: RequestPort, budget: Any,
                           authority: Any, uses: Any, log: Any) -> GovernanceTarget:
    """The supported reference egress factory: the core egress target's contract, under the mandatory budget."""
    if not isinstance(endpoint, HttpEndpoint):
        raise TypeError("reference egress requires a registered receipt-capable HTTP endpoint")
    if not callable(request):
        raise TypeError("reference egress requires an explicit request port")
    if not isinstance(log, TenantFencedGovernanceLog) or log.tenant != endpoint.tenant_id:
        # B-F7b: an egress scope is tenant-scoped; its fences stay in the tenant-isolated table.
        raise TypeError("reference egress requires the endpoint tenant's fenced governance log")
    transport = _BudgetedTransport(endpoint, pool, request)

    def send(change: GovernedChange) -> None:
        if change.approved_prior == ABSENT:
            raise FinalCheckRefused("the endpoint is not registered; nothing was sent")
        transport.send(change, idempotency_key(change.tenant_id, change.operation, change.nonce, change.change_digest))

    def receipt(tenant: str, operation: str, nonce: str, change_digest: str) -> Outcome:
        return transport.status(tenant, idempotency_key(tenant, operation, nonce, change_digest))

    options = _options(budget, {})
    target = EgressGovernanceTarget(
        tenant_id=endpoint.tenant_id, kind=EGRESS_BOUNDARY, subject=endpoint.endpoint_id, authority=authority,
        uses=uses, state=lambda: transport.endpoint(endpoint.tenant_id, endpoint.endpoint_id),
        apply=_host_transaction_only, log=log, operation_name=EGRESS_OPERATION, transact=send,
        scope=f"{EGRESS_BOUNDARY}:{endpoint.tenant_id}:{endpoint.endpoint_id}", receipt=receipt,
        boundary=EGRESS_BOUNDARY, schema=EGRESS_SCHEMA, validate=egress_change_check(endpoint.max_payload_bytes),
        **options)
    return _register(target, budget)


__all__ = ["BudgetedHttpAttempts", "DuplicateSendRefused", "EgressGovernanceTarget", "egress_delivery_target"]
