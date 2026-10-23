"""Compose the one sole-owner self-approval check at its three points (X-3).

* Grant: ``SoleOwnerReviewGate.grant_review`` checks a requester's own grant before
  the inherited exchange records it (frozen ``studio_owner_review_pg`` grant).
* Settlement: ``SoleOwnerReviewGate.authorize_release`` checks the retained grants
  before the permit is issued and bounds the request's ``not_after_us`` by any
  pending owner activation (frozen ``studio_owner_settlement_pg._approval_deadline``).
* Receiver: ``SoleOwnerReleaseAdmission.admit_release`` holds the shared roster lock
  in its own transaction across the inherited exact-session admission and repeats
  the check immediately before the effect (frozen ``regulated_studio_owner_pg``
  ``lock_current_on``).

All three call ``require_sole_owner_self_approval_on`` over the retained, locked
review; none accepts a request field as authority. Grants by anyone but the
requester pass through unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from typing import Any, Callable, Iterator

from assurance_reference.sole_owner_approval import require_sole_owner_self_approval_on, validate_self_approval_terms
from regulated_core.approval_evidence import ReviewError
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import decode_envelope
from regulated_core.review_store import PostgresReviewStore


class SoleOwnerApproval:
    """The shared check over the owner-roster reader login, the installed signed pack and the trusted clock."""

    def __init__(self, *, pool: Any, pack: Any, clock_us: Callable[[], int]) -> None:
        if not callable(getattr(pool, "connection", None)) or not callable(clock_us):
            raise TypeError("sole-owner approval requires the owner-roster reader pool and the trusted clock")
        validate_self_approval_terms(pack)
        self.pool, self.pack, self.clock_us = pool, pack, clock_us

    def _on(self, conn: Any, tenant: str, review_id: str, reviewers: Any = None) -> int | None:
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        state = PostgresReviewStore.read_locked_on(conn, tenant, review_id)
        if not isinstance(state, dict):
            raise CredentialError("the retained review is unavailable")
        try:
            record = decode_envelope(state["envelope"]).record
            named = reviewers if reviewers is not None else {g["reviewer_id"] for g in state["grants"]}
            producer = state.get("review_producer_id", "")
        except (KeyError, TypeError, ValueError) as error:
            raise CredentialError("the retained review is malformed") from error
        if record.tenant_id != tenant:
            raise CredentialError("the retained review belongs to another tenant")
        return require_sole_owner_self_approval_on(conn, pack=self.pack, record=record, reviewers=named,
                                                   producer=producer, clock_us=self.clock_us)

    def check(self, tenant: str, review_id: str, reviewers: Any = None) -> int | None:
        """One independent transaction: the grant and settlement points."""
        with self.pool.connection() as conn, conn.transaction():
            return self._on(conn, tenant, review_id, reviewers)

    @contextmanager
    def held(self, tenant: str, review_id: str) -> Iterator[Callable[[], int | None]]:
        """The receiving point: the roster lock and review lock stay held for the whole block."""
        with self.pool.connection() as conn, conn.transaction():
            self._on(conn, tenant, review_id)
            yield lambda: self._on(conn, tenant, review_id)


class SoleOwnerReviewGate:
    """A host pack gate whose grant and permit settlement enforce the sole-owner term."""

    def __init__(self, gate: Any, approval: SoleOwnerApproval) -> None:
        if not isinstance(approval, SoleOwnerApproval) or not callable(getattr(gate, "grant_review", None)):
            raise TypeError("sole-owner review requires the host gate and the shared check")
        self._gate, self._approval = gate, approval

    def __getattr__(self, name: str) -> Any:
        return getattr(self._gate, name)

    def grant_review(self, *, spec: Any, contract: dict, context: Any, review_id: str, role: str) -> dict:
        requester = self._gate._exchange().requester(context, review_id)
        if context.actor_id == requester:
            try:
                self._approval.check(context.tenant, review_id, {context.actor_id})
            except CredentialError as error:
                raise ReviewError(str(error)) from error
        return self._gate.grant_review(spec=spec, contract=contract, context=context, review_id=review_id, role=role)

    def authorize_release(self, **request: Any) -> Any:
        context = request["context"]
        if context.approval:
            deadline = self._approval.check(context.tenant, context.approval)
            if deadline is not None:
                bound = deadline if not context.not_after_us else min(context.not_after_us, deadline)
                request = {**request, "context": replace(context, not_after_us=bound)}
        return self._gate.authorize_release(**request)


class SoleOwnerReleaseAdmission:
    """Receiving-side credential verifier: the inherited exact-session admission plus the held sole-owner check."""

    def __init__(self, inner: Any, approval: SoleOwnerApproval) -> None:
        if not callable(getattr(inner, "admit_release", None)) or not isinstance(approval, SoleOwnerApproval):
            raise TypeError("sole-owner release admission requires session admission and the shared check")
        self._inner, self._approval = inner, approval

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    @contextmanager
    def admit_release(self, *, contract: Any, context: Any, authorization: Any) -> Iterator[Callable[[], None]]:
        reference = authorization.permit.permit.approval_ref
        with self._approval.held(context.tenant, reference) as current:
            with self._inner.admit_release(contract=contract, context=context,
                                           authorization=authorization) as before:
                def before_effect() -> None:
                    before()
                    try:
                        deadline = current()
                    except CredentialError as error:
                        raise EmissionError(str(error)) from error
                    if deadline is not None and self._approval.clock_us() >= deadline:
                        raise EmissionError("a pending owner activation ends this self-approval")
                yield before_effect


__all__ = ["SoleOwnerApproval", "SoleOwnerReleaseAdmission", "SoleOwnerReviewGate"]
