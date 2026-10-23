"""A stored human review: authenticated requester, actual reviewer, exact artifact.

The host owns authentication and passes an EmissionContext bound to that caller.
This service never accepts a caller-named approver. The selected role is only a
query to the injected credential authority, whose signed receipt decides whether
the authenticated principal can grant. Storage and signing remain injected.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Protocol

from factory.projectos.regulated import EmissionContext

from .approval import (
    ApprovalCertificate, ApprovalError, ApprovalGrant, ApprovalRequest,
    ApprovalWorkflow, ApprovedDecision,
)
from .canonical import digest_hex
from .models import Actor, DecisionKind
from .identity_provider import CredentialError, CredentialReceipt
from .persistence_pg import decode_envelope
from .review_store import ReviewStore


from .approval_evidence import (
    ReviewError as ReviewError, _data as _data, _grant as _grant,
    _certificate as _certificate, _credential as _credential,
    verified_approvals as verified_approvals,
)


class ReviewMembershipEvidence(Protocol):
    """A host-configured issuer and verifier of token-free membership evidence."""

    def issue(self, context: EmissionContext, *, review_id: str, role: str,
              contract: dict[str, Any]) -> tuple[CredentialReceipt, dict[str, Any]]:
        """Authenticate the current browser request and attest its membership."""
        ...

    def validate(self, state: dict[str, Any]) -> None:
        """Verify every retained binding; raise CredentialError on refusal."""
        ...


def append_membership_grant(
    state: dict[str, Any], request: ApprovalRequest,
    prior: tuple[ApprovalGrant, ...], authority: ApprovalWorkflow,
    reviewer: Actor, receipt: CredentialReceipt, binding: dict[str, Any],
    evidence: ReviewMembershipEvidence, now_us: int,
) -> dict[str, Any]:
    """Append one signed membership grant to an already verified, locked review.

    The caller authenticates the immutable decision and existing grants before
    entering here. This function performs no I/O or authority lookup while the
    review writer holds its exclusive transaction lock.
    """
    if state.get("schema") != "regulated/review/v3":
        raise ReviewError("membership grant requires a retained v3 review")
    granted = authority.grant(request, reviewer, now_us, receipt=receipt)
    grants = [*prior, granted]
    certificate = None
    try:
        certificate = authority.finalize(request, grants, now_us)
    except ApprovalError as exc:
        if not str(exc).startswith(("quorum not met", "role groups not covered")):
            raise
    updated = {
        **state,
        "grants": [_data(grant) for grant in grants],
        "certificate": _data(certificate),
        "credential_receipts": [*state["credential_receipts"], _data(receipt)],
        "membership_bindings": [*state["membership_bindings"], binding],
    }
    try:
        evidence.validate(updated)
    except CredentialError as exc:
        raise ReviewError("membership grant lacks valid retained evidence") from exc
    return updated


class ApprovalExchange:
    """One gate's review workflow over an injected tenant-scoped store."""

    def __init__(self, gate: Any, store: ReviewStore, *,
                 membership_evidence: ReviewMembershipEvidence | None = None) -> None:
        self.gate, self.store = gate, store
        self._membership_evidence = membership_evidence
        if membership_evidence is not None and not callable(getattr(store, "transact_timed", None)):
            raise ValueError("membership reviews require a database-timed review writer")

    @staticmethod
    def _id(context: EmissionContext) -> str:
        if not all((context.tenant, context.vertical_name, context.project_id, context.action_id, context.nonce)):
            raise ReviewError("review requires tenant, vertical, project, action and nonce bindings")
        return "review:" + digest_hex([context.tenant, context.vertical_name, context.project_id,
                                      context.action_id, context.nonce])[:48]

    def _validated(
        self, state: Any, contract: dict[str, Any], context: EmissionContext, review_id: str,
    ) -> tuple[ApprovalRequest, Any, EmissionContext, tuple[ApprovalGrant, ...], ApprovalCertificate | None]:
        try:
            legacy_keys = {"schema", "review_id", "vertical_name", "project_id", "action_id", "nonce",
                           "envelope", "grants", "certificate", "credential_receipts"}
            if (not isinstance(state, dict)
                    or (state.get("schema"), set(state)) not in (
                        ("regulated/review/v1", legacy_keys),
                        ("regulated/review/v2", legacy_keys | {"review_producer_id"}),
                        ("regulated/review/v3", legacy_keys | {"review_producer_id", "membership_bindings"}),
                    ) or state["review_id"] != review_id):
                raise ReviewError("invalid stored review")
            is_membership = state["schema"] == "regulated/review/v3"
            if is_membership != (self._membership_evidence is not None):
                raise ReviewError("review membership evidence configuration differs from stored schema")
            if self._membership_evidence is not None:
                self._membership_evidence.validate(state)
            envelope = decode_envelope(state["envelope"])
            record = envelope.record
            if not self.gate._engine._recorder.verify_entry(envelope):
                raise ReviewError("review decision is not signed by the evidence authority")
            original = EmissionContext(
                tenant=record.tenant_id, actor_id=record.actor_id, now_us=record.decided_at_us,
                project_id=state["project_id"], vertical_name=state["vertical_name"],
                action_id=state["action_id"], nonce=state["nonce"],
                review_producer_id=state.get("review_producer_id", ""),
                retained_state=context.retained_state,  # Current server snapshot, not stored source authority.
            )
            if (original.review_producer_id != context.review_producer_id
                    or record.tenant_id != context.tenant or original.project_id != context.project_id
                    or original.vertical_name != context.vertical_name or self._id(original) != review_id
                    or record.assertion_id != f"{self.gate.VERTICAL}:{original.nonce}"
                    or record.correlation_id != f"{self.gate.VERTICAL}-{original.nonce}"
                    or record.action.action_id != self.gate.EMIT_ACTION
                    or record.action.destination != self.gate._destination(contract, original)):
                raise ReviewError("review does not bind this tenant, project, action and artifact")
            requirement = record.decision.approval
            if record.decision.kind is not DecisionKind.REQUIRE_APPROVAL or requirement is None:
                raise ReviewError("stored decision does not require human approval")
            request = self.gate._engine._approvals.open(
                request_id=review_id, requester_id=original.review_producer_id or record.actor_id, tenant_id=record.tenant_id,
                assertion_id=record.assertion_id, decision_record_id=record.record_id,
                decision_record_hash=envelope.record_hash, requirement=requirement, now_us=record.decided_at_us,
            )
            if not record.decided_at_us <= context.now_us < request.expires_at_us:
                raise ReviewError("review window expired or is in the future")
            grants, certificate = verified_approvals(self.gate._engine._approvals, state, envelope, request,
                                                     now_us=context.now_us)
            return request, envelope, original, grants, certificate
        except (TypeError, KeyError, CredentialError) as exc:
            raise ReviewError("invalid stored review data") from exc

    def requester(self, context: EmissionContext, review_id: str) -> str:
        """The execution identity that opened this stored review, read only from its evidence-signed decision.

        The review id must recompute from the stored tenant, vertical, project, action and nonce, and the stored
        tenant, vertical and project must be the caller's; a caller never supplies this identity (source review 3179)."""
        state = self.store.get(context.tenant, review_id)
        try:
            if not isinstance(state, dict) or state.get("review_id") != review_id:
                raise ReviewError("no stored review with this id")
            envelope = decode_envelope(state["envelope"])
            if not self.gate._engine._recorder.verify_entry(envelope):
                raise ReviewError("review decision is not signed by the evidence authority")
            record = envelope.record
            original = EmissionContext(tenant=record.tenant_id, actor_id=record.actor_id,
                                       project_id=state["project_id"], vertical_name=state["vertical_name"],
                                       action_id=state["action_id"], nonce=state["nonce"])
        except (TypeError, KeyError) as exc:
            raise ReviewError("invalid stored review data") from exc
        if (self._id(original) != review_id or record.tenant_id != context.tenant
                or original.project_id != context.project_id or original.vertical_name != context.vertical_name
                or not record.actor_id):
            raise ReviewError("review does not bind this tenant, project and action")
        return record.actor_id

    @staticmethod
    def _view(state: dict[str, Any], request: ApprovalRequest) -> dict[str, Any]:
        return {"review_id": request.request_id, "status": "approved" if state["certificate"] else "awaiting-review",
                "requester_id": request.requester_id, "opened_by_id": state["envelope"]["record"]["actor_id"],
                "reason": request.requirement.reason,
                "project_id": state["project_id"],
                "action_id": state["action_id"], "nonce": state["nonce"],
                "expires_at_us": request.expires_at_us,
                "required_role_groups": [sorted(group) for group in request.requirement.role_groups],
                "minimum_approvers": request.requirement.minimum_approvers,
                "approver_ids": [g["reviewer_id"] for g in state["grants"]],
                "decision_record_hash": request.decision_record_hash}

    def open(self, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        """Record the exact decision once before asking a human to review it."""
        review_id = self._id(context)
        if context.is_producer or context.actor_roles:
            raise ReviewError("review requester must be an authenticated human without self-supplied roles")
        existing = self.store.get(context.tenant, review_id)
        if existing is not None:
            request, _, original, _, _ = self._validated(existing, contract, context, review_id)
            if original.actor_id != context.actor_id:
                raise ReviewError("review action already belongs to a different requester")
            return self._view(existing, request)
        # Finish authority work before borrowing the review-store transaction:
        # the recorder may use the same bounded Postgres pool.
        assertion, action, _, policy_context = self.gate._build(contract, context)
        if not self.gate._engine._vtrust.authenticate(assertion):
            raise ReviewError("review verifications are untrusted")
        policy = self.gate._resolved_policy(assertion.content_type)
        decision = policy.evaluate(assertion, action, policy_context)
        envelope = self.gate._engine._recorder.record(assertion, action, policy_context, policy.ref, decision)
        if decision.kind is not DecisionKind.REQUIRE_APPROVAL:
            raise ReviewError(f"nothing to approve: decision is {decision.kind.value}")
        prepared = {"schema": "regulated/review/v2", "review_id": review_id,
                    "review_producer_id": context.review_producer_id,
                    "vertical_name": context.vertical_name, "project_id": context.project_id,
                    "action_id": context.action_id, "nonce": context.nonce,
                    "envelope": _data(envelope), "grants": [], "certificate": None, "credential_receipts": []}
        if self._membership_evidence is not None:
            prepared.update(schema="regulated/review/v3", membership_bindings=[])

        def create(old: dict[str, Any] | None) -> dict[str, Any]:
            if old is not None:
                _, _, original, _, _ = self._validated(old, contract, context, review_id)
                if original.actor_id != context.actor_id:
                    raise ReviewError("review action already belongs to a different requester")
                return old
            return prepared

        state = self.store.transact(context.tenant, review_id, create)
        request, _, _, _, _ = self._validated(state, contract, context, review_id)
        return self._view(state, request)

    def get(self, contract: dict[str, Any], context: EmissionContext, review_id: str) -> dict[str, Any]:
        """Return the verified review status for this entitled project."""
        state = self.store.get(context.tenant, review_id)
        request, _, _, _, _ = self._validated(state, contract, context, review_id)
        assert state is not None
        return self._view(state, request)

    def grant(self, contract: dict[str, Any], context: EmissionContext, review_id: str, role: str) -> dict[str, Any]:
        """Grant only as the authenticated caller after authoritative credential verification."""
        if ((self.gate._credverify is None and self._membership_evidence is None)
                or not self.gate._engine._approvals.requires_credentials):
            raise ReviewError("human review requires the configured credential authority")
        if context.is_producer:
            raise ReviewError("a producer cannot approve")

        snapshot = self.store.get(context.tenant, review_id)
        request, envelope, original, prior, certificate = self._validated(snapshot, contract, context, review_id)
        assert snapshot is not None
        if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
            return self._view(snapshot, request)
        if role not in set().union(*request.requirement.role_groups):
            raise ReviewError("role is not requested by this policy")
        # Recheck as the original requester, not as a more privileged reviewer.
        # Credential providers may also use the host pool; call them before the
        # review transaction and merge their signed grant under the lock below.
        assertion, action, _, policy_context = self.gate._build(contract, replace(original, now_us=context.now_us))
        if not self.gate._engine._vtrust.authenticate(assertion):
            raise ReviewError("current review verifications are untrusted")
        policy = self.gate._resolved_policy(assertion.content_type)
        decision = policy.evaluate(assertion, action, policy_context)
        current, _ = self.gate._engine._recorder.make_record(assertion, action, policy_context, policy.ref, decision)
        if replace(envelope.record, record_id=current.record_id, decided_at_us=current.decided_at_us) != current:
            raise ReviewError("the current decision differs from the requested review")
        authority = self.gate._engine._approvals
        binding = None
        try:
            if self._membership_evidence is None:
                receipt = self.gate._review_credential(context.actor_id, role, contract, context)
            else:
                receipt, binding = self._membership_evidence.issue(
                    replace(context, action_id=original.action_id, nonce=original.nonce),
                    review_id=review_id, role=role, contract=contract,
                )
            actor = Actor(context.actor_id, context.tenant, frozenset({role}))
            new_grant = (authority.grant(request, actor, context.now_us, receipt=receipt)
                         if self._membership_evidence is None else None)
        except (CredentialError, ApprovalError) as exc:
            raise ReviewError(str(exc)) from exc

        validation_time = context.now_us

        def approve_at(state: dict[str, Any] | None, now_us: int) -> dict[str, Any]:
            nonlocal validation_time
            validation_time = now_us
            timed_context = replace(context, now_us=now_us)
            request, latest, _, prior, certificate = self._validated(state, contract, timed_context, review_id)
            assert state is not None
            if latest.record_hash != envelope.record_hash:
                raise ReviewError("the stored decision changed while the grant was verified")
            if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
                return state
            if self._membership_evidence is not None:
                if binding is None:
                    raise ReviewError("membership grant lacks a signed binding")
                try:
                    return append_membership_grant(
                        state, request, prior, authority, actor, receipt, binding,
                        self._membership_evidence, now_us,
                    )
                except (CredentialError, ApprovalError) as exc:
                    raise ReviewError("membership grant was refused") from exc
            try:
                granted = new_grant or authority.grant(request, actor, now_us, receipt=receipt)
            except ApprovalError as exc:
                raise ReviewError(str(exc)) from exc
            grants = [*prior, granted]
            try:
                certificate = authority.finalize(request, grants, now_us)
            except ApprovalError as exc:
                if not str(exc).startswith(("quorum not met", "role groups not covered")):
                    raise
            updated = {**state, "grants": [_data(g) for g in grants], "certificate": _data(certificate),
                       "credential_receipts": [*state["credential_receipts"], _data(receipt)]}
            return updated

        if self._membership_evidence is None:
            state = self.store.transact(context.tenant, review_id,
                                        lambda old: approve_at(old, context.now_us))
        else:
            state = getattr(self.store, "transact_timed")(context.tenant, review_id, approve_at)
        request, _, _, _, _ = self._validated(state, contract, replace(context, now_us=validation_time), review_id)
        return self._view(state, request)

    def resolve(self, contract: dict[str, Any], context: EmissionContext, review_id: str) -> EmissionContext:
        """Resolve the original nonce and certificate without accepting another actor or action."""
        state = self.store.get(context.tenant, review_id)
        _, envelope, original, _, certificate = self._validated(state, contract, context, review_id)
        if certificate is None:
            raise ReviewError("human review has not reached the required quorum")
        if (context.actor_id != original.actor_id
                or (context.action_id and context.action_id != original.action_id)
                or (context.nonce and context.nonce != original.nonce)):
            raise ReviewError("release does not match the original requester and action")
        assert state is not None
        return replace(context, action_id=original.action_id, nonce=original.nonce,
                       approval=ApprovedDecision(certificate, envelope,
                                                 tuple(_credential(raw) for raw in state["credential_receipts"])))
