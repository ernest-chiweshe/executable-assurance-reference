"""Keep the original pack gate, with current-time Education review grants.

The original exchange fixes grant time before credential lookup. Scoped session
credentials are verified at current authority time, so grants must instead use
fresh time after that lookup, while merging the retained review under its lock.
No original module or approval verification rule is changed.
"""

from dataclasses import replace

from regulated_core.approval import ApprovalError
from regulated_core.approval_exchange import ApprovalExchange
from regulated_core.approval_evidence import ReviewError, _data
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Actor


class _CurrentEducationExchange(ApprovalExchange):
    def grant(self, contract, context, review_id, role):
        credential = self.gate._credverify
        if (credential is None or self._membership_evidence is not None
                or not self.gate._engine._approvals.requires_credentials):
            raise ReviewError("scoped Education review requires its configured credential authority")
        if context.is_producer:
            raise ReviewError("a producer cannot approve")
        context = credential._current_context(context)
        snapshot = self.store.get(context.tenant, review_id)
        request, envelope, original, prior, certificate = self._validated(
            snapshot, contract, context, review_id)
        if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
            return self._view(snapshot, request)
        if role not in set().union(*request.requirement.role_groups):
            raise ReviewError("role is not requested by this policy")
        assertion, action, _, policy_context = self.gate._build(
            contract, replace(original, now_us=credential.sessions.clock.now_us()))
        if not self.gate._engine._vtrust.authenticate(assertion):
            raise ReviewError("current review verifications are untrusted")
        policy = self.gate._resolved_policy(assertion.content_type)
        decision = policy.evaluate(assertion, action, policy_context)
        current, _ = self.gate._engine._recorder.make_record(
            assertion, action, policy_context, policy.ref, decision)
        if replace(envelope.record, record_id=current.record_id,
                   decided_at_us=current.decided_at_us) != current:
            raise ReviewError("the current decision differs from the requested review")
        receipt = self.gate._review_credential(context.actor_id, role, contract, context)
        # The caller holds lifecycle/source/reviewer locks through the merge.
        # Resolve authority before the review transaction: the original PG
        # lifecycle and review stores share one session-bound connection.
        credential.validate_review(receipt, contract=contract,
                                   context=credential._current_context(context))
        authority = self.gate._engine._approvals
        actor = Actor(context.actor_id, context.tenant, frozenset({role}))

        def approve(state, now):
            # Use the review store's database time after acquiring its lock;
            # no connection is borrowed while that transaction is active.
            fresh = replace(context, now_us=now)
            request, latest, _, prior, certificate = self._validated(state, contract, fresh, review_id)
            if latest.record_hash != envelope.record_hash:
                raise ReviewError("the stored decision changed while the grant was verified")
            if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
                return state
            # Authority locks remain held. Fresh time checks expiry without
            # backdating or replacing the already signed credential receipt.
            granted = authority.grant(request, actor, now, receipt=receipt)
            grants = [*prior, granted]
            try:
                certificate = authority.finalize(request, grants, now)
            except ApprovalError as error:
                if not str(error).startswith(("quorum not met", "role groups not covered")):
                    raise
            return {**state, "grants": [_data(g) for g in grants], "certificate": _data(certificate),
                    "credential_receipts": [*state["credential_receipts"], _data(receipt)]}

        state = self.store.transact_timed(context.tenant, review_id, approve)
        request, _, _, _, _ = self._validated(state, contract, credential._current_context(context), review_id)
        return self._view(state, request)


class EducationGate:
    """Delegate every release operation to the intact composed reference gate."""

    def __init__(self, gate):
        from assurance_reference.education_release_authority import EducationReleaseAuthority
        if (not isinstance(gate._credverify, EducationReleaseAuthority)
                or gate.source_reviews is not gate._credverify.source_reviews
                or gate._credverify._receiving_gate is None
                or gate._credverify._receiving_gate[0] is not gate):
            raise TypeError("Education facade requires the complete scoped authority composition")
        self._gate = gate

    def __getattr__(self, name):
        return getattr(self._gate, name)

    def _current_call(self, method, request):
        gate = self._gate
        context = gate._credverify._current_context(request["context"])
        # Stamp after acquiring potentially blocking authority locks. The
        # original nested operation reuses them and keeps the five-second
        # evidence-age guard intact; waiting does not backdate a new decision.
        with gate._operation_guard(request["contract"], context,
                                   writer=method == "confirm_source_review") as record:
            reason = gate._refusal(record, context, request["spec"])
            if reason:
                raise ReviewError(reason)
            context = gate._credverify._current_context(context)
            return getattr(gate, method)(**{**request, "context": context})

    def open_review(self, **request):
        return self._current_call("open_review", request)

    def get_review(self, **request):
        return self._current_call("get_review", request)

    def resolve_review_context(self, **request):
        return self._current_call("resolve_review_context", request)

    def get_source_review(self, **request):
        return self._current_call("get_source_review", request)

    def confirm_source_review(self, **request):
        return self._current_call("confirm_source_review", request)

    def grant_review(self, *, spec, contract, context, review_id, role):
        gate = self._gate
        try:
            context = gate._credverify._current_context(context)
            gate._review_scope(spec, context)
            with gate._operation_guard(contract, context) as record:
                reason = gate._refusal(record, context, spec)
                if reason:
                    raise ReviewError(reason)
                with gate._credverify.review_guard(contract=contract, context=context, actors=(context.actor_id,)):
                    return _CurrentEducationExchange(gate, gate._review_store).grant(
                        contract, context, review_id, role)
        except (CredentialError, ApprovalError) as error:
            raise ReviewError(str(error)) from error
