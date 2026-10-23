"""The neutral facade for delegating a project's mission: propose a root, have humans review it, admit it.

Paper A section 4.2; docs/ARCHITECTURE-OF-RECORD/08 row A08 (review 3224, 3227, 3229). The core
already decides and admits a delegation root (`RegulatedEngine.record_delegation_proposal`,
`admit_delegation_root`), but only from core objects: an Assertion, an Action carrying the proposal and a
PolicyContext. A host must never construct those or touch a signer. This exchange lets a host drive the whole
lifecycle with only what it legitimately holds: the project's governed contract, the AUTHENTICATED EmissionContext of
the caller, and plain parameters.

The lifecycle, each step durable in the same tenant-scoped review store as a release review:

1. **Propose** (`open`). The session owner (the authenticated actor, never a caller-named subject) proposes to
   delegate this project's release. The exchange builds the decision from the contract exactly as a release review
   does, adds a `DelegationProposal` (the owner as root subject, this project's release action, the exact targets,
   the project's release mission, a lifetime, an admission deadline and the tenant's revocation epoch, all taken on
   the engine's trusted clock), and records it through the engine, which requires a signed, budgeted policy that asks
   for human approval. Nothing is admitted.
2. **Review** (`grant`). Other authenticated humans grant through the configured credential authority, exactly like
   a release review: the decision is re-derived from the current contract and must still be the one recorded; the
   requester can never approve their own delegation (the approval workflow refuses it).
3. **Admit** (`admit`). Only the owner who proposed it, and only once the certificate stands, admits the root through
   the engine, which re-checks the policy in force, the revocation epoch, the deadline and the approval on its own
   clock. The root's digest is kept with the review; admitting again returns the same root.
4. **Look up** (`root`). A verified reference to the admitted root: the stored grant must verify through the
   delegation authority and must have been admitted by exactly this review's decision. It carries the narrowed
   issuance metadata a child may narrow within (subject, operations, targets, mission, expiry, delegability).

What the host then does with the root (issuing a fresh child to an executor through its issuance door, binding a
project to it) is the host's; this module never issues children and never converts an ordinary project into a
delegate.
"""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from factory.projectos.regulated import EmissionContext

from .approval import ApprovalCertificate, ApprovalError, ApprovalGrant, ApprovalRequest
from .approval_exchange import ReviewError, _credential, _data, verified_approvals
from .canonical import digest_hex
from .delegation import PROPOSAL_FIELD, DelegationError, DelegationProposal, delegation_proposal_of
from .identity_provider import CredentialError
from .models import Actor, DecisionKind
from .persistence_pg import decode_envelope
from .review_store import ReviewStore

SCHEMA = "regulated/delegation-review/v1"
HOUR_US = 3_600 * 1_000_000
#: The longest root a proposal may ask for, and the longest it may wait to be admitted. A deployment's policy budget
#: still bounds what the root may spend; these bound how long an approval can stay live.
MAX_ROOT_LIFETIME_US = 7 * 24 * HOUR_US
MAX_ADMISSION_WAIT_US = 24 * HOUR_US
_KEYS = {"schema", "review_id", "vertical_name", "project_id", "action_id", "nonce", "review_producer_id",
         "envelope", "grants", "certificate", "credential_receipts", "root_digest"}


def _without_proposal(destination: str) -> Any:
    named = json.loads(destination)
    if not isinstance(named, dict):
        raise ReviewError("the delegation decision has no structured destination")
    return {key: value for key, value in named.items() if key != PROPOSAL_FIELD}


class DelegationRootExchange:
    """One regulated gate's delegation-root review workflow over the same injected review store."""

    def __init__(self, gate: Any, store: ReviewStore) -> None:
        self.gate, self.store = gate, store

    @property
    def _engine(self) -> Any:
        return self.gate._engine

    @staticmethod
    def _id(context: EmissionContext) -> str:
        if not all((context.tenant, context.vertical_name, context.project_id, context.action_id, context.nonce)):
            raise ReviewError("a delegation review requires tenant, vertical, project, action and nonce bindings")
        return "delegation-review:" + digest_hex(["delegation-root", context.tenant, context.vertical_name,
                                                  context.project_id, context.nonce])[:48]

    def _now(self) -> int:
        now: int = self._engine.targets.now_us()
        return now

    # --- verification of a stored review ---------------------------------------------------------------------------

    def _validated(self, state: Any, contract: dict[str, Any], context: EmissionContext, review_id: str) -> tuple[
            ApprovalRequest, Any, EmissionContext, DelegationProposal, tuple[ApprovalGrant, ...],
            ApprovalCertificate | None, int]:
        now = self._now()
        try:
            if not isinstance(state, dict) or state.get("schema") != SCHEMA or set(state) != _KEYS \
                    or state["review_id"] != review_id:
                raise ReviewError("no valid stored delegation review with this id")
            envelope = decode_envelope(state["envelope"])
            record = envelope.record
            if not self._engine._recorder.verify_entry(envelope):
                raise ReviewError("the delegation decision is not signed by the evidence authority")
            original = EmissionContext(tenant=record.tenant_id, actor_id=record.actor_id,
                                       now_us=record.decided_at_us, project_id=state["project_id"],
                                       vertical_name=state["vertical_name"], action_id=state["action_id"],
                                       nonce=state["nonce"], review_producer_id=state["review_producer_id"],
                                       retained_state=context.retained_state)
            proposal = delegation_proposal_of(json.loads(record.action.destination).get(PROPOSAL_FIELD))
            # The host derives the nonce (and names the action) from what it trusts, e.g. the immutable project
            # instance, so a caller's context must carry EXACTLY the stored ones: a project recreated under the same
            # name derives a different nonce and cannot reuse an old root review (review 3237).
            if (proposal is None or record.tenant_id != context.tenant
                    or context.nonce != original.nonce or context.action_id != original.action_id
                    or original.review_producer_id != context.review_producer_id
                    or original.project_id != context.project_id or original.vertical_name != context.vertical_name
                    or self._id(original) != review_id
                    or record.assertion_id != f"{self.gate.VERTICAL}:{original.nonce}"
                    or record.action.action_id != self.gate.EMIT_ACTION
                    or proposal.subject != record.actor_id
                    or _without_proposal(record.action.destination)
                    != json.loads(self.gate._destination(contract, original))):
                raise ReviewError("the delegation review does not bind this tenant, project, owner and artifact")
            requirement = record.decision.approval
            if record.decision.kind is not DecisionKind.REQUIRE_APPROVAL or requirement is None:
                raise ReviewError("the stored delegation decision does not require human approval")
            request = self._engine._approvals.open(
                request_id=review_id, requester_id=record.actor_id, tenant_id=record.tenant_id,
                assertion_id=record.assertion_id, decision_record_id=record.record_id,
                decision_record_hash=envelope.record_hash, requirement=requirement, now_us=record.decided_at_us)
            grants, certificate = verified_approvals(self._engine._approvals, state, envelope, request, now_us=now)
            return request, envelope, original, proposal, grants, certificate, now
        except (TypeError, KeyError, ValueError, DelegationError) as exc:
            if isinstance(exc, ReviewError):
                raise
            raise ReviewError("invalid stored delegation review data") from exc

    @staticmethod
    def _view(state: dict[str, Any], request: ApprovalRequest, proposal: DelegationProposal) -> dict[str, Any]:
        status = "admitted" if state["root_digest"] else "approved" if state["certificate"] else "awaiting-review"
        return {"delegation_review_id": request.request_id, "status": status,
                "owner_id": request.requester_id, "project_id": state["project_id"],
                "action_id": state["action_id"], "nonce": state["nonce"],
                "vertical_name": state["vertical_name"], "reason": request.requirement.reason,
                "review_expires_at_us": request.expires_at_us,
                "required_role_groups": [sorted(group) for group in request.requirement.role_groups],
                "minimum_approvers": request.requirement.minimum_approvers,
                "approver_ids": [g["reviewer_id"] for g in state["grants"]],
                "decision_record_hash": request.decision_record_hash,
                "proposal": {"subject": proposal.subject, "operations": list(proposal.operations),
                             "targets": list(proposal.targets), "root_mission": proposal.root_mission,
                             "delegable": proposal.delegable, "expires_at_us": proposal.expires_at_us,
                             "admit_by_us": proposal.admit_by_us},
                "root_digest": state["root_digest"]}

    # --- the lifecycle ---------------------------------------------------------------------------------------------

    def open(self, contract: dict[str, Any], context: EmissionContext, *, destinations: tuple[str, ...],
             expires_in_us: int, admit_within_us: int, delegable: bool) -> dict[str, Any]:
        """Record the owner's proposal to delegate this project's release, once, for humans to review."""
        if context.is_producer or context.actor_roles or not context.actor_id.strip():
            raise ReviewError("only an authenticated human owner without self-supplied roles proposes delegation")
        if (type(expires_in_us) is not int or not 0 < expires_in_us <= MAX_ROOT_LIFETIME_US
                or type(admit_within_us) is not int or not 0 < admit_within_us <= min(expires_in_us,
                                                                                       MAX_ADMISSION_WAIT_US)
                or type(delegable) is not bool):
            raise ReviewError("a delegation needs a bounded lifetime and an admission deadline within it")
        if not destinations or any(not isinstance(d, str) or not d.strip() for d in destinations):
            raise ReviewError("a delegation names at least one exact destination")
        review_id = self._id(context)
        existing = self.store.get(context.tenant, review_id)
        if existing is not None:
            request, _, original, proposal, _, _, _ = self._validated(existing, contract, context, review_id)
            if original.actor_id != context.actor_id:
                raise ReviewError("this delegation proposal belongs to a different owner")
            return self._view(existing, request, proposal)
        mission = contract.get("release_mission")
        if not isinstance(mission, str) or not mission:
            raise ReviewError("the project's contract names no release mission to delegate")
        assertion, action, _cap, policy_context = self.gate._build(contract, context)
        if not self._engine._vtrust.authenticate(assertion):
            raise ReviewError("the delegation's verifications are untrusted")
        tenant = context.tenant
        targets = tuple(sorted({self.gate.target_for(d, tenant).target.digest() for d in destinations}))
        now = self._now()
        proposal = DelegationProposal(context.actor_id, (action.action_id,), targets, mission, delegable,
                                      now + expires_in_us, now + admit_within_us, self._engine.targets.epoch(tenant))
        named = json.loads(action.destination)
        if not isinstance(named, dict) or PROPOSAL_FIELD in named:
            raise ReviewError("the project's release action cannot carry a delegation proposal")
        action = replace(action, destination=json.dumps({**named, PROPOSAL_FIELD: proposal.as_fields()}))
        try:
            envelope = self._engine.record_delegation_proposal(assertion=assertion, action=action,
                                                               ctx=replace(policy_context, now_us=now))
        except DelegationError as exc:
            raise ReviewError(str(exc)) from exc
        prepared = {"schema": SCHEMA, "review_id": review_id, "vertical_name": context.vertical_name,
                    "project_id": context.project_id, "action_id": context.action_id, "nonce": context.nonce,
                    "review_producer_id": context.review_producer_id, "envelope": _data(envelope),
                    "grants": [], "certificate": None, "credential_receipts": [], "root_digest": None}

        def create(old: dict[str, Any] | None) -> dict[str, Any]:
            if old is not None:
                _, _, original, _, _, _, _ = self._validated(old, contract, context, review_id)
                if original.actor_id != context.actor_id:
                    raise ReviewError("this delegation proposal belongs to a different owner")
                return old
            return prepared

        state = self.store.transact(tenant, review_id, create)
        request, _, _, stored, _, _, _ = self._validated(state, contract, context, review_id)
        return self._view(state, request, stored)

    def get(self, contract: dict[str, Any], context: EmissionContext, review_id: str) -> dict[str, Any]:
        """The verified status of one delegation review."""
        state = self.store.get(context.tenant, review_id)
        request, _, _, proposal, _, _, _ = self._validated(state, contract, context, review_id)
        assert state is not None
        return self._view(state, request, proposal)

    def grant(self, contract: dict[str, Any], context: EmissionContext, review_id: str, role: str) -> dict[str, Any]:
        """Grant as the authenticated caller, through the credential authority, on the unchanged decision."""
        if self.gate._credverify is None or not self._engine._approvals.requires_credentials:
            raise ReviewError("delegation review requires the configured credential authority")
        if context.is_producer:
            raise ReviewError("a producer cannot approve a delegation")
        snapshot = self.store.get(context.tenant, review_id)
        request, envelope, original, proposal, prior, certificate, now = self._validated(
            snapshot, contract, context, review_id)
        assert snapshot is not None
        if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
            return self._view(snapshot, request, proposal)
        if role not in set().union(*request.requirement.role_groups):
            raise ReviewError("role is not requested by this policy")
        record = envelope.record
        # The decision is re-derived now from the CURRENT contract as the owner, on the stored action (which carries
        # the proposal): if the artifact or the policy's answer changed, nobody may approve the stale proposal.
        assertion, _, _, policy_context = self.gate._build(contract, replace(original, now_us=now))
        if not self._engine._vtrust.authenticate(assertion) or assertion.assertion_id != record.assertion_id:
            raise ReviewError("the current delegation verifications are untrusted or differ")
        policy = self.gate._resolved_policy(assertion.content_type)
        decision = policy.evaluate(assertion, record.action, policy_context)
        current, _ = self._engine._recorder.make_record(assertion, record.action, policy_context, policy.ref, decision)
        if replace(record, record_id=current.record_id, decided_at_us=current.decided_at_us) != current:
            raise ReviewError("the current decision differs from the proposed delegation")
        authority = self._engine._approvals
        try:
            receipt = self.gate._review_credential(context.actor_id, role, contract, context)
            new_grant = authority.grant(request, Actor(context.actor_id, context.tenant, frozenset({role})), now,
                                        receipt=receipt)
        except (CredentialError, ApprovalError) as exc:
            raise ReviewError(str(exc)) from exc

        def approve(state: dict[str, Any] | None) -> dict[str, Any]:
            _, latest, _, _, prior, certificate, _ = self._validated(state, contract, context, review_id)
            assert state is not None
            if latest.record_hash != envelope.record_hash:
                raise ReviewError("the stored delegation decision changed while the grant was verified")
            if certificate is not None or any(g.reviewer_id == context.actor_id for g in prior):
                return state
            grants = [*prior, new_grant]
            try:
                certificate = authority.finalize(request, grants, now)
            except ApprovalError as exc:
                if not str(exc).startswith(("quorum not met", "role groups not covered")):
                    raise
            return {**state, "grants": [_data(g) for g in grants], "certificate": _data(certificate),
                    "credential_receipts": [*state["credential_receipts"], _data(receipt)]}

        state = self.store.transact(context.tenant, review_id, approve)
        request, _, _, proposal, _, _, _ = self._validated(state, contract, context, review_id)
        return self._view(state, request, proposal)

    def admit(self, contract: dict[str, Any], context: EmissionContext, review_id: str) -> dict[str, Any]:
        """Admit the approved root, as the owner who proposed it, through the engine's own admission."""
        snapshot = self.store.get(context.tenant, review_id)
        request, envelope, original, proposal, _, certificate, now = self._validated(
            snapshot, contract, context, review_id)
        assert snapshot is not None
        if context.actor_id != original.actor_id or context.is_producer:
            raise ReviewError("only the owner who proposed this delegation admits it")
        if certificate is None:
            raise ReviewError("the delegation has not reached the required approvals")
        assertion, _, _, policy_context = self.gate._build(contract, replace(original, now_us=now))
        if assertion.assertion_id != envelope.record.assertion_id:
            raise ReviewError("the current contract is not the one this delegation was decided about")
        try:
            root = self._engine.admit_delegation_root(
                envelope, certificate, assertion=assertion, subject=proposal.subject, targets=proposal.targets,
                expires_at_us=proposal.expires_at_us, delegable=proposal.delegable, now_us=now, ctx=policy_context)
        except DelegationError as exc:
            raise ReviewError(str(exc)) from exc

        def remember(state: dict[str, Any] | None) -> dict[str, Any]:
            self._validated(state, contract, context, review_id)
            assert state is not None
            if state["root_digest"] not in (None, root.digest):
                raise ReviewError("this delegation review already admitted a different root")
            return {**state, "root_digest": root.digest}

        state = self.store.transact(context.tenant, review_id, remember)
        return self.root(contract, context, review_id, _state=state)

    def root(self, contract: dict[str, Any], context: EmissionContext, review_id: str, *,
             _state: dict[str, Any] | None = None) -> dict[str, Any]:
        """A verified reference to the root this review admitted, with the metadata a child may narrow within."""
        state = _state if _state is not None else self.store.get(context.tenant, review_id)
        request, envelope, _, proposal, _, certificate, _ = self._validated(state, contract, context, review_id)
        assert state is not None
        digest = state["root_digest"]
        delegation = self._engine.delegation
        if not digest or certificate is None or delegation is None:
            raise ReviewError("this delegation review has not admitted a root")
        try:
            chain = delegation.resolve(context.tenant, digest, now_us=None)     # every blocking read, revocation too
            # Expiry is judged on the trusted clock read AFTER those reads (review 3234): a root that expired, before
            # or during them, is not reported as a verified, usable root.
            delegation.check_live_at(chain, self._now())
        except DelegationError as exc:
            raise ReviewError(f"the admitted root no longer verifies: {exc}") from exc
        grant = chain.leaf
        if (len(chain.grants) != 1 or grant.digest() != digest or grant.parent_digest
                or grant.decision_record_id != envelope.record.record_id or grant.subject != proposal.subject
                or grant.root_mission != proposal.root_mission or tuple(grant.targets) != proposal.targets):
            raise ReviewError("the stored root is not the one this delegation review admitted")
        return {**self._view(state, request, proposal), "root": {
            "root_digest": digest, "subject": grant.subject, "operations": list(grant.operations),
            "targets": list(grant.targets), "policy_refs": list(grant.policy_refs),
            "root_mission": grant.root_mission, "budget_limit": grant.budget_limit,
            "expires_at_us": grant.expires_at_us, "delegable": grant.delegable, "issued_at_us": grant.issued_at_us,
            "credential_receipt_digests": [_credential(raw).digest() for raw in state["credential_receipts"]]}}


__all__ = ["DelegationRootExchange", "MAX_ADMISSION_WAIT_US", "MAX_ROOT_LIFETIME_US", "SCHEMA"]
