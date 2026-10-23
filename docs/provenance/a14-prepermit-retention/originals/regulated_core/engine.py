"""The single enforced path: preflight -> decide -> approve -> permit -> emit -> evidence.

This orchestrator is integration review's decisive graft onto source review's substrate. source review shipped every part
but no single chokepoint, so its signed preflight capability was never checked on the emit path.
Here, `authorize_and_emit` verifies the capability BEFORE anything, binds an approval to the
exact decision and requirement, and lets output reach the world only through the output-bound
permit. Every outcome, including every refusal, is written to the signed, chained evidence log.
"""
from __future__ import annotations

import json
from hashlib import sha256

from collections.abc import Callable
from dataclasses import dataclass, replace

from .approval import ApprovalCertificate, ApprovalWorkflow
from .canonical import canonical_bytes, digest_hex
from .evidence import DecisionRecorder, SignedDecisionEnvelope
from .models import (
    Action, ActionEffect, Actor, Annotation, ApprovalRequirement, Assertion, Decision, DecisionKind, PolicyContext, PolicyRef,
)
from .permit import EmissionAuthority, EmissionError, SignedEmissionPermit
from .preflight import GenerationCapability, PreflightAuthority
from .registry import DeclaresMissionBudget, PolicyRegistry
from .budget import UNBUDGETED, BudgetError, InMemoryMissionBudget, MissionBudget
from .delegation import (EXECUTOR_PREFIX, PROPOSAL_FIELD, RELEASE_AUTHORITY_FIELD, Chain, DelegationAuthority,
                         DelegationError, ReleaseAuthority, SignedGrant, delegation_proposal_of, release_authority_of)
from .revocation import InMemoryRevocationLedger, Revocation, RevocationError, RevocationLedger
from .clock import TrustedClock
from .heartbeat import HeartbeatGate
from .tier4 import TIER3, TIER4, Tier4Controls
from .restrictions import RestrictionRegistry
from .target import (BoundEffect, FilesystemTargetAdapter, Outcome, SignedTargetPermit, TargetAdapter, TargetAuthority, TargetResult,
                     effect_of)
from .verification import VerificationTrustStore

_FAIL_CLOSED = PolicyRef(vertical="core", policy_id="fail-closed", version="1.0.0")


@dataclass(frozen=True, slots=True)
class EmissionOutcome:
    emitted: bool
    output: bytes | None
    decision_kind: str
    reason: str
    envelope: SignedDecisionEnvelope
    # The comment below stated the real type all along; `object` hid it and made
    # every `out.permit.permit` read an error in the gate.
    permit: SignedEmissionPermit | None = None   # evidence packs bind it


@dataclass(frozen=True, slots=True)
class _Decided:
    """The decision steps 1 to 6 passed: what a permit of either kind is issued against."""

    envelope: SignedDecisionEnvelope
    policy: PolicyRef
    approval_ref: str
    decision_kind: str
    # The latest instant any source authority allows: the capability's expiry and, when approval was required, the end
    # of the approved decision's window. No permit issued against this decision outlives it (source review 3107).
    authority_expires_us: int = 0


@dataclass(frozen=True, slots=True)
class TargetAuthorization:
    """A recorded decision and, when allowed, a target-bound permit. Nothing has reached the target yet."""

    authorized: bool
    reason: str
    decision_kind: str
    envelope: SignedDecisionEnvelope
    permit: SignedTargetPermit | None
    assertion: Assertion
    action: Action
    ctx: PolicyContext
    policy: PolicyRef


@dataclass(frozen=True, slots=True)
class TargetOutcome:
    """The outcome event recorded after the adapter answered: a separate, later entry in the evidence chain."""

    outcome: Outcome
    detail: str
    envelope: SignedDecisionEnvelope


#: Annotation kinds that bind a signed outcome record to the decision and permit it records the outcome of.
OUTCOME_OF_DECISION = "outcome-of-decision"
OUTCOME_OF_PERMIT = "outcome-of-permit"


class RegulatedEngine:
    def __init__(self, *, registry: PolicyRegistry, recorder: DecisionRecorder,
                 verification_trust: VerificationTrustStore, approvals: ApprovalWorkflow,
                 emission: EmissionAuthority, preflight: PreflightAuthority,
                 targets: TargetAuthority | None = None, budget: MissionBudget | None = None,
                 revocation: RevocationLedger | None = None,
                 delegation: DelegationAuthority | None = None, tier4: Tier4Controls | None = None,
                 restrictions: RestrictionRegistry | None = None,
                 delegation_source_status: Callable[[str, str], None] | None = None,
                 heartbeat: HeartbeatGate | None = None,
                 clock: TrustedClock | None = None, effect_margin_us: int = 0) -> None:
        if clock is None and targets is not None:
            clock = targets.clock
        if not isinstance(clock, TrustedClock):
            raise ValueError("regulated engine requires a named trusted clock")
        if targets is not None and targets.clock is not clock:
            raise ValueError("engine and target require the same configured clock")
        self._registry = registry
        self._recorder = recorder
        self._vtrust = verification_trust
        self._approvals = approvals
        self._emission = emission
        self._preflight = preflight
        # Target permits are issued by the emission authority itself (Paper A 4.2: the issuing authority), under
        # their own v2 schema, so no deployment needs a new signing identity. Each permit carries the tenant's
        # revocation epoch from the revocation ledger (Paper A 5.3); raising it revokes every outstanding permit.
        # A host that injects its own TargetAuthority injects the ledger that authority reads, or it cannot revoke.
        # Delegated authority (Paper A 4.2; docs/ARCHITECTURE-OF-RECORD/13): the target re-reads the chain at its
        # final check, so a delegation-aware engine needs a target authority that can.
        self._delegation = delegation
        # Paper A 4.2 (A03): tier-4 actions need two humans from different reporting lines, monitor clearance and a
        # cooling-off period. Without these controls composed, a tier-4 action is refused, never waved through.
        self._tier4 = tier4
        # A17: without a live, verified monitor heartbeat, no new authority at or above the gate's tier (heartbeat.py).
        self._heartbeat = heartbeat
        # Restriction policies a delegated child adds, evaluated at release (A08, composed policy).
        self._restrictions = restrictions
        # The host's receiving-side source check for a delegated grant (ledger 3114): the project admission, goal and
        # customer membership behind the grant are still current. Raises when they are not. Called at authorization
        # and again at the target's final check, so authority withdrawn between permit and commit refuses the effect.
        self._source_status = delegation_source_status
        if targets is None:
            revocation = revocation if revocation is not None else InMemoryRevocationLedger()
            targets = TargetAuthority(emission.signer, emission.trust, revocation_epoch=revocation.epoch,
                                      clock=clock, effect_margin_us=effect_margin_us,
                                      chain_status=self._chain_status if delegation is not None else None)
        elif delegation is not None and not targets.checks_delegation:
            raise ValueError("a delegation-aware engine needs a target authority that re-checks delegated chains")
        self._targets = targets
        self._revocation = revocation
        # The receiving emission authority judges on this same trusted clock, fixed here once (source review 3126).
        emission.bind_trusted_clock(clock)
        preflight.bind_clock(clock)
        recorder.bind_clock(clock)

        # Paper A 4.2: aggregate budgets reserved in shared state before authority is issued. The engine enforces
        # the limit the resolved signed policy declares; no caller argument names or resizes it.
        self._budget: MissionBudget = budget if budget is not None else InMemoryMissionBudget()

    @property
    def targets(self) -> TargetAuthority:
        return self._targets

    @property
    def delegation(self) -> DelegationAuthority | None:
        return self._delegation

    def _chain_status(self, tenant_id: str, grant_digest: str) -> None:
        """For the target's final check: the chain still resolves and no ancestor is revoked. Expiry is judged on
        the permit, whose expiry the chain's capped at issuance, against the target authority's clock."""
        assert self._delegation is not None
        try:
            self._delegation.resolve(tenant_id, grant_digest, now_us=None)
        except DelegationError as refused:
            raise EmissionError(f"delegated authority withdrawn: {refused}") from None
        if self._source_status is not None:
            try:
                self._source_status(tenant_id, grant_digest)
            except Exception:
                # The host's source authority (admission, goal, membership) no longer stands; its detail stays private.
                raise EmissionError("delegated authority withdrawn: its source is no longer current") from None

    def _delegate_downgrade(self, ctx: PolicyContext) -> bool:
        """A delegate acts only through its chain: a request from one that names no chain is never a root act.
        An executor principal is a delegate on every engine, composed with delegation or not."""
        actor = ctx.actor.actor_id
        return actor.startswith(EXECUTOR_PREFIX) or (
            self._delegation is not None and self._delegation.is_delegate(ctx.tenant_id, actor))

    def record_delegation_proposal(self, *, assertion: Assertion, action: Action,
                                   ctx: PolicyContext) -> SignedDecisionEnvelope:
        """Decide and record a proposal to delegate a mission, so a human can approve exactly it.

        The proposal lives in the signed action's destination (`delegation_admission`), so the decision and any
        approval of it cover every field. The policy in force must be signed and budgeted and must not deny; the
        proposal must carry the tenant's current revocation epoch. Nothing is admitted here: admission is a second,
        separately approved step (`admit_delegation_root`)."""
        proposal = delegation_proposal_of(_destination_field(action.destination, PROPOSAL_FIELD))
        if proposal is None:
            raise DelegationError("the action carries no delegation proposal")
        if assertion.tenant_id != ctx.tenant_id:
            raise DelegationError("assertion tenant does not match context")
        if ctx.actor.producer:
            raise DelegationError("a probabilistic producer cannot propose delegation")
        if proposal.revocation_epoch != self._targets.epoch(ctx.tenant_id):
            raise DelegationError("the proposal does not carry the tenant's current revocation epoch")
        policy = self._registry.resolve(assertion.content_type)
        if policy is None or not policy.ref.digest or not isinstance(policy, DeclaresMissionBudget):
            raise DelegationError("delegation needs a signed, budgeted policy in force")
        decision = policy.evaluate(assertion, action, ctx)
        envelope = self._recorder.record(assertion, action, ctx, policy.ref, decision)
        if decision.kind is DecisionKind.DENY:
            raise DelegationError("the policy denies this delegation proposal")
        if decision.kind is not DecisionKind.REQUIRE_APPROVAL:
            raise DelegationError("delegation is always a human-approved act: the policy must require approval")
        return envelope

    def admit_delegation_root(self, envelope: SignedDecisionEnvelope, approval: ApprovalCertificate, *,
                              assertion: Assertion, subject: str, targets: tuple[str, ...], expires_at_us: int,
                              delegable: bool, now_us: int, ctx: PolicyContext | None = None) -> SignedGrant:
        """Admit a delegation root from an approved delegation proposal, and from nothing else (source review 3080, 3084).

        The decision envelope must be intact in this engine's evidence chain, not denied, and its signed action must
        carry a delegation proposal: an ordinary effect approval never grants delegation. The certificate must be a
        genuine approval that satisfies exactly the requirement the policy recorded, validated by the same function
        as every release (`_approval_problem`). Every root fact comes from the approved proposal and the recorded
        decision; the caller's `subject`, `targets`, `expires_at_us` and `delegable` must equal what was approved, or
        admission refuses.

        Authority is decided again, in this documented order (source review 3086, 3088): first every blocking read, the policy
        in force and the tenant's revocation epoch; then the trusted clock, once; then, at that instant, the current
        decision (the policy re-evaluated on the approved action, which must equal the decision the human approved),
        the approval's validity and the admission deadline. That clock reading is admission's linearization point: a
        revocation or policy change recorded after it is ordered after this admission. `ctx`, when the host supplies
        its authenticated context, must name the recorded actor and tenant; otherwise the recorded context is used.
        The caller's `now_us` is never believed. Admitting the same approval twice yields the same grant."""
        if self._delegation is None:
            raise DelegationError("this engine was given no delegation authority")
        record = envelope.record
        if not self._recorder.verify_entry(envelope):
            raise DelegationError("the admitting decision is not an intact record of this engine")
        proposal = delegation_proposal_of(_destination_field(record.action.destination, PROPOSAL_FIELD))
        if proposal is None:
            raise DelegationError("an ordinary approval does not grant delegation: no approved proposal")
        if record.decision.kind is not DecisionKind.REQUIRE_APPROVAL or record.decision.approval is None:
            raise DelegationError("a delegation root needs the approval its policy required")
        if not self._approvals.verify_certificate(approval):
            raise DelegationError("the approval is not a genuine approval of this exact decision")
        if assertion.assertion_id != record.assertion_id or assertion.tenant_id != record.tenant_id:
            raise DelegationError("the assertion is not the one this decision was made about")
        if (subject != proposal.subject or tuple(sorted(targets)) != proposal.targets
                or expires_at_us != proposal.expires_at_us or delegable != proposal.delegable):
            raise DelegationError("the requested root differs from the approved delegation proposal")
        if ctx is not None and (ctx.tenant_id != record.tenant_id or ctx.actor.actor_id != record.actor_id):
            raise DelegationError("the authenticated context is not the one this decision was made in")
        # 1. Every blocking read first: the policy in force, then the revocation epoch.
        policy = self._registry.resolve(assertion.content_type)
        if policy is None or not record.policy.digest or policy.ref != record.policy:
            raise DelegationError("the decision's signed policy is no longer the policy in force")
        declared = policy.mission_budget(record.action.action_id) if isinstance(policy, DeclaresMissionBudget) else None
        if declared is None:
            raise DelegationError("an unbudgeted policy cannot delegate")
        if proposal.revocation_epoch != self._targets.epoch(record.tenant_id):
            raise DelegationError("the tenant's authority was revoked after this proposal was approved")
        # 2. The trusted clock, once, after them; the caller's `now_us` is not believed.
        now = self._targets.now_us()
        # 3. At that instant: the deadline, the current decision, and the approval.
        if now >= proposal.admit_by_us:
            raise DelegationError("the approved proposal's admission deadline has passed")
        current_ctx = replace(ctx, now_us=now) if ctx is not None else PolicyContext(
            tenant_id=record.tenant_id, actor=Actor(actor_id=record.actor_id, tenant_id=record.tenant_id,
                                                    roles=frozenset()),
            purpose=record.purpose, correlation_id=record.correlation_id, now_us=now)
        if policy.evaluate(assertion, record.action, current_ctx) != record.decision:
            raise DelegationError("the policy in force no longer makes the decision the human approved")
        problem = _approval_problem(envelope, record.decision.approval, approval, tenant_id=record.tenant_id,
                                    assertion_id=record.assertion_id, now_us=now)
        if problem is not None:
            raise DelegationError(f"the approval does not satisfy the decision it approves: {problem[1]}")
        return self._delegation.admit_root(
            tenant_id=record.tenant_id, approver=",".join(sorted(approval.approver_ids)), subject=proposal.subject,
            operations=proposal.operations, targets=proposal.targets,
            policy_refs=(f"{record.policy.vertical}/{record.policy.policy_id}@{record.policy.digest}",),
            root_mission=proposal.root_mission, budget_limit=int(declared["limit"]),
            expires_at_us=proposal.expires_at_us, decision_record_id=record.record_id,
            approval_digest=sha256(canonical_bytes(approval.signed_body())).hexdigest(),
            delegable=proposal.delegable, now_us=now, issued_at_us=record.decided_at_us)

    @property
    def budget(self) -> MissionBudget:
        return self._budget

    def revoke(self, tenant_id: str, *, actor: str, reason: str, now_us: int) -> Revocation:
        """Revoke every outstanding permit of the tenant (Paper A 5.3): the target refuses any permit issued before
        this. Committed effects stay committed. Who may revoke is the host's decision; the ledger records who did."""
        if self._revocation is None:
            raise RevocationError("this engine's target authority reads a revocation source it was not given")
        return self._revocation.revoke(tenant_id, actor=actor, reason=reason, now_us=now_us)

    def for_policy(self, *, registry: PolicyRegistry, preflight: PreflightAuthority) -> RegulatedEngine:
        """A sibling that decides under one pinned policy version and shares EVERY authority of this engine: the
        evidence recorder, verification trust, approvals, emission and target authorities and the mission budget.
        Only the policy lookup and the declared uses differ, so a version gate can never drop an injected
        authority by rebuilding an engine from parts."""
        return RegulatedEngine(registry=registry, recorder=self._recorder, verification_trust=self._vtrust,
                               approvals=self._approvals, emission=self._emission, preflight=preflight,
                               targets=self._targets, budget=self._budget, revocation=self._revocation,
                               delegation=self._delegation, tier4=self._tier4, restrictions=self._restrictions,
                               delegation_source_status=self._source_status, heartbeat=self._heartbeat)

    def authorize_and_emit(
        self, *, vertical: str, capability: GenerationCapability, assertion: Assertion,
        action: Action, ctx: PolicyContext, output: bytes, permit_ttl_us: int, nonce: str,
        approval_cert: ApprovalCertificate | None = None,
        approval_evidence: SignedDecisionEnvelope | None = None,
    ) -> EmissionOutcome:
        """The in-process path: decide, then return the permitted bytes to the caller.

        The caller writes them, so no target checks the permit. Covered effects use `authorize_for_target`.
        Delegated authority never travels this path: a delegate is refused here."""
        # The present is the authority's trusted clock, never a time the caller supplies (source review 3107).
        ctx = replace(ctx, now_us=self._targets.now_us())
        if self._delegate_downgrade(ctx):
            why = "a delegate acts only through its verified chain, which this path cannot carry"
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED,
                                        Decision.deny("DELEGATE_WITHOUT_CHAIN", why))
            return EmissionOutcome(False, None, "deny", why, env)
        decided = self._decide(vertical=vertical, capability=capability, assertion=assertion, action=action,
                               ctx=ctx, approval_cert=approval_cert, approval_evidence=approval_evidence)
        if not isinstance(decided, _Decided):
            return decided

        def denied(code: str, why: str) -> EmissionOutcome:
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED, Decision.deny(code, why))
            return EmissionOutcome(False, None, "deny", why, env)

        # 7. output-bound, single-use permit, then the only path out
        ttl = min(permit_ttl_us, decided.authority_expires_us - ctx.now_us) if decided.authority_expires_us else permit_ttl_us
        if ttl <= 0:
            return denied("AUTHORITY_WINDOW_CLOSED", "the capability or approval behind this decision has expired")
        try:
            permit = self._emission.issue(decided.envelope, output, approval_ref=decided.approval_ref,
                                          now_us=ctx.now_us, ttl_us=ttl, nonce=nonce,
                                          not_after_us=ctx.now_us + ttl)
            # Judged on the emission authority's own clock, bound to the target authority's at composition, read
            # after the blocking signing and again after the single-use claim (source review 3120, 3126).
            # now_us is informational for older receivers and decides nothing in EmissionAuthority.
            emitted = self._emission.emit(permit, output, tenant_id=ctx.tenant_id, now_us=self._targets.now_us())
        except EmissionError as exc:
            return denied("EMISSION_BLOCKED", str(exc))

        self._recorder.record(assertion, action, ctx, decided.policy,
                              Decision.allow("EMITTED", f"emitted under permit nonce {nonce}"))
        return EmissionOutcome(True, emitted, decided.decision_kind, "", decided.envelope, permit)

    def authorize_for_target(
        self, *, vertical: str, capability: GenerationCapability, assertion: Assertion,
        action: Action, ctx: PolicyContext, output: bytes, target: TargetAdapter,
        permit_ttl_us: int, nonce: str, qualification_digests: tuple[str, ...] = (), not_after_us: int = 0,
        approval_cert: ApprovalCertificate | None = None,
        approval_evidence: SignedDecisionEnvelope | None = None,
    ) -> TargetAuthorization:
        """Decide, then issue a permit bound to these exact bytes, this operation and this target's current state.

        Nothing is written here and nothing is reported as emitted: the adapter commits, and the outcome is a
        later event (`commit`, `reconcile`). The decision record is durable before the permit exists.

        The effect comes from the signed action itself (`effect_of(action.destination)`), the same action any
        approval must match. A permit is only ever issued for exactly that effect: an action naming none, other
        bytes, another target, or a target whose state has changed is a recorded denial here, at the door.

        The mission comes from the same signed effect, and its budget from the resolved signed policy
        (`DeclaresMissionBudget`). No argument can name, remove or resize either (source review 2988)."""
        if self._emission.uses.used(ctx.tenant_id, nonce):
            # Refused and recorded at decision time, so the evidence says "denied" rather than an allowed
            # decision that only the target refused. The adapter's atomic claim remains the race-safe backstop.
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED,
                                        Decision.deny("PERMIT_REPLAY", "this permit nonce is already spent"))
            return TargetAuthorization(False, "this permit nonce is already spent", "deny", env, None,
                                       assertion, action, ctx, _FAIL_CLOSED)
        bound = effect_of(action.destination)
        mismatch = _effect_mismatch(bound, action.action_id, output, target)
        if mismatch or bound is None:
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED,
                                        Decision.deny("EFFECT_NOT_APPROVED", mismatch))
            return TargetAuthorization(False, mismatch, "deny", env, None, assertion, action, ctx, _FAIL_CLOSED)

        def refused(code: str, why: str) -> TargetAuthorization:
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED, Decision.deny(code, why))
            return TargetAuthorization(False, why, "deny", env, None, assertion, action, ctx, _FAIL_CLOSED)

        # Delegated authority, named inside the signed action beside the effect, so approval covers it too.
        chain: Chain | None = None
        try:
            claimed = release_authority_of(_destination_field(action.destination, RELEASE_AUTHORITY_FIELD))
        except DelegationError as malformed:
            return refused("DELEGATION_MALFORMED", str(malformed))
        policy = self._registry.resolve(assertion.content_type)
        declared = policy.mission_budget(action.action_id) if isinstance(policy, DeclaresMissionBudget) else None
        if claimed is not None:
            if self._delegation is None:
                return refused("DELEGATION_UNAVAILABLE", "this engine was given no delegation authority")
            try:
                chain = self._delegation.resolve(ctx.tenant_id, claimed.grant_digest, now_us=self._targets.now_us())
            except DelegationError as withdrawn:
                return refused("DELEGATION_REFUSED", str(withdrawn))
            problem = _chain_mismatch(chain, claimed, ctx, action, bound)
            if problem is None and self._source_status is not None:
                try:
                    self._source_status(ctx.tenant_id, claimed.grant_digest)
                except Exception:
                    problem = "the delegated authority's source is no longer current"
            if problem is None and declared is None:
                problem = "a delegated release needs a policy that declares a mission budget"
            if problem is not None:
                return refused("DELEGATION_REFUSED", problem)
        elif self._delegate_downgrade(ctx):
            return refused("DELEGATE_WITHOUT_CHAIN",
                           "a delegate acts only through its verified chain, and this request names none")
        # Every blocking read above (nonce store, delegation chain) is done; from here the present is the authority's
        # trusted clock, never a time the caller supplies, so an old ctx.now_us cannot revive an expired capability or
        # approval (source review 3107).
        ctx = replace(ctx, now_us=self._targets.now_us())
        # 0. reserve, BEFORE the decision is recorded: the model's order is reserve, record, permit, commit.
        mission, reservation, units = bound.mission, UNBUDGETED, 0
        if declared is not None:
            limit, units = int(declared["limit"]), int(declared["units"])
            if chain is not None:
                # The lower of the root's ceiling, fixed at admission, and the signed policy in force now (source review 3080):
                # a policy tightened since admission binds at once. The mission was matched to the root above, so no
                # fresh child project, goal, target or nonce opens a new allowance.
                limit = min(limit, chain.root.budget_limit)
            if not mission:
                env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED, Decision.deny(
                    "BUDGET_MISSION_MISSING", "the policy bounds this action per mission, and the action names none"))
                return TargetAuthorization(False, "the action names no mission for its declared budget", "deny", env,
                                           None, assertion, action, ctx, _FAIL_CLOSED)
            try:
                reservation = self._budget.reserve(ctx.tenant_id, mission, reservation_id=nonce, units=units,
                                                   limit=limit).reservation_id
            except BudgetError as exceeded:
                env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED,
                                            Decision.deny("BUDGET_EXCEEDED", str(exceeded)))
                return TargetAuthorization(False, str(exceeded), "deny", env, None, assertion, action, ctx,
                                           _FAIL_CLOSED)
        try:
            decided = self._decide(vertical=vertical, capability=capability, assertion=assertion, action=action,
                                   ctx=ctx, approval_cert=approval_cert, approval_evidence=approval_evidence)
        except BaseException:
            if reservation != UNBUDGETED:
                self._budget.release(ctx.tenant_id, mission, reservation)   # no authority was issued against it
            raise
        if not isinstance(decided, _Decided):
            if reservation != UNBUDGETED:
                self._budget.release(ctx.tenant_id, mission, reservation)
            return TargetAuthorization(False, decided.reason, "deny", decided.envelope, None,
                                       assertion, action, ctx, _FAIL_CLOSED)
        if chain is not None:
            decided_ref = f"{decided.policy.vertical}/{decided.policy.policy_id}@{decided.policy.digest}"
            restricted = (_restriction_problem(self._restrictions, set(chain.leaf.policy_refs) - {decided_ref},
                                               assertion, action, ctx)
                          if decided.policy.digest and decided_ref in chain.leaf.policy_refs else
                          "the delegated authority does not bind the signed policy in force")
            if restricted is not None:
                if reservation != UNBUDGETED:
                    self._budget.release(ctx.tenant_id, mission, reservation)
                return refused("DELEGATION_REFUSED", restricted)
            # No permit issued under the chain outlives any grant in it.
            not_after_us = min(not_after_us, chain.expires_at_us) if not_after_us else chain.expires_at_us
        if decided.authority_expires_us:
            # Nor does any permit outlive the capability or the approval it was decided on (source review 3107).
            not_after_us = (min(not_after_us, decided.authority_expires_us) if not_after_us
                            else decided.authority_expires_us)
        try:
            permit = self._targets.issue(
                # Every binding the approval owns comes from the signed action alone; the adapter only executes and
                # checks it, and supplies no authority after validation (source review 2995).
                decided.envelope, output, target=bound.target, operation=action.action_id,
                # The APPROVED prior state from the signed action, never a fresh read: anything written after the
                # check above is not adopted, and the target refuses the commit because its state differs (2988).
                expected_target_state=bound.target_state, principal=ctx.actor.actor_id,
                approval_ref=decided.approval_ref, qualification_digests=qualification_digests,
                ttl_us=permit_ttl_us, not_after_us=not_after_us, nonce=nonce, mission=mission,
                budget_reservation=reservation, budget_units=units if reservation != UNBUDGETED else 0,
                policy_version=(f"{decided.policy.vertical}/{decided.policy.policy_id}@{decided.policy.version}"
                                + (f"#{decided.policy.digest}" if decided.policy.digest else "")),
                grant_digest=chain.leaf.digest() if chain is not None else "",
                chain_digest=chain.digest if chain is not None else "",
                root_digest=chain.root.digest() if chain is not None else "")
        except EmissionError as closed:
            # The host deadline passed before a permit could be issued: no authority exists, so the reservation
            # returns, and the refusal is recorded beside the decision.
            if reservation != UNBUDGETED:
                self._budget.release(ctx.tenant_id, mission, reservation)
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED,
                                        Decision.deny("AUTHORITY_WINDOW_CLOSED", str(closed)))
            return TargetAuthorization(False, str(closed), "deny", env, None, assertion, action, ctx, _FAIL_CLOSED)
        return TargetAuthorization(True, "", decided.decision_kind, decided.envelope, permit,
                                   assertion, action, ctx, decided.policy)

    def record_refusal(self, *, assertion: Assertion, action: Action, ctx: PolicyContext, code: str,
                       reason: str) -> SignedDecisionEnvelope:
        """Record a refusal a gate decided before policy evaluation, such as authority that is missing, revoked or
        changed, in the same signed chain as every decision. It grants nothing and issues no permit."""
        return self._recorder.record(assertion, action, ctx, _FAIL_CLOSED, Decision.deny(code, reason))

    def commit(self, authorization: TargetAuthorization, output: bytes, target: TargetAdapter) -> TargetOutcome:
        """Hand the permitted bytes to the adapter, which rechecks everything at the target on the authority's own
        clock, and record the outcome."""
        if not authorization.authorized or authorization.permit is None:
            raise EmissionError("no target permit was issued for this authorization")
        result = target.commit(authorization.permit, output)
        return self._record_outcome(authorization, result, reconciled=False)

    def cancel(self, authorization: TargetAuthorization, target: FilesystemTargetAdapter) -> TargetOutcome:
        """Record cancellation only after the target retires the exact permit."""
        if not authorization.authorized or authorization.permit is None:
            raise EmissionError("no target permit was issued for this authorization")
        result = target.cancel(authorization.permit)
        if result.outcome is Outcome.NOT_COMMITTED:
            result = TargetResult(Outcome.FAILED, result.detail, result.target_state)
        return self._record_outcome(authorization, result, reconciled=False)

    def reconcile(self, authorization: TargetAuthorization, target: TargetAdapter) -> TargetOutcome:
        """Resolve an UNKNOWN outcome by querying the target. Never re-sends."""
        if authorization.permit is None:
            raise EmissionError("no target permit was issued for this authorization")
        return self._record_outcome(authorization, target.status(authorization.permit), reconciled=True)

    def _record_outcome(self, authorization: TargetAuthorization, result: TargetResult, *,
                        reconciled: bool) -> TargetOutcome:
        # Outcome events use stable reason codes in the same signed chain as the decision, as EMITTED always
        # has; ALLOW marks only a target that holds the permitted bytes.
        assert authorization.permit is not None
        prefix = "RECONCILED_" if reconciled else "OUTCOME_"
        code = prefix + result.outcome.name
        why = (f"{result.outcome.value} at {authorization.permit.permit.target_kind} under permit nonce "
               f"{authorization.permit.permit.nonce}" + (f": {result.detail}" if result.detail else ""))
        # The outcome names, inside its own signature, the exact decision and permit it records the outcome OF, so no
        # other decision over the same assertion and action can claim it (source review 3205). Kind is unchanged.
        binding = (Annotation(OUTCOME_OF_DECISION, authorization.envelope.record_hash),
                   Annotation(OUTCOME_OF_PERMIT, digest_hex(authorization.permit.permit.signed_body())))
        kind = DecisionKind.ALLOW if result.outcome is Outcome.COMMITTED else DecisionKind.DENY
        decision = Decision(kind, (code,), why, annotations=binding)
        env = self._recorder.record(authorization.assertion, authorization.action, authorization.ctx,
                                    authorization.policy, decision)
        return TargetOutcome(result.outcome, result.detail, env)

    def _decide(
        self, *, vertical: str, capability: GenerationCapability, assertion: Assertion,
        action: Action, ctx: PolicyContext, approval_cert: ApprovalCertificate | None,
        approval_evidence: SignedDecisionEnvelope | None,
    ) -> _Decided | EmissionOutcome:
        """Steps 1 to 6, shared by both permit kinds. A refusal is recorded and returned as an EmissionOutcome."""

        def denied(code: str, why: str) -> EmissionOutcome:
            env = self._recorder.record(assertion, action, ctx, _FAIL_CLOSED, Decision.deny(code, why))
            return EmissionOutcome(False, None, "deny", why, env)

        # 1. tenant isolation
        if assertion.tenant_id != ctx.tenant_id:
            return denied("TENANT_MISMATCH", "assertion tenant does not match context")
        # 2. preflight capability, verified ON the emit path
        if not self._preflight.verify(capability, tenant_id=ctx.tenant_id, vertical=vertical,
                                      action_id=action.action_id, correlation_id=ctx.correlation_id, now_us=ctx.now_us):
            return denied("PREFLIGHT_INVALID", "generation capability invalid, expired, or mismatched")
        # 3. producer may never take an authoritative/external action (core invariant)
        if action.effect in (ActionEffect.AUTHORITATIVE, ActionEffect.EXTERNAL) and ctx.actor.producer:
            return denied("PRODUCER_FORBIDDEN", "a probabilistic producer cannot take this action")
        # 4. attached verifications must be authentic (signed, bound, tenant-scoped)
        if not self._vtrust.authenticate(assertion):
            return denied("VERIFICATION_FORGED", "a verification is forged, mis-signed, or unbound")

        # 5. the consequence decision (fail-closed on unknown content type)
        policy = self._registry.resolve(assertion.content_type)
        if policy is None:
            return denied("NO_POLICY", f"no policy for content type {assertion.content_type}")
        decision = policy.evaluate(assertion, action, ctx)
        env = self._recorder.record(assertion, action, ctx, policy.ref, decision)

        if decision.kind is DecisionKind.DENY:
            return EmissionOutcome(False, None, "deny", decision.rationale, env)

        # 6. approval, when required — bound to THIS decision and the EXACT requirement
        approval_ref = ""
        approved = env
        if decision.kind is DecisionKind.REQUIRE_APPROVAL:
            assert decision.approval is not None
            if approval_cert is None or not self._approvals.verify_certificate(approval_cert):
                return denied("APPROVAL_MISSING", "valid approval certificate required")
            approved = env
            if approval_evidence is not None:
                if not self._recorder.verify_entry(approval_evidence):
                    return denied("APPROVAL_EVIDENCE_INVALID", "approval decision evidence is invalid or untrusted")
                approved = approval_evidence
                # Only the recording time and its derived ID may differ. Actor,
                # tenant, assertion, destination, policy and the full decision
                # (including the actual approval requirement) must still match.
                current = replace(approved.record, record_id=env.record.record_id,
                                  decided_at_us=env.record.decided_at_us)
                if current != env.record:
                    return denied("APPROVAL_DECISION_CHANGED", "the current decision differs from the approved record")
            problem = _approval_problem(approved, decision.approval, approval_cert, tenant_id=ctx.tenant_id,
                                        assertion_id=assertion.assertion_id, now_us=ctx.now_us)
            if problem is not None:
                return denied(*problem)
            approval_ref = approval_cert.request_id

        # 7. tier 4 (Paper A 4.2; A03). The tier is the higher of the signed capability's and the tier the intended use
        # declares, so a caller asking for a lower tier never skips these controls (source review 3103); judged on the
        # authority's trusted clock, so a caller's timestamp can never shorten the cooling-off period.
        declared_tier = self._preflight.declared_tier(vertical, action.action_id) or 0
        effective_tier = max(capability.risk_tier, declared_tier)
        # Tier 3 (Paper A 4.2; A03): one verified human, enforced here by tier, not left to each pack's policy. The
        # approval workflow admits only credential-verified, non-producer approvers, so a genuine certificate that
        # names an approver IS a verified human's sign-off on exactly this decision (source review 3298).
        if effective_tier >= TIER3 and (decision.kind is not DecisionKind.REQUIRE_APPROVAL or approval_cert is None
                                        or not approval_cert.approver_ids):
            return denied("TIER3_REQUIRES_APPROVAL", "a tier-3 action needs a verified human's approval")
        if self._heartbeat is not None:
            stale = self._heartbeat.problem(effective_tier, now_us=self._targets.now_us())
            if stale is not None:
                return denied(*stale)
        if effective_tier >= TIER4:
            if decision.kind is not DecisionKind.REQUIRE_APPROVAL or approval_cert is None:
                return denied("TIER4_REQUIRES_APPROVAL", "a tier-4 action always needs human approval")
            if self._tier4 is None:
                return denied("TIER4_UNAVAILABLE", "tier-4 controls are not composed on this engine")
            tier4_problem = self._tier4.problem(approved, approval_cert, now_us=self._targets.now_us())
            if tier4_problem is not None:
                return denied(*tier4_problem)

        expires = capability.expires_at_us
        if decision.kind is DecisionKind.REQUIRE_APPROVAL and decision.approval is not None:
            expires = min(expires, approved.record.decided_at_us + decision.approval.expires_after_us)
        return _Decided(env, policy.ref, approval_ref, decision.kind.value, authority_expires_us=expires)


def _approval_problem(approved: SignedDecisionEnvelope, requirement: ApprovalRequirement,
                      cert: ApprovalCertificate, *, tenant_id: str, assertion_id: str,
                      now_us: int) -> tuple[str, str] | None:
    """The one validation of a (signature-verified) approval certificate against the decision it approves, shared by
    every consequential path: release and delegation-root admission alike (source review 3086). It must be finalized inside
    the decision's window, before now, and bind this tenant, assertion, exact record and exact requirement, so a
    genuine certificate over a weaker requirement or a stale decision grants nothing. Returns (code, reason)."""
    if not (approved.record.decided_at_us <= cert.finalized_at_us <= now_us):
        return "APPROVAL_TIME_INVALID", "approval time is outside the decision and release interval"
    if now_us >= approved.record.decided_at_us + requirement.expires_after_us:
        return "APPROVAL_EXPIRED", "the approved decision window has expired"
    if not (cert.tenant_id == tenant_id and cert.assertion_id == assertion_id
            and cert.decision_record_id == approved.record.record_id
            and cert.decision_record_hash == approved.record_hash
            and cert.requirement_digest == requirement.digest()):
        return "APPROVAL_UNBOUND", "approval is not bound to this decision/requirement"
    return None


def _restriction_problem(restrictions: RestrictionRegistry | None, refs: set[str], assertion: Assertion,
                         action: Action, ctx: PolicyContext) -> str | None:
    """Evaluate every restriction a delegated chain adds (regulated_core/restrictions.py); None when all allow."""
    for ref in sorted(refs):
        restriction = restrictions.get(ref) if restrictions is not None else None
        if restriction is None:
            return f"the delegated authority names a policy this engine cannot evaluate: {ref} (source review 3081)"
        verdict = restriction.evaluate(assertion, action, ctx)
        if verdict.kind is DecisionKind.DENY:
            return f"a delegated restriction denies this release: {ref}: {verdict.rationale}"
        if verdict.kind is DecisionKind.REQUIRE_APPROVAL:
            return f"a delegated restriction requires an approval of its own, which is not supported yet: {ref}"
    return None


def _destination_field(destination: str, name: str) -> object:
    """One named field of a signed action's JSON destination, or None when absent or not JSON."""
    try:
        fields = json.loads(destination)
    except ValueError:
        return None
    return fields.get(name) if isinstance(fields, dict) else None


def _chain_mismatch(chain: Chain, claimed: ReleaseAuthority, ctx: PolicyContext, action: Action,
                    bound: BoundEffect) -> str | None:
    """Why a verified chain does not authorize this exact act, or None when it does. The claim in the signed
    action must name exactly the chain the core resolved; the actor must be its leaf subject; the operation and
    target must be within the leaf; and the mission must be the root's."""
    leaf, root = chain.leaf, chain.root
    if claimed.chain_digest != chain.digest or claimed.root_digest != root.digest():
        return "the signed action names a different delegation chain than the one that resolved"
    if ctx.actor.actor_id != leaf.subject:
        return "only the delegated subject may act under this grant"
    if action.action_id not in leaf.operations:
        return "the operation is outside the delegated authority"
    if bound.target.digest() not in leaf.targets:
        return "the target is outside the delegated authority"
    if not (claimed.mission == bound.mission == root.root_mission):
        return "a delegated release draws on its root mission, and only that"
    return None


def _effect_mismatch(bound: BoundEffect | None, operation: str, output: bytes, target: TargetAdapter) -> str:
    """Why this request is not the effect its signed action names, or "" when it is exactly that effect."""
    if bound is None:
        return "the action names no effect, so no effect can be permitted"
    if target.operation != operation:
        return "the target performs a different operation than the signed action"
    if sha256(output).hexdigest() != bound.output_digest:
        return "the bytes are not the bytes the approval covered"
    if target.target != bound.target:
        return "the target is not the target the approval named"
    if target.current_state() != bound.target_state:
        return "the target has changed since the approval; a new approval is needed"
    return ""
