"""The composition seam: `regulated_core`-backed RegulatedEmissionGate(s) for Project OS.

This module may import BOTH sides (`regulated_core` depends on `factory`; `factory` never depends on
`regulated_core`), so it is the one place they meet. It turns a Project OS draft/release of a
regulated vertical's contract into a full authority decision: run the domain verifiers over the
draft, build a signed `Assertion`, and route the reversible draft / external release through the
`regulated_core` engine (deny-by-default, credentialed approval, output-bound permit, signed evidence).

`_RegulatedGateBase` is the reusable recipe; each domain vertical is a THIN subclass that supplies its
verifiers, content type, actions, data class, and audit shape. Patient education (health) and
investment research (financial services) are both just configurations of the same base — the proof
that a new regulated domain follows exactly the same recipe.
"""
from __future__ import annotations

from .production_gate import ProductionReadinessError, ReleaseReadiness
from .permit import EmissionError

import json
import logging

from psycopg import OperationalError
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Protocol

from factory.projectos.governed_release import MISSION_FIELD, PREPARATION_FIELD, TARGET_FIELD
from factory.projectos.regulated import EmissionContext, EmissionDecision, ReleaseOutcome
from factory.projectos.spec import (
    AXIS_KNOWLEDGE_BACKED, KIND_PROJECT, RegulatedBlock, StageSpec, VerticalSpec,
)

from .approval import ApprovalCertificate, ApprovedDecision
from .approval_exchange import ApprovalExchange, ReviewError, ReviewMembershipEvidence
from .canonical import canonical_bytes
from .budget import UNBUDGETED
from .engine import RegulatedEngine, TargetAuthorization
from .identity_provider import CredentialError
from .registry import ConsequencePolicy
from .models import (
    Action, ActionEffect, Actor, Assertion, DataClass, DecisionKind, PolicyContext,
    ProducerLineage, SignedVerification,
)
from .signing import Signer
from .review_store import ReviewStore
from .verticals import investment_research as ir
from .verticals import patient_education as pe
from .target import (
    BoundEffect, FilesystemTargetAdapter, Outcome, ReleaseAdmissionUnavailable,
    TargetAdapter, TargetRef, effect_destination, effect_of,
)
from .worm import WormStore, WormUnavailable, anchor_evidence_chain, bind_worm_receipt
from .kms import KmsUnavailable
from .evidence import SignedDecisionEnvelope
from .outage import LogOutageAlarm, OutageAlarm, OutageEvent, Severity
from .delegation import RELEASE_AUTHORITY_FIELD, DelegationError, release_authority_of

_HOUR = 3_600_000_000
_YEARS7 = 7 * 365 * 86_400_000_000            # WORM retention default (SEC 17a-4 flavor)


class QualificationRegistry(Protocol):
    """The qualification-graph seam. Declared `object` before, which made every
    use of it an error and hid what the gate actually requires of it."""

    def summaries(
        self, classes: tuple[str, ...], now_us: int
    ) -> dict[str, Any] | None: ...


class CredentialVerifier(Protocol):
    """Provider-backed approver verification. Returns a signed receipt; fails
    closed inside `verify` itself."""

    def verify(
        self, actor_id: str, tenant: str, role: str, *,
        jurisdiction: str | None, now_us: int,
    ) -> Any: ...


_LOG = logging.getLogger(__name__)
_OUTAGES = (KmsUnavailable, WormUnavailable, ReleaseAdmissionUnavailable, OperationalError)


def _component(down: Exception) -> str:
    if isinstance(down, OperationalError):
        return "authority-store"
    if isinstance(down, ReleaseAdmissionUnavailable):
        return "session-admission"
    return "write-once-evidence" if isinstance(down, WormUnavailable) else "signer"


def require_retention_store(store: WormStore) -> None:
    """Reject incomplete retention configuration without invoking storage."""
    if any(not callable(getattr(store, name, None))
           for name in ("anchor", "fetch", "verify")):
        raise ValueError("explicit retention operations required")


class _RegulatedGateBase:
    """The reusable recipe. A domain subclass sets the class attributes and implements `_verify`/`_audit`."""

    VERTICAL: str = ""
    CONTENT_TYPE: str = ""
    DRAFT_ACTION: str = ""
    EMIT_ACTION: str = ""
    DATA_CLASSES: frozenset[DataClass] = frozenset()
    PURPOSE: str = "regulated:emit"
    RISK_TIER: int = 3

    def __init__(self, engine: RegulatedEngine, *, verifier_signers: dict[str, Signer],
                 worm: WormStore, worm_retain_us: int = _YEARS7,
                 credential_verifier: CredentialVerifier | None = None,
                 required_jurisdiction: str | None = None,
                 qualifications: QualificationRegistry | None = None,
                 review_store: ReviewStore | None = None, outage_alarm: OutageAlarm | None = None,
                 membership_evidence: ReviewMembershipEvidence | None = None,
                 release_readiness: ReleaseReadiness | None = None) -> None:
        require_retention_store(worm)
        self._engine = engine
        # Paper A 5.3 (A17): an outage of the signer, key store or evidence store is reported through this channel,
        # which depends on none of them; the default is the structured log a CloudWatch metric filter alarms on.
        self._outage: OutageAlarm = outage_alarm if outage_alarm is not None else LogOutageAlarm()
        self._vsign = verifier_signers
        # Mandatory (Paper A Appendix B item 1): no gate exists that could release without write-once evidence.
        self._worm = worm
        self._worm_retain_us = worm_retain_us
        self._credverify = credential_verifier     # optional: provider-backed approver verification
        self._jurisdiction = required_jurisdiction
        self._qualifications = qualifications       # optional: qualification-graph registry (engineering trust)
        self._review_store = review_store
        self._release_readiness = release_readiness
        # A membership provider contains one authenticated request. Hosts must
        # construct this gate per request, never mutate a shared gate to bind it.
        self._membership_evidence = membership_evidence
        if membership_evidence is not None:
            if review_store is None:
                raise ValueError("membership reviews require a configured review store")
            ApprovalExchange(self, review_store, membership_evidence=membership_evidence)

    # --- domain hooks ----------------------------------------------------------
    def _verify(self, draft: str, contract: dict[str, Any], *, assertion_id: str, content_digest: str,
                tenant_id: str, now_us: int) -> tuple[SignedVerification, ...]:
        raise NotImplementedError

    def _verify_for_context(self, draft: str, contract: dict[str, Any], *, assertion_id: str,
                            content_digest: str, context: EmissionContext) -> tuple[SignedVerification, ...]:
        return self._verify(draft, contract, assertion_id=assertion_id, content_digest=content_digest,
                            tenant_id=context.tenant, now_us=context.now_us)

    def _audit(self, *, envelope: Any, assertion: Assertion, approval_cert: Any, permit: Any,
               qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def _qualification_summaries(
        self, assertion: Assertion, now_us: int
    ) -> dict[str, Any] | None:
        """Resolve the current qualification (by digest, plus a small summary) for each verifier that
        attested this assertion. This is the ONE point the qualification graph feeds the decision graph;
        the evidence record's own signature makes the reference tamper-evident."""
        if self._qualifications is None:
            return None
        classes = tuple(sorted({v.result.verification_class for v in assertion.verifications}))
        return self._qualifications.summaries(classes, now_us)

    def _resolved_policy(self, content_type: str) -> ConsequencePolicy:
        """Fail CLOSED when no policy owns this content type.

        `PolicyRegistry.resolve` returns None for an unregistered type and the
        callers dereferenced it directly -- an AttributeError deep inside a
        compliance decision. This raising form is for `request_approval`, which
        has no verdict return seam. `review_draft` denies in place instead
        (GATE4-F1), because losing the operator-visible reason would be a
        regression even though refusing is correct.
        """
        policy = self._engine._registry.resolve(content_type)
        if policy is None:
            raise ValueError(f'no consequence policy owns content type {content_type!r}')
        return policy

    # --- shared machinery ------------------------------------------------------
    def _build(
        self, contract: dict[str, Any], context: EmissionContext
    ) -> tuple[Assertion, Action, Any, PolicyContext]:
        draft = str(contract.get("body", ""))
        cd = sha256(draft.encode()).hexdigest()
        aid = f"{self.VERTICAL}:{context.nonce}"
        verifs = self._verify_for_context(draft, contract, assertion_id=aid, content_digest=cd, context=context)
        assertion, action, pctx = self._subject(contract, context, verifs)
        cap = self._engine._preflight.authorize(
            tenant_id=context.tenant, vertical=self.VERTICAL, action_id=self.EMIT_ACTION, risk_tier=self.RISK_TIER,
            # Issued on the engine's trusted clock, the same clock the decision is judged on (review 3107).
            correlation_id=pctx.correlation_id, now_us=self._engine.targets.now_us(), ttl_us=_HOUR,
            nonce=f"{context.nonce}-cap")
        return assertion, action, cap, pctx

    def _subject(self, contract: Mapping[str, Any], context: EmissionContext,
                 verifs: tuple[Any, ...]) -> tuple[Assertion, Action, PolicyContext]:
        """What a decision about this contract is about: the assertion, the signed action naming its effect, and
        the requester's context. Shared by every decision and every recorded refusal, so both name one subject."""
        draft = str(contract.get("body", ""))
        cd = sha256(draft.encode()).hexdigest()
        aid = f"{self.VERTICAL}:{context.nonce}"
        prov = contract.get("provenance") or {}
        lineage = ProducerLineage(
            "agent-factory", str(prov.get("run_id", "run-0")), str(prov.get("model_id", "unknown")),
            sha256(str(prov.get("prompt", "p")).encode()).hexdigest(),
            sha256(str(prov.get("policy", "pol")).encode()).hexdigest(),
            sha256(str(prov.get("gate", "g")).encode()).hexdigest())
        assertion = Assertion(
            assertion_id=aid, tenant_id=context.tenant, content_type=self.CONTENT_TYPE, content_digest=cd,
            data_classes=self.DATA_CLASSES, verifications=verifs, lineage=lineage,
            payload_ref=str(contract.get("payload_ref", f"vault://{self.VERTICAL}/{context.nonce}")))
        # The reviewed destination includes the whole contract, not just its
        # prose: a rubric or source change must invalidate prior approval too.
        action = Action(self.EMIT_ACTION, ActionEffect.EXTERNAL,
                        destination=self._destination(dict(contract), context))
        corr = f"{self.VERTICAL}-{context.nonce}"
        pctx = PolicyContext(
            tenant_id=context.tenant,
            actor=Actor(actor_id=context.actor_id, tenant_id=context.tenant,
                        roles=frozenset(context.actor_roles), producer=context.is_producer),
            purpose=self.PURPOSE, correlation_id=corr, now_us=context.now_us)
        return assertion, action, pctx

    def _recorded_refusal(self, contract: Mapping[str, Any], context: EmissionContext, code: str,
                          reason: str) -> EmissionDecision:
        """A refusal decided before the policy runs (the authority behind the gate is missing or changed), written
        to the signed evidence chain like every other decision, so no refused attempt goes unrecorded."""
        assertion, action, pctx = self._subject(contract, context, ())
        envelope = self._engine.record_refusal(assertion=assertion, action=action, ctx=pctx, code=code,
                                               reason=reason)
        return EmissionDecision(allowed=False, reason=reason,
                                evidence={"refusal_record_id": envelope.record.record_id,
                                          "refusal_record_hash": envelope.record_hash})

    @staticmethod
    def _destination(contract: dict[str, Any], context: EmissionContext) -> str:
        contract_digest = sha256(json.dumps(contract, sort_keys=True, separators=(",", ":"),
                                           default=str, allow_nan=False).encode()).hexdigest()
        destination: dict[str, Any] = {"vertical": context.vertical_name, "project": context.project_id,
                                       "action": context.action_id, "contract_digest": contract_digest}
        if context.review_producer_id:
            destination["review_producer_id"] = context.review_producer_id
        named = contract.get(RELEASE_AUTHORITY_FIELD)
        if isinstance(named, dict) and "refused" not in named:
            # The delegated binding travels in the signed action beside the effect, so approval covers it and the
            # core re-resolves exactly what was approved (docs/ARCHITECTURE-OF-RECORD/13).
            destination[RELEASE_AUTHORITY_FIELD] = named
        effect = _RegulatedGateBase._approved_effect(contract)
        if effect is not None:
            # The effect is part of the signed action, so review, approval and the release decision all cover it
            # and the core reads it from there; nothing beside the decision can name a different one.
            return effect_destination(destination, effect)
        return json.dumps(destination, sort_keys=True, separators=(",", ":"))

    def _delegation_refusal(self, contract: Mapping[str, Any], context: EmissionContext) -> EmissionDecision | None:
        """A host that could not resolve a delegated invocation says so in the contract (docs/ARCHITECTURE-OF-RECORD
        13); a malformed binding is refused the same way. Either is signed evidence on the one chain, never only a
        host exception, and no review or release proceeds past it."""
        try:
            release_authority_of(contract.get(RELEASE_AUTHORITY_FIELD))
        except DelegationError as unresolved:
            code = "DELEGATION_UNRESOLVED" if "unresolved" in str(unresolved) else "DELEGATION_MALFORMED"
            return self._recorded_refusal(contract, context, code, str(unresolved))
        return None

    def _trusted(self, context: EmissionContext) -> EmissionContext:
        """The context with its present replaced by the engine's trusted clock (review 3107). Every entry point decides,
        records, approves and issues on this clock; a caller's `now_us` is never believed."""
        return replace(context, now_us=self._engine.targets.now_us())

    def review_draft(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext) -> EmissionDecision:
        context = self._trusted(context)
        refused = self._delegation_refusal(contract, context)
        if refused is not None:
            return refused
        assertion, _action, _cap, pctx = self._build(contract, context)
        if not self._engine._vtrust.authenticate(assertion):
            return EmissionDecision(allowed=False, reason="verification forged or untrusted")
        policy = self._engine._registry.resolve(assertion.content_type)
        if policy is None:
            # GATE4-F1: this is the REVERSIBLE draft-review boundary, and its
            # contract is to return a verdict. Raising here would skip
            # ProjectEngine.assemble's `regulated_draft` denial record, so the
            # operator would lose the visible in-place reason. Deny, and name
            # the unowned content type in the reason.
            return EmissionDecision(
                allowed=False,
                reason=f"no consequence policy owns content type {assertion.content_type!r}")
        decision = policy.evaluate(assertion, Action(self.DRAFT_ACTION, ActionEffect.REVERSIBLE), pctx)
        allowed = decision.kind in (DecisionKind.ALLOW, DecisionKind.ALLOW_WITH_ANNOTATION)
        reason = "" if allowed else f"{decision.reason_codes[0]}: {decision.rationale}"
        return EmissionDecision(allowed=allowed, reason=reason,
                                evidence={"decision": {"kind": decision.kind.value, "reason_codes": list(decision.reason_codes)}})

    def _review_credential(self, actor_id: str, role: str, contract: dict[str, Any],
                           context: EmissionContext) -> Any:
        if self._credverify is None:
            raise CredentialError("review credential authority is not configured")
        scoped = getattr(self._credverify, "verify_review", None)
        if callable(scoped):
            return scoped(actor_id, context.tenant, role, contract=contract, context=context,
                          jurisdiction=self._jurisdiction)
        return self._credverify.verify(actor_id, context.tenant, role,
                                       jurisdiction=self._jurisdiction, now_us=context.now_us)

    def request_approval(self, contract: dict[str, Any], context: EmissionContext,
                         approvers: tuple[Actor, ...]) -> ApprovalCertificate:
        context = self._trusted(context)
        if getattr(self._credverify, "requires_stored_review", False):
            raise CredentialError("scoped pilot authority requires the stored human-review workflow")
        refused = self._delegation_refusal(contract, context)
        if refused is not None:
            raise ValueError(refused.reason)          # recorded on the signed chain; nobody approves it
        try:
            return self._request_approval(contract, context, approvers)
        except _OUTAGES as down:
            raise ValueError(self._raise_outage(down, "request_approval", context, effect_possible=False)) from None

    def _request_approval(self, contract: dict[str, Any], context: EmissionContext,
                          approvers: tuple[Actor, ...]) -> ApprovalCertificate:
        assertion, action, _cap, pctx = self._build(contract, context)
        policy = self._resolved_policy(assertion.content_type)
        decision = policy.evaluate(assertion, action, pctx)
        if decision.kind is not DecisionKind.REQUIRE_APPROVAL:
            raise ValueError(f"nothing to approve: decision is {decision.kind.value}")
        if decision.approval is None:
            # DEFENCE IN DEPTH, NOT A DISCOVERED VULNERABILITY (GATE4-F2). I first
            # described this as closing an "unbounded approval request"; that was
            # wrong, and the reviewer was right to reject the claim.
            # `Decision.__post_init__` already refuses REQUIRE_APPROVAL without an
            # ApprovalRequirement, so this branch is UNREACHABLE through the
            # constructor. It is kept only so the type is narrowed locally and a
            # future change to that invariant fails here rather than silently.
            raise ValueError("approval required but no requirement was stated")
        # The decision a human is asked to approve is recorded, so the release can validate against exactly it on the
        # trusted clock (review 3107): approval time is the approved record's, never a caller's re-timed copy.
        approved_envelope = self._engine._recorder.record(assertion, action, pctx, policy.ref, decision)
        record, rh = approved_envelope.record, approved_envelope.record_hash
        req = self._engine._approvals.open(
            request_id=f"req:{context.nonce}", requester_id=context.actor_id, tenant_id=context.tenant,
            assertion_id=assertion.assertion_id, decision_record_id=record.record_id,
            decision_record_hash=rh, requirement=decision.approval, now_us=context.now_us)
        grants = []
        for a in approvers:
            if self._credverify is not None:
                # provider-backed: verify the approver's claimed role against the identity/licence
                # providers and grant against the SIGNED receipt (fail-closed inside verify()).
                role = next(iter(a.roles), "")
                receipt = self._review_credential(a.actor_id, role, contract, context)
                grants.append(self._engine._approvals.grant(req, a, context.now_us, receipt=receipt))
            else:
                grants.append(self._engine._approvals.grant(req, a, context.now_us))
        return self._engine._approvals.finalize(req, grants, context.now_us)

    def authorize_release(self, *, spec: VerticalSpec, contract: dict[str, Any], out_path: str,
                          context: EmissionContext, artifact: bytes) -> EmissionDecision:
        """Decide a release of exactly `artifact` to `out_path`. On allow, the decision carries a v2 permit bound
        to those bytes and that target; nothing is written until `commit_release`. There is no other release path."""
        try:
            return self._authorize_available_release(
                spec=spec, contract=contract, out_path=out_path, context=context, artifact=artifact)
        except OperationalError as down:
            reason = self._raise_outage(down, "authorize_release", context, effect_possible=False)
            return EmissionDecision(allowed=False, reason=reason,
                                    evidence={"outage": _component(down), "signed": False})

    def _authorize_available_release(self, *, spec: VerticalSpec, contract: dict[str, Any],
                                     out_path: str, context: EmissionContext,
                                     artifact: bytes) -> EmissionDecision:
        """Preserve entry, review and authority checks inside the store-outage boundary."""
        context = self._trusted(context)
        refused = self._delegation_refusal(contract, context)
        if refused is not None:
            return refused
        if isinstance(context.approval, str):
            try:
                context = self._exchange().resolve(contract, context, context.approval)
            except ReviewError as exc:
                return EmissionDecision(allowed=False, reason=str(exc))
        guard = getattr(self._credverify, "review_guard", None)
        approved = context.approval if isinstance(context.approval, ApprovedDecision) else None
        actors = tuple(r.subject_id for r in approved.credential_receipts) if approved is not None else ()
        try:
            with guard(contract=contract, context=context, actors=actors) if callable(guard) else nullcontext():
                if self._release_readiness is not None:
                    self._release_readiness()
                return self._authorize_release(contract=contract, out_path=out_path, context=context,
                                               artifact=artifact)
        except ProductionReadinessError as exc:
            return self.record_entrance_refusal(spec=spec, contract=contract, context=context,
                                               code="PRODUCTION_ASSURANCE_UNAVAILABLE", reason=str(exc))
        except CredentialError as exc:
            return EmissionDecision(allowed=False, reason=str(exc))
        except _OUTAGES as down:
            reason = self._raise_outage(down, "authorize_release", context, effect_possible=False)
            return EmissionDecision(allowed=False, reason=reason, evidence={"outage": _component(down), "signed": False})

    def target_for(self, out_path: str, tenant: str) -> TargetAdapter:
        """The adapter that alone writes this release target, checking every permit at the target."""
        return FilesystemTargetAdapter(path=Path(out_path), tenant_id=tenant, authority=self._engine.targets,
                                       uses=self._engine._emission.uses, operation_name=self.EMIT_ACTION,
                                       budget=self._engine.budget)

    def describe_target(self, *, spec: VerticalSpec, out_path: str, context: EmissionContext) -> Mapping[str, str]:
        adapter = self.target_for(out_path, context.tenant)
        return {"kind": adapter.target.kind, "identity": adapter.target.identity,
                "expected_state": adapter.current_state()}

    @contextmanager
    def _release_admission(
        self, contract: Mapping[str, Any], context: EmissionContext, decision: EmissionDecision,
    ) -> Iterator[Callable[[], None] | None]:
        """Bind domain admission to the intact decision before taking pack locks."""
        admit = getattr(self._credverify, "admit_release", None)
        if not callable(admit):
            if getattr(self._credverify, "requires_stored_review", False):
                raise CredentialError("stored review requires domain release admission")
            yield None
            return
        auth = decision.permit
        if not decision.allowed or not isinstance(auth, TargetAuthorization) or auth.permit is None:
            raise CredentialError("no target authority for session admission")
        envelope, permit = auth.envelope, auth.permit.permit
        try:
            expected = sha256(json.dumps(dict(contract), sort_keys=True, separators=(",", ":"),
                                         default=str, allow_nan=False).encode()).hexdigest()
            destination = json.loads(envelope.record.action.destination)
        except (TypeError, ValueError) as error:
            raise CredentialError("release decision has no contract binding") from error
        if (not self._engine._recorder.verify_entry(envelope)
                or permit.decision_record_hash != envelope.record_hash
                or permit.decision_record_id != envelope.record.record_id
                or envelope.record.tenant_id != context.tenant
                or envelope.record.actor_id != context.actor_id
                or not isinstance(destination, dict) or destination.get("contract_digest") != expected):
            raise CredentialError("session admission does not match the approved release")
        # Reviewer session SHARE locks precede the domain's requester/lifecycle
        # admission. Neither callback signs or substitutes current credentials.
        with self._reviewer_admission(contract, context, auth) as reviewer_current:
            with admit(contract=contract, context=context, authorization=auth) as current:
                if not callable(current):
                    raise CredentialError("release admission did not provide a final effect check")
                def before_effect():
                    if reviewer_current is not None:
                        reviewer_current()
                    current()
                    if reviewer_current is not None:
                        reviewer_current()
                yield before_effect

    @contextmanager
    def _reviewer_admission(self, contract, context, authorization):
        admit = getattr(self._credverify, "admit_reviewers", None)
        if not callable(admit):
            if getattr(self._credverify, "requires_stored_review", False):
                raise CredentialError("stored review requires reviewer session admission")
            yield None
            return
        permit = authorization.permit.permit
        if not permit.approval_ref:
            raise CredentialError("session-bound release requires retained reviewer approval")
        try:
            resolved = self._exchange().resolve(dict(contract), context, permit.approval_ref)
        except (ReviewError, KeyError, TypeError, ValueError) as error:
            raise CredentialError("retained reviewer approval unavailable or invalid") from error
        approved = resolved.approval
        record = authorization.envelope.record
        if (not isinstance(approved, ApprovedDecision) or not approved.credential_receipts
                or approved.certificate.request_id != permit.approval_ref
                or replace(approved.envelope.record, record_id=record.record_id,
                           decided_at_us=record.decided_at_us) != record):
            raise CredentialError("reviewer approval differs from the authorized decision")
        with admit(receipts=approved.credential_receipts, tenant=context.tenant,
                   not_after_us=permit.expires_at_us) as current:
            if not callable(current):
                raise CredentialError("reviewer admission did not provide a final check")
            yield current


    def commit_release(self, *, spec: VerticalSpec, contract: Mapping[str, Any], decision: EmissionDecision,
                       artifact: bytes, out_path: str, context: EmissionContext) -> ReleaseOutcome:
        try:
            with self._release_admission(contract, context, decision) as current:
                return self._commit_admitted_release(
                    spec=spec, contract=contract, decision=decision, artifact=artifact,
                    out_path=out_path, context=context, effect_check=current,
                )
        except CredentialError as refused:
            return self._cancel_refused_release(decision, out_path, context, str(refused))
        except ReleaseAdmissionUnavailable as down:
            self._cancel_refused_release(decision, out_path, context, str(down))
            return ReleaseOutcome("unknown", str(down))
        except OperationalError as down:
            # Admission/clock/target setup or admission exit can fail outside
            # engine.commit. Do not infer whether a permitted effect occurred.
            reason = self._raise_outage(down, "commit_release", context, effect_possible=True)
            return ReleaseOutcome("unknown", reason,
                                  {"outage": _component(down), "signed": False})

    def _cancel_refused_release(
        self, decision: EmissionDecision, out_path: str, context: EmissionContext, reason: str,
    ) -> ReleaseOutcome:
        """Reclaim a refused release only through its authenticated target."""
        authorization = decision.permit
        if (not decision.allowed or not isinstance(authorization, TargetAuthorization)
                or authorization.permit is None):
            return ReleaseOutcome("failed", reason)
        p = authorization.permit.permit
        if p.tenant_id != context.tenant or p.principal != context.actor_id:
            return ReleaseOutcome("failed", reason)
        target = self.target_for(out_path, context.tenant)
        if not isinstance(target, FilesystemTargetAdapter):
            return ReleaseOutcome("unknown", reason + "; target cancellation unavailable")
        try:
            result = self._engine.cancel(authorization, target)
        except Exception:
            return ReleaseOutcome("unknown", reason + "; cancellation outcome needs reconciliation")
        return ReleaseOutcome(result.outcome.value, reason + "; " + result.detail,
                              {"outcome_record_id": result.envelope.record.record_id,
                               "outcome_record_hash": result.envelope.record_hash})

    def _commit_admitted_release(
        self, *, spec: VerticalSpec, contract: Mapping[str, Any], decision: EmissionDecision,
        artifact: bytes, out_path: str, context: EmissionContext,
        effect_check: Callable[[], None] | None,
    ) -> ReleaseOutcome:
        context = self._trusted(context)
        authorization = decision.permit
        if not decision.allowed or not isinstance(authorization, TargetAuthorization):
            return ReleaseOutcome("failed", "no target permit was issued for this release")
        if self._release_readiness is not None:
            try:
                window = self._release_readiness()
            except ProductionReadinessError as refused:
                return self._cancel_refused_release(decision, out_path, context, str(refused))
            session_check = effect_check

            def check_current() -> None:
                if session_check is not None:
                    session_check()
                try:
                    window.check_current()
                except ProductionReadinessError as refused:
                    raise EmissionError(str(refused)) from refused

            effect_check = check_current
        target = self.target_for(out_path, context.tenant)
        if effect_check is not None:
            if not isinstance(target, FilesystemTargetAdapter):
                return ReleaseOutcome("failed", "target does not support retained session admission")
            target = replace(target, effect_check=effect_check)
        try:
            outcome = self._engine.commit(authorization, artifact, target)
            if outcome.outcome is Outcome.UNKNOWN:
                outcome = self._engine.reconcile(authorization, target)
        except _OUTAGES as down:
            # The target may or may not have committed before the outcome record failed to sign: the outcome is
            # unknown, never failed, and it is resolved later from the target's receipts (Paper A 5.2).
            reason = self._raise_outage(down, "commit_release", context, effect_possible=True)
            return ReleaseOutcome("unknown", reason, {"outage": _component(down), "signed": False})
        return ReleaseOutcome(outcome.outcome.value, outcome.detail,
                              {"outcome_record_id": outcome.envelope.record.record_id,
                               "outcome_record_hash": outcome.envelope.record_hash})

    def reconcile_release(self, *, spec: VerticalSpec, artifact_sha256: str, out_path: str,
                          context: EmissionContext, nonce: str) -> ReleaseOutcome:
        adapter = self.target_for(out_path, context.tenant)
        found = adapter.status_of(context.tenant, nonce, artifact_sha256)
        # The receipt answers whether the commit happened; whether the target STILL holds the bytes is a separate
        # fact, reported so the caller never hands back a target that has since changed.
        return ReleaseOutcome(found.outcome.value, found.detail,
                              {"target_holds": adapter.current_state() == artifact_sha256})

    def record_entrance_refusal(self, *, spec: VerticalSpec, contract: Mapping[str, Any], context: EmissionContext,
                                code: str, reason: str) -> EmissionDecision:
        """Record, on the signed evidence chain, a regulated effect refused at an entrance before any decision (an
        export of a regulated vertical, for example), so no refused attempt goes unrecorded (claims row A01)."""
        try:
            return self._recorded_refusal(contract, context, code, reason)
        except _OUTAGES as down:
            outage = self._raise_outage(down, "record_entrance_refusal", context, effect_possible=False)
            return EmissionDecision(allowed=False, reason=f"{reason}; {outage}",
                                    evidence={"outage": _component(down), "signed": False})

    def _approved_record(self, certificate: Any, tenant: str) -> SignedDecisionEnvelope | None:
        """The recorded decision a direct approval certificate approves, from this engine's own evidence chain, or None.
        The engine then checks the certificate binds exactly that record, and the current decision still equals it."""
        if not isinstance(certificate, ApprovalCertificate):
            return None
        for envelope in reversed(self._engine._recorder.entries(tenant)):
            if (envelope.record.record_id == certificate.decision_record_id
                    and envelope.record_hash == certificate.decision_record_hash):
                return envelope
        return None

    def _raise_outage(self, down: Exception, operation: str, context: EmissionContext, *,
                      effect_possible: bool) -> str:
        """Raise the independent alarm and return plain, unsigned text that is true for this phase.

        Contained: a failure of the alarm channel itself falls back to the default log channel and never escapes, so
        it can never suppress the refusal or the UNKNOWN outcome the caller must still record (review 3097)."""
        component = _component(down)
        # CRITICAL when an effect may have happened and its outcome is unknown; HIGH when nothing was released.
        # The alarm must remain observable when its authority clock shares the
        # failed dependency. An unavailable timestamp is explicit, not fabricated.
        try:
            at_us = self._engine.targets.now_us()
        except Exception as clock_error:
            at_us = None
            # Keep the exception class observable without logging its message
            # or consulting the failed store. Logging must not mask the alarm.
            try:
                _LOG.warning("authority alarm timestamp unavailable: %s",
                             type(clock_error).__name__,
                             extra={"clock_error_type": type(clock_error).__name__})
            except Exception:
                pass
        event = OutageEvent(tenant_id=context.tenant, component=component, operation=operation,
                            detail=type(down).__name__, at_us=at_us,
                            severity=Severity.CRITICAL if effect_possible else Severity.HIGH,
                            phase="outcome-unknown" if effect_possible else "contained")
        try:
            self._outage.raise_alarm(event)
        except Exception:
            LogOutageAlarm().raise_alarm(event)
        if effect_possible:
            return (f"authority outage in the {component} during commit handling: a permitted effect may have occurred; the outcome "
                    "is unknown, no signed outcome record could be made, and it must be resolved from the target's "
                    "receipts; an independent alarm was raised")
        return (f"authority outage in the {component}: nothing was released and no signed record could be made; "
                "an independent alarm was raised")

    def _authorize_release(self, *, contract: dict[str, Any], out_path: str, context: EmissionContext,
                           artifact: bytes) -> EmissionDecision:
        """The one covered path: a permit bound to the artifact and the target, evidence anchored before it."""
        assertion, action, cap, pctx = self._build(contract, context)
        approved = context.approval if isinstance(context.approval, ApprovedDecision) else None
        if getattr(self._credverify, "requires_stored_review", False):
            validate = getattr(self._credverify, "validate_review", None)
            if approved is None or not approved.credential_receipts or not callable(validate):
                return EmissionDecision(allowed=False, reason="scoped pilot release requires retained reviewer credentials")
            try:
                for credential_receipt in approved.credential_receipts:
                    validate(credential_receipt, contract=contract, context=context)
            except CredentialError as exc:
                return EmissionDecision(allowed=False, reason=str(exc))
        certificate = approved.certificate if approved is not None else context.approval
        quals = self._qualification_summaries(assertion, context.now_us)
        summaries = quals.values() if isinstance(quals, dict) else ()
        receipt = None

        def retain_before_permit() -> None:
            nonlocal receipt
            retained = anchor_evidence_chain(self._worm, self._engine._recorder, context.tenant,
                                             retain_us=self._worm_retain_us, now_us=context.now_us)
            if not self._worm.verify(retained):
                raise WormUnavailable("anchored evidence did not verify; no permit is issued")
            receipt = retained

        auth = self._engine.authorize_for_target(
            vertical=self.VERTICAL, capability=cap, assertion=assertion, action=action, ctx=pctx, output=artifact,
            target=self.target_for(out_path, context.tenant), permit_ttl_us=_HOUR, nonce=context.nonce,
            # The host deadline for this request (a recoverable attempt): no permit issued for it outlives it.
            not_after_us=context.not_after_us,
            qualification_digests=tuple(sorted(str(q["report_digest"]) for q in summaries
                                               if isinstance(q, dict) and q.get("report_digest"))),
            approval_cert=certificate,
            approval_evidence=(approved.envelope if approved is not None
                               else self._approved_record(certificate, context.tenant)),
            retain_before_permit=retain_before_permit)
        evidence = self._evidence(auth, assertion=assertion, certificate=certificate, approved=approved, quals=quals)
        if auth.authorized:
            # The explicitly configured shared engine retains the exact full
            # action leaf before witnessing; legacy compositions retain a chain.
            shared = getattr(self._engine, "shared_evidence", None)
            if shared is not None:
                receipt = shared.receipt_for(context.tenant, auth.envelope.seq)
            evidence = bind_worm_receipt(evidence, receipt)
        return EmissionDecision(allowed=auth.authorized, reason=auth.reason or auth.decision_kind,
                                evidence=evidence, permit=auth if auth.authorized else None)

    def _return_unreleased_reservation(self, auth: TargetAuthorization) -> None:
        """The permit never left this gate, so no authority was issued against its mission reservation: return it, or
        one evidence-store outage would spend the mission for good and leave the work unreleasable (A14, A07). Safe even
        if the permit escaped: a released reservation can no longer be consumed, so the target would refuse it. A
        failure to return it leaves the reservation held, the conservative side, and never masks the outage."""
        permit = auth.permit.permit if auth.permit is not None else None
        if permit is None or not permit.mission or permit.budget_reservation in ("", UNBUDGETED):
            return
        try:
            self._engine.budget.release(permit.tenant_id, permit.mission, permit.budget_reservation)
        except Exception:  # noqa: BLE001 - the outage being raised is what the caller must see
            pass

    @staticmethod
    def _approved_effect(contract: Mapping[str, Any]) -> BoundEffect | None:
        """The effect a governed contract names: the prepared bytes' digest, the declared target with its prior
        state, and the mission whose budget it draws on. A contract without them names no effect, and the door
        denies any release against it. The contract is what approval covers, so all of these are approved."""
        prepared, target = contract.get(PREPARATION_FIELD), contract.get(TARGET_FIELD)
        if not isinstance(prepared, Mapping) or not isinstance(target, Mapping):
            return None
        return BoundEffect(output_digest=str(prepared.get("artifact_sha256", "")),
                           target=TargetRef(str(target.get("kind", "")), str(target.get("identity", ""))),
                           target_state=str(target.get("expected_state", "")),
                           mission=str(contract.get(MISSION_FIELD, "")))

    def _evidence(self, auth: TargetAuthorization, *, assertion: Assertion, certificate: Any,
                  approved: ApprovedDecision | None, quals: Any) -> dict[str, Any]:
        """The evidence pack: the decision, the permit, both mechanisms (qualification by digest and the approvers'
        verified credential receipts), and the target the permit binds."""
        permit = auth.permit.permit if auth.permit is not None else None
        evidence = self._audit(envelope=auth.envelope, assertion=assertion,
                               approval_cert=certificate if isinstance(certificate, ApprovalCertificate) else None,
                               permit=permit, qualifications=quals)
        if permit is not None:
            evidence["target"] = {"kind": permit.target_kind, "digest": permit.target_digest,
                                  "operation": permit.operation, "expected_state": permit.expected_target_state,
                                  "mission": permit.mission, "budget_reservation": permit.budget_reservation,
                                  # The schema the permit was actually signed under: a delegated release is v3.
                                  "permit_schema": permit.signed_body()["schema"]}
            if permit.grant_digest:
                # The delegated chain the effect was released under, so the evidence names the authority it used.
                evidence["target"].update(grant_digest=permit.grant_digest, chain_digest=permit.chain_digest,
                                          root_digest=permit.root_digest)
        if approved is not None and self._engine._recorder.verify_entry(approved.envelope):
            evidence["approval_decision"] = json.loads(canonical_bytes(approved.envelope))
            authority = self._engine._approvals
            receipts = approved.credential_receipts
            if (receipts and isinstance(certificate, ApprovalCertificate)
                    and tuple(sorted(r.digest() for r in receipts)) == certificate.credential_receipt_digests
                    and all(authority.verify_credential_signature(r) for r in receipts)):
                evidence["approval_credential_receipts"] = json.loads(canonical_bytes(receipts))
        return evidence

    def _exchange(self) -> ApprovalExchange:
        if self._review_store is None:
            raise ReviewError("governed human review store is not configured")
        return ApprovalExchange(
            self, self._review_store, membership_evidence=self._membership_evidence,
        )

    @staticmethod
    def _review_scope(spec: VerticalSpec, context: EmissionContext) -> None:
        if spec.regulated is None or context.vertical_name != spec.name or not context.project_id:
            raise ReviewError("human review requires the authenticated vertical and project")

    def get_source_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        self._review_scope(spec, context)
        return {"required": False}

    def open_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        """Prepare a stored review of this exact project contract."""
        self._review_scope(spec, context)
        return self._exchange().open(contract, context)

    def resolve_review_context(self, *, spec: VerticalSpec, contract: dict[str, Any],
                               context: EmissionContext) -> EmissionContext:
        """Resolve server-owned action bindings before ProjectOS checks release idempotency."""
        self._review_scope(spec, context)
        if not isinstance(context.approval, str):
            raise ReviewError("stored review reference required")
        return self._exchange().resolve(contract, context, context.approval)

    def verified_release_decision(self, *, spec: VerticalSpec, tenant: str, record_hash: str, nonce: str,
                                  artifact_sha256: str, target: Mapping[str, Any], project_id: str = "",
                                  action_id: str = "") -> SignedDecisionEnvelope | None:
        """The ONE signed decision the attempt recorded (by its exact record hash), verified against the evidence
        authority now and checked against that attempt: this tenant, this vertical's release action and nonce, and a
        bound effect naming exactly these bytes, this target and its prior state. Never the latest decision that
        merely reuses the nonce; None when the exact envelope is absent or any binding differs (review 3195)."""
        # The same decision record may be appended more than once (approval, then authorization); every copy has
        # the same record hash and content, so the earliest verified copy is that exact decision.
        matches = [envelope for envelope in self._engine._recorder.entries(tenant)
                   if envelope.record_hash == record_hash and self._engine._recorder.verify_entry(envelope)]
        if not matches:
            return None
        record = matches[0].record
        effect = effect_of(record.action.destination)
        if (record.tenant_id != tenant or record.assertion_id != f"{self.VERTICAL}:{nonce}"
                or record.action.action_id != self.EMIT_ACTION or effect is None
                or effect.output_digest != artifact_sha256
                or effect.target.kind != target.get("kind") or effect.target.identity != target.get("identity")
                or effect.target_state != target.get("expected_state")):
            return None
        # The signed destination itself must name the attempt asked about: this vertical, project and action. A
        # relabelled or copied local record cannot borrow another attempt's genuine envelope (review 3200).
        try:
            signed = json.loads(record.action.destination)
        except ValueError:
            return None
        # The assertion prefix and the release action already bind the vertical, so an unnamed vertical is tolerated;
        # a named one must be this one. The action must be named and be the one asked about. The project is bound by
        # what the HOST signed, never by the caller's context: a named project must be this one; an unnamed one is
        # bound by the host-derived mission "<vertical>:<project>" inside the signed effect. A delegated release's
        # mission is its root's, so a delegated decision must name its project (review 3200, 3207).
        if (not isinstance(signed, dict) or signed.get("vertical") not in ("", spec.name)
                or not signed.get("action") or signed.get("action") != action_id):
            return None
        named_project = signed.get("project")
        if named_project:
            if named_project != project_id:
                return None
        elif RELEASE_AUTHORITY_FIELD in signed or effect.mission != f"{spec.name}:{project_id}":
            return None
        return matches[0]

    def verified_release_outcome(self, *, spec: VerticalSpec, tenant: str,
                                 decision: SignedDecisionEnvelope) -> SignedDecisionEnvelope | None:
        """The signed receiving outcome of EXACTLY that decision: an evidence-chain record for the same signed assertion
        and action, OUTCOME_COMMITTED or RECONCILED_COMMITTED, whose own signed annotations name that decision's record
        hash, verified now. Another decision over the same action never matches (review 3205)."""
        from .engine import OUTCOME_OF_DECISION

        for envelope in self._engine._recorder.entries(tenant):
            record = envelope.record
            named = [a.message for a in record.decision.annotations if a.kind == OUTCOME_OF_DECISION]
            if (record.tenant_id == tenant and record.assertion_id == decision.record.assertion_id
                    and record.action == decision.record.action
                    and record.decision.reason_codes[:1] in (("OUTCOME_COMMITTED",), ("RECONCILED_COMMITTED",))
                    and named == [decision.record_hash]
                    and self._engine._recorder.verify_entry(envelope)):
                return envelope
        return None

    def release_receipt(self, *, spec: VerticalSpec, out_path: str, tenant: str, nonce: str,
                        artifact_sha256: str, decision_record_hash: str = "") -> Mapping[str, str] | None:
        """The receiving target's durable committed receipt for this nonce, only when it names exactly this tenant,
        target, release operation, bytes, nonce and decision; None otherwise. It is the target's own unsigned record;
        the authenticated evidence is the signed outcome record, which it must agree with."""
        adapter = self.target_for(out_path, tenant)
        read = getattr(adapter, "_read_receipt", None)
        receipt = read(nonce, "committed") if callable(read) else None
        if (not isinstance(receipt, dict) or receipt.get("tenant") != tenant
                or receipt.get("target") != adapter.target.digest() or receipt.get("operation") != self.EMIT_ACTION
                or receipt.get("output_digest") != artifact_sha256 or receipt.get("nonce") != nonce
                or not decision_record_hash or receipt.get("decision_record_hash") != decision_record_hash):
            return None
        return {key: str(value) for key, value in receipt.items()}

    def record_delegation_proposal(self, *, assertion: Assertion, action: Action, ctx: PolicyContext) -> SignedDecisionEnvelope:
        """Decide and record a delegation proposal so humans can approve exactly it (see RegulatedEngine). Decided on
        the engine's trusted clock; the caller's present is replaced."""
        return self._engine.record_delegation_proposal(assertion=assertion, action=action,
                                                       ctx=replace(ctx, now_us=self._engine.targets.now_us()))

    def admit_delegation_root(self, envelope: SignedDecisionEnvelope, approval: ApprovalCertificate, *,
                              assertion: Assertion, subject: str, targets: tuple[str, ...], expires_at_us: int,
                              delegable: bool) -> Any:
        """Admit a delegation root only from an APPROVED delegation proposal, through the engine's own admission,
        on its trusted clock. The host's public door to root admission; it never touches the signer."""
        return self._engine.admit_delegation_root(envelope, approval, assertion=assertion, subject=subject,
                                                  targets=targets, expires_at_us=expires_at_us, delegable=delegable,
                                                  now_us=self._engine.targets.now_us())

    def _delegation_exchange(self) -> Any:
        if self._review_store is None:
            raise ReviewError("governed human review store is not configured")
        from .delegation_review import DelegationRootExchange
        return DelegationRootExchange(self, self._review_store)

    def open_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                               destinations: tuple[str, ...], expires_in_us: int, admit_within_us: int,
                               delegable: bool) -> dict[str, Any]:
        """The authenticated owner proposes delegating this project's release (regulated_core/delegation_review.py).
        The host passes only the contract, its authenticated context and plain parameters; never a core object."""
        self._review_scope(spec, context)
        return dict(self._delegation_exchange().open(contract, self._trusted(context), destinations=destinations,
                                                     expires_in_us=expires_in_us, admit_within_us=admit_within_us,
                                                     delegable=delegable))

    def get_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                              delegation_review_id: str) -> dict[str, Any]:
        self._review_scope(spec, context)
        return dict(self._delegation_exchange().get(contract, self._trusted(context), delegation_review_id))

    def grant_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                                delegation_review_id: str, role: str) -> dict[str, Any]:
        """Grant as the authenticated reviewer through the credential authority, like a release review."""
        self._review_scope(spec, context)
        guard = getattr(self._credverify, "review_guard", None)
        try:
            with guard(contract=contract, context=context, actors=(context.actor_id,)) if callable(guard) else nullcontext():
                return dict(self._delegation_exchange().grant(contract, self._trusted(context), delegation_review_id,
                                                              role))
        except CredentialError as exc:
            raise ReviewError(str(exc)) from exc

    def admit_delegation(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                         delegation_review_id: str) -> dict[str, Any]:
        """The owner admits the approved root; returns the verified root reference."""
        self._review_scope(spec, context)
        return dict(self._delegation_exchange().admit(contract, self._trusted(context), delegation_review_id))

    def delegation_root(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                        delegation_review_id: str) -> dict[str, Any]:
        """The verified root a delegation review admitted, with the metadata a child may narrow within."""
        self._review_scope(spec, context)
        return dict(self._delegation_exchange().root(contract, self._trusted(context), delegation_review_id))

    def review_requester(self, *, spec: VerticalSpec, context: EmissionContext, review_id: str) -> str:
        """The verified execution identity that opened a stored review (see ApprovalExchange.requester)."""
        try:
            return self._exchange().requester(context, review_id)
        except ReviewError as exc:
            raise ValueError(str(exc)) from exc

    def get_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                   review_id: str) -> dict[str, Any]:
        """Read verified review status through the entitled project."""
        self._review_scope(spec, context)
        return self._exchange().get(contract, context, review_id)

    def grant_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                     review_id: str, role: str) -> dict[str, Any]:
        """Grant as the authenticated reviewer through the credential authority."""
        self._review_scope(spec, context)
        guard = getattr(self._credverify, "review_guard", None)
        try:
            with guard(contract=contract, context=context, actors=(context.actor_id,)) if callable(guard) else nullcontext():
                return self._exchange().grant(contract, context, review_id, role)
        except CredentialError as exc:
            raise ReviewError(str(exc)) from exc


# --- health: Clinician-Approved Patient Education ---------------------------------------------

class PatientEducationGate(_RegulatedGateBase):
    VERTICAL = "patient-education"
    CONTENT_TYPE = pe.CONTENT_TYPE
    DRAFT_ACTION = pe.CREATE_DRAFT
    EMIT_ACTION = pe.EMIT_TO_PATIENT
    DATA_CLASSES = frozenset({DataClass.PHI})
    PURPOSE = "care:education"

    def _verify(self, draft: str, contract: dict[str, Any], *, assertion_id: str,
                content_digest: str, tenant_id: str,
                now_us: int) -> tuple[SignedVerification, ...]:
        return pe.run_verifiers(draft, tuple(contract.get("sources", ())), assertion_id=assertion_id,
                                content_digest=content_digest, tenant_id=tenant_id, now_us=now_us,
                                verifier_signers=self._vsign,
                                allowed_identifiers=frozenset(contract.get("allowed_identifiers", ())))

    def _audit(self, *, envelope: Any, assertion: Assertion, approval_cert: Any, permit: Any,
               qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
        return pe.audit_export(envelope=envelope, assertion=assertion, approval_cert=approval_cert,
                               permit=permit, qualifications=qualifications)


def patient_education_spec(state_dir: str = "patient_education") -> VerticalSpec:
    d = pe.PATIENT_EDUCATION
    return VerticalSpec(
        name=d.name, axis=AXIS_KNOWLEDGE_BACKED, state_dir=state_dir, id_field="pe_id",
        stages=(StageSpec(id="draft", title="Draft from approved sources", kind=KIND_PROJECT),),
        regulated=RegulatedBlock(
            policy_ref="patient-education/clinician-approved", intended_use=d.intended_use,
            prohibited_uses=d.prohibited_uses, risk_tiers=d.risk_tiers,
            required_verifiers=d.required_verifiers, approver_roles=d.required_approver_roles,
            emission_policy=d.emission_policy))


# --- financial services: Investment Research & Compliance Brief -------------------------------

class InvestmentResearchGate(_RegulatedGateBase):
    VERTICAL = "investment-research"
    CONTENT_TYPE = ir.CONTENT_TYPE
    DRAFT_ACTION = ir.CREATE_DRAFT
    EMIT_ACTION = ir.EMIT_BRIEF
    DATA_CLASSES = frozenset({DataClass.FINANCIAL})
    PURPOSE = "research:brief"

    def _verify(self, draft: str, contract: dict[str, Any], *, assertion_id: str,
                content_digest: str, tenant_id: str,
                now_us: int) -> tuple[SignedVerification, ...]:
        return ir.run_verifiers(draft, tuple(contract.get("sources", ())), assertion_id=assertion_id,
                                content_digest=content_digest, tenant_id=tenant_id, now_us=now_us,
                                verifier_signers=self._vsign)

    def _audit(self, *, envelope: Any, assertion: Assertion, approval_cert: Any, permit: Any,
               qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
        return ir.audit_export(envelope=envelope, assertion=assertion, approval_cert=approval_cert,
                               permit=permit, qualifications=qualifications)


def investment_research_spec(state_dir: str = "investment_research") -> VerticalSpec:
    d = ir.INVESTMENT_RESEARCH
    return VerticalSpec(
        name=d.name, axis=AXIS_KNOWLEDGE_BACKED, state_dir=state_dir, id_field="ir_id",
        stages=(StageSpec(id="draft", title="Draft from approved financial sources", kind=KIND_PROJECT),),
        regulated=RegulatedBlock(
            policy_ref="investment-research/compliance-reviewed", intended_use=d.intended_use,
            prohibited_uses=d.prohibited_uses, risk_tiers=d.risk_tiers,
            required_verifiers=d.required_verifiers, approver_roles=d.required_approver_roles,
            emission_policy=d.emission_policy))
