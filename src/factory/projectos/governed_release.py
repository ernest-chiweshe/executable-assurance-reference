"""The Project OS side of a regulated release: one generic component that knows no domain, product or target kind.

Paper A 4.2 and 5, and approved architecture item 5: before approval, freeze the tenant, operation, target, exact
bytes and preconditions; decide; retain evidence; permit; let the target adapter recheck and commit; record the
outcome separately; resolve a lost acknowledgement from the target, never by re-sending.

What this component owns, and nothing else:

* **Preparation.** The vertical's exporter renders the artifact ONCE into a private temporary path it cannot
  publish from; the bytes go to the tenant's content-addressed artifact store; a preparation record is kept in
  project state. Later renders never replace them, so what was approved is what leaves.
* **The governed contract.** Composed from typed values, `PreparedArtifact` and `ReleaseTarget`; it always names
  its target and the target's prior state. A replay is checked against the recorded decision: the current
  contract, with the target as the decision recorded it, must reproduce the approved digest exactly.
* **The protocol.** Decide through the injected gate, record the decision before any effect, commit through the
  gate's target adapter, record the outcome as its own event, and answer a repeated action from the target's
  receipts.

What it never does: write, read or describe a target itself. The target's kind, identity and current state come
from the governance side through `RegulatedEmissionGate.describe_target`, so this module holds no knowledge of
files, buckets or any other target. The engine calls it and knows nothing of the protocol.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from factory.ledger import ArtifactStore
from factory.projectos.errors import ProjectEngineError
from factory.projectos.regulated import ReleaseObservation
from factory.projectos.regulated import (EmissionContext, ReceiptPinSource, RegulatedEmissionGate, ReleaseOutcome,
                                         ReleaseAuthorityBinding, ReleaseAuthoritySource, ReleaseAuthorityUnavailable)
from factory.projectos.spec import VerticalSpec
from factory.tenant import TenantContext

PREPARATION_SCHEMA = "projectos.prepared-release/v1"
PREPARATION_FIELD = "prepared_release"
TARGET_FIELD = "release_target"
MISSION_FIELD = "release_mission"
RELEASE_AUTHORITY_FIELD = "release_authority"


class GovernedReleaseError(ProjectEngineError):
    """A regulated release was refused or could not be completed; the message says why."""


class ReleaseRefused(GovernedReleaseError):
    """Refused BEFORE the target was handed anything: this call wrote nothing, so its outcome is certain.

    Raised only on the path before `commit_release`. Any error after the hand-off stays a plain
    GovernedReleaseError, whose outcome a caller must treat as unknown and resolve from the target's receipts."""


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass(frozen=True)
class PreparedArtifact:
    """The exact bytes prepared once for one contract version, with the record that describes them."""

    record: Mapping[str, Any]
    content: bytes = field(repr=False)

    @property
    def sha256(self) -> str:
        return str(self.record["artifact_sha256"])

    def binding(self) -> dict[str, str]:
        """What approval and replay both bind: the bytes' digest and the digest of their preparation record."""
        return {"artifact_sha256": self.sha256, "record_digest": _digest(dict(self.record))}


@dataclass(frozen=True)
class ReleaseTarget:
    """Where the release lands, as the governance side describes it."""

    kind: str
    identity: str
    expected_state: str

    @classmethod
    def from_description(cls, description: Mapping[str, str]) -> ReleaseTarget:
        try:
            return cls(str(description["kind"]), str(description["identity"]), str(description["expected_state"]))
        except KeyError as missing:
            raise GovernedReleaseError(f"the gate described the target without {missing}") from missing

    def binding(self) -> dict[str, str]:
        """What approval binds: the target and its prior state, so a changed target voids the approval."""
        return {"kind": self.kind, "identity": self.identity, "expected_state": self.expected_state}



@dataclass(frozen=True)
class GovernedContract:
    """The vertical's contract, the prepared artifact, the declared target and the mission, composed in one place."""

    base: Mapping[str, Any]
    prepared: PreparedArtifact
    target: ReleaseTarget
    mission: str = ""
    authority: ReleaseAuthorityBinding | None = None
    authority_refused: bool = False

    def for_approval(self) -> dict[str, Any]:
        """The contract review, approval and the release decision all bind: the vertical's contract, the prepared
        bytes, the target with its prior state, and the mission whose budget the release draws on."""
        contract = {**self.base, PREPARATION_FIELD: self.prepared.binding(), TARGET_FIELD: self.target.binding(),
                    MISSION_FIELD: self.mission}
        if self.authority_refused:
            contract[RELEASE_AUTHORITY_FIELD] = {"schema": "regulated/release-authority/v1",
                                                 "refused": "delegated release authority unavailable"}
        elif self.authority is not None:
            contract[RELEASE_AUTHORITY_FIELD] = self.authority.as_fields()
        return contract

    def digest(self) -> str:
        return _digest(self.for_approval())

    def with_prior_state(self, expected_state: str) -> GovernedContract:
        """This contract with the same target, in the state a prior decision approved it in. Only the state is
        taken from the record; the kind and identity stay this request's, so a changed target never matches."""
        return replace(self, target=replace(self.target, expected_state=expected_state))


def vertical_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """The vertical's own contract inside a governed one: the inverse of `GovernedContract.for_approval`.

    A domain authority that binds the work itself, such as an assessment scope created before any release was
    prepared, compares this. What approval and release bind, the prepared bytes and the target, stay in the
    governed contract and are checked by the door."""
    return {k: v for k, v in contract.items() if k not in (PREPARATION_FIELD, TARGET_FIELD, MISSION_FIELD, RELEASE_AUTHORITY_FIELD)}


class ProjectState(Protocol):
    """The engine's project state, as this component needs it: a view of the engine's `ProjectStateStore`.

    Tenancy: that store is bound to one tenant at construction, so this view never crosses tenants.
    Concurrency: the durable Postgres store saves by compare-and-set on the revision it loaded, so a release that
    records its decision over a concurrent writer fails loudly rather than losing either update. The rows written
    here are the project's account of its releases; they are not what makes a release safe. The effect is guarded
    by the target's atomic nonce claim and the append-only evidence chain, so a lost or refused row can only cause
    a later replay to be refused as spent, never a second effect."""

    def load(self, project_id: str) -> dict[str, Any]: ...

    def save(self, project_id: str, state: dict[str, Any]) -> None: ...


@dataclass
class GovernedRelease:
    """Runs one regulated vertical's release protocol. Constructed by the engine with the seams it already holds."""

    spec: VerticalSpec
    gate: RegulatedEmissionGate
    build_contract: Callable[[dict[str, Any], bool], dict[str, Any]]
    exporter: Callable[[dict[str, Any], str], str]
    artifacts: ArtifactStore
    state: ProjectState
    clock: Callable[[], float]
    review_context: Callable[[str, dict[str, Any], EmissionContext, dict[str, Any]], EmissionContext]
    receipt_pins: ReceiptPinSource | None = None
    release_authority: ReleaseAuthoritySource | None = None

    # ── the governed contract ──

    def contract(self, project_id: str, *, tenant: str, context: EmissionContext,
                 state: dict[str, Any] | None = None) -> GovernedContract:
        """Prepare once, then compose. The target is the one `context.release_target` declares, described by the
        governance side. There is no governed contract without a target: review and approval must name where the
        bytes will land, before they are approved (Paper A 4.2; review 2964).

        A release whose content changed since review prepares new bytes with a new digest. It is not refused here:
        the approval binds the reviewed digest, so the door denies it and records that denial as evidence. Every
        attempt reaches the one place that decides, and none is turned away unrecorded."""
        if not context.release_target:
            raise GovernedReleaseError("a regulated review or release must declare its release target")
        if tenant != context.tenant:
            raise GovernedReleaseError("release authority tenant differs from the request context")
        if context.project_id and context.project_id != project_id:
            raise GovernedReleaseError("release authority context names a different project")
        if context.vertical_name and context.vertical_name != self.spec.name:
            raise GovernedReleaseError("release authority context names a different vertical")
        authority = None
        authority_refused = False
        if self.release_authority is not None:
            try:
                if not context.actor_id:
                    raise ReleaseAuthorityUnavailable("missing authenticated actor")
                authority = self.release_authority.resolve(
                    tenant=tenant, actor_id=context.actor_id, vertical=self.spec.name, project_id=project_id)
                if authority is not None and not isinstance(authority, ReleaseAuthorityBinding):
                    raise ReleaseAuthorityUnavailable("invalid authority binding")
            except Exception:
                # The gate records a fixed refusal on its signed chain. Neither a store
                # outage nor malformed local data may select a fresh ordinary mission.
                authority = None
                authority_refused = True
        state = self.state.load(project_id) if state is None else state
        base = {k: v for k, v in self.build_contract(state, bool(state.get("approved", False))).items()
                if k not in (PREPARATION_FIELD, TARGET_FIELD, MISSION_FIELD, RELEASE_AUTHORITY_FIELD)}          # never taken from project-authored data
        prepared = self._prepared(project_id, state, base, tenant=tenant)
        target = ReleaseTarget.from_description(self.gate.describe_target(
            spec=self.spec, out_path=os.path.abspath(context.release_target), context=context))
        # The mission is a host fact: this vertical's project, stable across policy and overlay revisions, never
        # chosen by a caller, so a fresh nonce or target cannot reset its budget. Approval covers it.
        return GovernedContract(base, prepared, target,
                                mission=("" if authority_refused else authority.mission if authority is not None
                                         else f"{self.spec.name}:{project_id}"),
                                authority=authority, authority_refused=authority_refused)

    def _prepared(self, project_id: str, state: dict[str, Any], base: Mapping[str, Any], *,
                  tenant: str) -> PreparedArtifact:
        base_digest = _digest(dict(base))
        owner = TenantContext(tenant_id=tenant, display_name=tenant)
        record = state.get(PREPARATION_FIELD)
        if isinstance(record, dict) and record.get("contract_digest") == base_digest:
            if record.get("tenant") != tenant or record.get("project_id") != project_id:
                raise GovernedReleaseError("the prepared release belongs to a different tenant or project")
            try:
                content = self.artifacts.get(owner, str(record.get("artifact_address", "")))
            except Exception as broken:                  # missing or failed integrity: refuse, never re-render
                raise GovernedReleaseError(f"the prepared release artifact cannot be verified: {broken}") from broken
            if sha256(content).hexdigest() != record.get("artifact_sha256"):
                raise GovernedReleaseError("the prepared release artifact does not match its preparation record")
            return PreparedArtifact(dict(record), content)
        content = self._render_once(dict(base))
        record = {"schema": PREPARATION_SCHEMA, "tenant": tenant, "project_id": project_id,
                  "vertical": self.spec.name, "contract_digest": base_digest,
                  "artifact_address": self.artifacts.put(owner, content),
                  "artifact_sha256": sha256(content).hexdigest(), "size_bytes": len(content),
                  "prepared_at": self.clock()}
        state[PREPARATION_FIELD] = record
        self.state.save(project_id, state)
        return PreparedArtifact(record, content)

    def _render_once(self, contract: dict[str, Any]) -> bytes:
        """The exporter writes into a private temporary path only; it never sees the release destination."""
        with tempfile.TemporaryDirectory(prefix="release-prepare-") as tmp:
            private = os.path.join(tmp, "artifact")
            written = self.exporter(contract, private)
            if os.path.abspath(written) != os.path.abspath(private) or not os.path.isfile(private):
                raise GovernedReleaseError("regulated release exporter must write exactly the path it is given")
            return Path(private).read_bytes()

    # ── the release ──

    def release(self, project_id: str, out_path: str, context: EmissionContext) -> str:
        destination = os.path.abspath(out_path)
        if context.release_target and os.path.abspath(context.release_target) != destination:
            raise ReleaseRefused("the release destination is not the target that was declared for review")
        if context.project_id and context.project_id != project_id:
            raise ReleaseRefused("the release context names a different project")
        context = replace(context, release_target=destination)            # the target is a host fact
        state = self.state.load(project_id)
        governed = self._as_decided(self.contract(project_id, tenant=context.tenant, context=context, state=state),
                                    state, context.action_id)
        contract = governed.for_approval()
        if governed.authority_refused:
            decision = self.gate.review_draft(spec=self.spec, contract=contract, context=context)
            if decision.allowed:
                # An older or incorrectly composed gate cannot turn an unresolved source
                # into permission. Never ask it to issue a target permit.
                raise ReleaseRefused("authority gate did not refuse unresolved delegated authority")
            self._record_decision(project_id, decision, context=context, governed=governed,
                                  evidence=dict(decision.evidence), destination=destination)
            raise ReleaseRefused(f"regulated emission denied by the authority plane: {decision.reason}")
        context = self.review_context(project_id, contract, context, state)
        if isinstance(context.approval, str):
            resolver = getattr(self.gate, "resolve_review_context", None)
            if resolver is None:
                raise ReleaseRefused("stored human review is not configured for this vertical")
            context = resolver(spec=self.spec, contract=contract, context=context)
            if not isinstance(context, EmissionContext):
                raise ReleaseRefused("human review gate returned an invalid release context")
        if context.action_id:
            prior = next((row for row in self.state.load(project_id).get("emissions", ())
                          if row.get("action_id") == context.action_id), None)
            if prior is not None:
                return self._replay(project_id, prior, governed, destination, context)
        decision = self.gate.authorize_release(spec=self.spec, contract=contract, out_path=destination,
                                               context=context, artifact=governed.prepared.content)
        evidence = {**dict(decision.evidence), **self._pins(context.tenant)}
        self._record_decision(project_id, decision, context=context, governed=governed, evidence=evidence,
                              destination=destination)
        if not decision.allowed:
            raise ReleaseRefused(f"regulated emission denied by the authority plane: {decision.reason}")
        outcome = self.gate.commit_release(spec=self.spec, contract=contract, decision=decision,
                                           artifact=governed.prepared.content, out_path=destination, context=context)
        return self._settle(project_id, context.action_id, outcome, destination, governed.prepared.sha256)

    def _recorded_attempt(self, project_id: str, destination: str, context: EmissionContext) -> Mapping[str, Any] | None:
        """The one recorded decision for this action and nonce, bound to its recorded tenant FIRST, then destination."""
        if context.release_target and os.path.abspath(context.release_target) != destination:
            raise GovernedReleaseError("reconciliation names a different destination than its context")
        if context.project_id and context.project_id != project_id:
            raise GovernedReleaseError("reconciliation names a different project than its context")
        if not context.action_id or not context.nonce:
            raise GovernedReleaseError("reconciliation needs the recorded action id and permit nonce")
        rows = [row for row in self.state.load(project_id).get("emissions", ())
                if row.get("action_id") == context.action_id and row.get("nonce") == context.nonce]
        if not rows:
            return None
        row = rows[-1]
        evidence = row.get("evidence") if isinstance(row.get("evidence"), Mapping) else {}
        recorded_tenant = row.get("tenant", evidence.get("tenant"))
        if not isinstance(recorded_tenant, str) or not recorded_tenant:
            raise GovernedReleaseError("the recorded attempt carries no tenant it can be bound to")
        if recorded_tenant != context.tenant:
            raise GovernedReleaseError("the recorded attempt belongs to another tenant")
        if row.get("destination") != destination:
            raise GovernedReleaseError("the recorded attempt was for a different destination")
        if not isinstance(row, Mapping):
            raise GovernedReleaseError("the recorded attempt is malformed")
        return row

    def observe(self, project_id: str, out_path: str, context: EmissionContext) -> ReleaseObservation:
        """Read-only evidence of one exact allowed attempt: the verified signed decision and the target's receipts.
        Writes nothing; never approves, renders, permits or delivers; a refused or unknown attempt is an error."""
        destination = os.path.abspath(out_path)
        row = self._recorded_attempt(project_id, destination, context)
        if row is None or not row.get("allowed"):
            raise GovernedReleaseError("there is no allowed recorded release attempt to observe")
        expected = str(row.get("artifact_sha256", ""))
        record_hash = str(row.get("decision_record_hash", ""))
        recorded_target = row.get("target")
        target: dict[str, Any] = dict(recorded_target) if isinstance(recorded_target, Mapping) else {}
        verified = getattr(self.gate, "verified_release_decision", None)
        if not expected or not callable(verified):
            raise GovernedReleaseError("this vertical cannot produce verified release evidence")
        if not record_hash:
            # A record that does not name its own signed decision cannot be joined to one after the fact.
            raise GovernedReleaseError("the recorded attempt does not name its signed decision")
        decision = verified(spec=self.spec, tenant=context.tenant, record_hash=record_hash, nonce=context.nonce,
                            artifact_sha256=expected, target=target, project_id=project_id,
                            action_id=context.action_id)
        if decision is None:
            raise GovernedReleaseError("no verified signed decision exists for this release")
        outcome = self.gate.reconcile_release(spec=self.spec, artifact_sha256=expected, out_path=destination,
                                              context=context, nonce=context.nonce)
        outcome_record = getattr(self.gate, "verified_release_outcome", None)
        receipt = getattr(self.gate, "release_receipt", None)
        return ReleaseObservation(
            context.tenant, project_id, context.action_id, context.nonce, destination, expected, outcome, decision,
            outcome_record(spec=self.spec, tenant=context.tenant, decision=decision) if callable(outcome_record) else None,
            receipt(spec=self.spec, out_path=destination, tenant=context.tenant, nonce=context.nonce,
                    artifact_sha256=expected, decision_record_hash=record_hash) if callable(receipt) else None)

    def reconcile(self, project_id: str, out_path: str, context: EmissionContext) -> ReleaseOutcome:
        """The outcome of ONE exact recorded release attempt, read from the target's receipts. Read-only.

        Never authorizes, renders, commits or resends. The attempt is the recorded decision with this action id and
        permit nonce, for this destination and this tenant; its outcome is recorded as an observed event. Answers:
        `not_attempted` (no such recorded decision), `not_committed` (the recorded decision refused, or the target
        proves the permitted bytes never landed), or the target's own `committed`/`unknown`. A historical commit is
        `committed` even when the target no longer holds the bytes (`target_holds` false); it is never re-created.
        A lapsed execution deadline does not forbid this read; the caller's current observation access still does."""
        destination = os.path.abspath(out_path)
        # The tenant is checked FIRST, for refused and allowed attempts alike: another tenant learns nothing, and a
        # receipt query under another tenant would read "no receipt" as proof of non-delivery (review 3172).
        row = self._recorded_attempt(project_id, destination, context)
        if row is None:
            return ReleaseOutcome("not_attempted", "no recorded decision for this action and nonce", {"attempt": False})
        if not row.get("allowed"):
            return ReleaseOutcome("not_committed", f"the recorded decision refused this action: {row.get('reason', '')}",
                                  {"attempt": True, "decided": False})
        expected = str(row.get("artifact_sha256", ""))
        if not expected:
            raise GovernedReleaseError("the recorded attempt has no artifact digest")
        outcome = self.gate.reconcile_release(spec=self.spec, artifact_sha256=expected, out_path=destination,
                                              context=context, nonce=context.nonce)
        self._record_outcome(project_id, context.action_id, outcome, destination, expected)
        return outcome

    @staticmethod
    def _as_decided(governed: GovernedContract, state: Mapping[str, Any], action_id: str) -> GovernedContract:
        """The contract as an earlier allowed decision approved it, when this request repeats that operation.

        A committed release changes its target's state, so the current contract no longer carries the state the
        approval froze, and a stored review would refuse the repeat before it could be answered from the target's
        receipts. Only an exact match counts: the same prepared bytes, the same contract and the same target, with
        only the prior state taken from the record. Anything else is a new operation and is decided afresh."""
        for row in reversed(list(state.get("emissions", ()))):
            recorded = row.get("target")
            if (not row.get("allowed") or not isinstance(recorded, Mapping)
                    or not isinstance(recorded.get("expected_state"), str)
                    or (action_id and row.get("action_id") != action_id)):
                continue
            decided = governed.with_prior_state(recorded["expected_state"])
            if decided.digest() == row.get("contract_digest"):
                return decided
        return governed

    def _pins(self, tenant: str) -> dict[str, str]:
        if self.receipt_pins is None:
            return {}
        if not self.receipt_pins.fields:
            raise GovernedReleaseError("regulated release authority pins declare no fields (fail-closed)")
        pins = dict(self.receipt_pins.resolve(tenant))
        missing = self.receipt_pins.missing(pins)
        if missing:
            raise GovernedReleaseError(f"regulated release authority pins are incomplete: {', '.join(missing)}")
        return pins

    def _replay(self, project_id: str, prior: Mapping[str, Any], governed: GovernedContract, destination: str,
                context: EmissionContext) -> str:
        """A repeated action is answered from the target's receipts, never re-sent (Paper A 5.2).

        The request must BE the approved operation: the current contract, with the target exactly as the prior
        decision recorded it, must reproduce the approved contract's digest. No approval invariant is dropped to
        make a replay match; the only thing taken from the record rather than the target is the prior state the
        approval froze, because the commit itself has since changed it."""
        recorded = prior.get("target")
        if not isinstance(recorded, Mapping) or not isinstance(recorded.get("expected_state"), str):
            raise GovernedReleaseError("regulated release replay has no recorded target state")
        if governed.with_prior_state(recorded["expected_state"]).digest() != prior.get("contract_digest"):
            raise GovernedReleaseError("regulated release idempotency conflict: action_id was used for a different "
                                       "artifact or target")
        if not prior.get("allowed"):
            raise GovernedReleaseError(f"regulated release replay preserves the prior refusal: {prior.get('reason', '')}")
        expected, nonce = str(prior.get("artifact_sha256", "")), str(prior.get("nonce", ""))
        if not expected or not nonce:
            raise GovernedReleaseError("regulated release replay has no recorded artifact digest and permit nonce")
        outcome = self.gate.reconcile_release(spec=self.spec, artifact_sha256=expected, out_path=destination,
                                              context=context, nonce=nonce)
        released = self._settle(project_id, str(prior.get("action_id", "")), outcome, destination, expected)
        if outcome.evidence.get("target_holds") is not True:
            # The receipt proves the commit happened; it does not prove the target still holds the bytes. Never
            # hand back a target that no longer does, and never re-send to put them back.
            raise GovernedReleaseError("regulated release was committed earlier, but the target no longer holds the "
                                       "permitted bytes; a new release needs a new authorisation")
        return released

    def _settle(self, project_id: str, action_id: str, outcome: ReleaseOutcome, destination: str,
                artifact_sha256: str) -> str:
        """Record the target's outcome; return the destination only when the target committed."""
        self._record_outcome(project_id, action_id, outcome, destination, artifact_sha256)
        if outcome.state == "committed":
            return destination
        raise GovernedReleaseError(f"regulated release {outcome.state} at the target: {outcome.detail}")

    # ── the project's record of it ──

    def _record_decision(self, project_id: str, decision: Any, *, context: EmissionContext,
                         governed: GovernedContract, evidence: Mapping[str, Any], destination: str) -> None:
        """The decision and its evidence, before any effect, appended to project state: the approved contract's
        digest and the target as approved, so a replay can be checked against exactly what was decided."""
        state = self.state.load(project_id)
        state.setdefault("emissions", []).append({
            "allowed": bool(decision.allowed), "reason": decision.reason, "action_id": context.action_id,
            # The tenant the decision was made for, recorded before any effect, so a later reconciliation binds to
            # it and never to whatever tenant a query names (review 3172).
            "tenant": context.tenant,
            # The exact signed decision behind the permit, so observation binds THIS envelope and never another
            # decision that reuses the nonce (review 3195); "" when no permit was issued.
            "decision_record_hash": str(getattr(getattr(getattr(decision, "permit", None), "envelope", None),
                                                "record_hash", "") or ""),
            "contract_digest": governed.digest(), "target": governed.target.binding(),
            "artifact_sha256": governed.prepared.sha256, "destination": destination,
            "nonce": context.nonce, "evidence": dict(evidence), "at": self.clock(),
            # The authority pinned on the receipt; a gate that supplies none leaves them visibly empty.
            "policy_ref": str(evidence.get("policy_ref", "")), "policy_version": str(evidence.get("policy_version", "")),
            "policy_digest": str(evidence.get("policy_digest", "")), "pack_version": str(evidence.get("pack_version", ""))})
        self.state.save(project_id, state)

    def _record_outcome(self, project_id: str, action_id: str, outcome: ReleaseOutcome, destination: str,
                        artifact_sha256: str) -> None:
        """The target's outcome as its own event; the decision record above is never rewritten."""
        state = self.state.load(project_id)
        state.setdefault("release_outcomes", []).append({
            "action_id": action_id, "state": outcome.state, "detail": outcome.detail, "destination": destination,
            "artifact_sha256": artifact_sha256, "evidence": dict(outcome.evidence), "at": self.clock()})
        self.state.save(project_id, state)


__all__ = ["PREPARATION_FIELD", "PREPARATION_SCHEMA", "TARGET_FIELD", "GovernedContract", "GovernedRelease",
           "GovernedReleaseError", "PreparedArtifact", "ProjectState", "ReleaseTarget"]
