"""Governance of governance: changing policy, checkers or approvers is a tier-4 act through the same door.

Paper A section 4.2; docs/ARCHITECTURE-OF-RECORD/08 row A09. The rules that govern everything else, which pack is in
force, which checkers are qualified, which issuers and approvers are recognised, must themselves change only through
the regulated engine, under the same permit protocol as any other effect, at tier 4:

* a change is exact bytes (the canonical change request) released to a governance target, so the approval covers the
  precise change and nothing else;
* the target is the only writer of that governance state. It verifies the permit and claims the nonce; then, under
  the lock of the governed SCOPE (the state itself, shared by every target instance and every tenant on the same log,
  since a pack registry is global), it compares the state with the one the permit approved, records a prepared
  attempt, re-checks the permit's freshness after that blocking write, and only then applies the change (source review 3129,
  3132);
* a host whose governed state has its own lock and compare-and-set receives the whole approved change, prior state
  included, as a `GovernedChange` through `transact`, so it never re-reads authority on its own;
* an attempt whose acknowledgement is lost is UNKNOWN, never FAILED, and fences its scope: no other change applies
  until `reconcile` resolves it from an EXACT RECEIVING RECEIPT, the host's durable record of applying this very
  operation (tenant, operation, nonce, change digest) written in the same transaction as the change. Equal state proves
  nothing (the same version may predate the attempt), so without a receipt the outcome stays UNKNOWN (source review 3138);
* the permit's freshness is judged once more INSIDE the host's own transaction, after its own lock and reads and just
  before its write, through `GovernedChange.final_check`: a receiving lifecycle that waits past the permit's life
  writes nothing;
* a registry composed with a GovernanceGuard (regulated_core/governance_guard.py) refuses every write, direct calls
  included, that is not this target applying the approved change;
* the only other way in is a narrow, signed bootstrap: a key the deployment names may install the FIRST state of a
  target that has none, once per exact change, and the bootstrap is logged like any change;
* every committed change is appended to a per-tenant governance log, and the log's Merkle root is anchored to
  write-once storage, so the history is retained and tamper-evident. Anchoring is evidence retention, not publication
  to independent witnesses: nobody outside the deployment cosigns the root (Paper A row A13 is that open work).

The intended use of a governance action is declared at tier 4 by the host, so the engine's step 7 requires two
approvers from different reporting lines, a monitor's clearance and a cooling-off period (regulated_core/tier4.py).
This module supplies the policy, the target seam, the log and one concrete target: pack activation. Routing the host's
administrative paths through it is the host's composition (ledger 3123).
"""
from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .canonical import canonical_bytes
from .governance_guard import GovernanceGuard
from .models import Action, ApprovalRequirement, Assertion, Decision, PolicyContext, PolicyRef
from .permit import EmissionError, PermitUseStore
from .signing import Signature, Signer, TrustDirectory
from .target import Outcome, SignedTargetPermit, TargetAuthority, TargetRef, TargetResult
from .worm import WormReceipt, WormStore

GOVERNANCE_CONTENT_TYPE = "governance:change"
GOVERNANCE_ROLE = "governance-approver"
#: Withdrawing authority (revoking a pack version) only reduces what may happen, so it takes one supervisor and no
#: cooling-off: an emergency withdrawal must not wait a day. It still needs a permit and is still logged.
WITHDRAWAL_CONTENT_TYPE = "governance:withdrawal"
WITHDRAWAL_ROLE = "governance-supervisor"
_WITHDRAWAL_TEXT = ("Withdrawing a policy only removes authority: one governance supervisor signs off on the exact "
                    "withdrawal, within one hour.")
CHANGE_SCHEMA = "regulated/governance-change/v1"
PREPARED, COMMITTED, NOT_COMMITTED = "prepared", "committed", "not-committed"


@dataclass(frozen=True, slots=True)
class GovernedChange:
    """Everything a host's own transaction needs to apply one approved change. The host contract, in order, inside
    its own lock and transaction: (1) read its state and refuse unless it is `approved_prior`; (2) call
    `final_check()`, which raises `FinalCheckRefused` if the permit is no longer current, and write nothing if it does;
    (3) write the change AND a receipt keyed (tenant_id, operation, nonce, change_digest), atomically."""
    tenant_id: str
    operation: str
    kind: str
    subject: str
    nonce: str
    change_digest: str
    change: Mapping[str, Any]
    approved_prior: str
    expected_state: str
    final_check: Callable[[], None] = lambda: None
    # A signed bootstrap installs a FIRST-EVER state only. The host checks it inside its own transaction against its
    # durable history, not current availability: a revoked or retired state is still history (source review 3430).
    first_state_only: bool = False
    # Retain the already authenticated authority for hosts that verify stored
    # state on later reads. It is evidence to verify, never authority by itself.
    authority_proof: SignedTargetPermit | SignedBootstrap | None = None


class FinalCheckRefused(EmissionError):
    """The permit was no longer current at the host's point of decision; the host wrote nothing."""


#: A host's receiving receipt: COMMITTED if it holds the receipt for exactly this operation, NOT_COMMITTED only if it
#: can prove none exists and none can still be written (its own transaction for it is over), UNKNOWN otherwise.
ReceiptLookup = Callable[[str, str, str, str], Outcome]
BOOTSTRAP_SCHEMA = "regulated/governance-bootstrap/v1"
_POLICY_TEXT = ("A change to policy, checkers or approvers is a tier-4 act: two governance approvers must sign off on "
                "the exact change, within one day.")


class GovernancePolicy:
    """The core policy for governance changes: every change needs two governance approvers; nothing is automatic."""

    content_types = frozenset({GOVERNANCE_CONTENT_TYPE})
    ref = PolicyRef(vertical="governance", policy_id="change-control", version="1.0.0",
                    digest=sha256(_POLICY_TEXT.encode("utf-8")).hexdigest())

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        requirement = ApprovalRequirement((frozenset({GOVERNANCE_ROLE}),), 2, action.action_id,
                                          "two governance approvers sign off on the exact change",
                                          24 * 3600 * 1_000_000)
        return Decision.require_approval("GOVERNANCE_CHANGE", _POLICY_TEXT, requirement)


class GovernanceWithdrawalPolicy:
    """The core policy for withdrawing governance state: one supervisor approves the exact withdrawal."""

    content_types = frozenset({WITHDRAWAL_CONTENT_TYPE})
    ref = PolicyRef(vertical="governance", policy_id="withdrawal", version="1.0.0",
                    digest=sha256(_WITHDRAWAL_TEXT.encode("utf-8")).hexdigest())

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        requirement = ApprovalRequirement((frozenset({WITHDRAWAL_ROLE}),), 1, action.action_id,
                                          "a governance supervisor signs off on the exact withdrawal", 3600 * 1_000_000)
        return Decision.require_approval("GOVERNANCE_WITHDRAWAL", _WITHDRAWAL_TEXT, requirement)


def change_bytes(kind: str, subject: str, change: Mapping[str, Any]) -> bytes:
    """The exact bytes a governance change is approved and released as."""
    return canonical_bytes({"schema": CHANGE_SCHEMA, "kind": kind, "subject": subject, "change": dict(change)})


@dataclass(frozen=True, slots=True)
class GovernanceEvent:
    tenant_id: str
    kind: str
    subject: str
    change_digest: str
    prior_state: str
    nonce: str
    decision_record_id: str
    at_us: int
    phase: str = COMMITTED          # PREPARED before applying, then COMMITTED or NOT_COMMITTED
    expected_state: str = ""        # the state the change produces, when the target can say; "" if it cannot
    operation: str = ""
    scope: str = ""                 # the governed state's identity; every attempt on it is fenced together

    def digest(self) -> str:
        return sha256(canonical_bytes({"kind": self.kind, "subject": self.subject, "change_digest": self.change_digest,
                                       "prior_state": self.prior_state, "nonce": self.nonce,
                                       "decision_record_id": self.decision_record_id, "at_us": self.at_us,
                                       "tenant_id": self.tenant_id, "phase": self.phase,
                                       "expected_state": self.expected_state, "operation": self.operation,
                                       "scope": self.scope})).hexdigest()


def attempt_key(tenant_id: str, nonce: str) -> str:
    """The opaque, tenant-free identity of one governance attempt, as a scope fence records it."""
    return sha256(canonical_bytes({"tenant_id": tenant_id, "nonce": nonce})).hexdigest()


def event_body(event: GovernanceEvent) -> dict[str, Any]:
    """The stored form of an event: every field, so a durable log reproduces the same digest and Merkle root."""
    return {name: getattr(event, name) for name in GovernanceEvent.__dataclass_fields__}


def merkle_root(leaves: list[str]) -> str:
    """A binary Merkle root over hex digests, duplicating the last leaf of an odd level; the empty root is sha256("")."""
    if not leaves:
        return sha256(b"").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest() for a, b in zip(level[::2], level[1::2])]
    return level[0]


class GovernanceLog:
    """Governance attempts and outcomes, append-only per tenant, with a published Merkle root.

    It also owns the lock of each governed scope: every target instance composed on this log, for any tenant,
    serialises its compare-and-apply on the scope here, so two instances over one registry cannot both apply. This
    in-memory log serialises one process; a durable log serialises across processes."""

    def __init__(self) -> None:
        self._events: dict[str, list[GovernanceEvent]] = {}
        self._lock = threading.Lock()
        self._scopes: dict[str, threading.Lock] = {}

    def permit_claimed(self, uses: PermitUseStore, tenant_id: str, nonce: str) -> bool:
        """Observe whether a receiving claim exists before a prepared event."""
        return uses.used(tenant_id, nonce)

    @contextmanager
    def governing(self, scope: str) -> Iterator[None]:
        """Hold the governed scope's lock for a compare-and-apply."""
        with self._lock:
            lock = self._scopes.setdefault(scope, threading.Lock())
        with lock:
            yield

    def append(self, event: GovernanceEvent) -> str:
        with self._lock:
            events = self._events.setdefault(event.tenant_id, [])
            events.append(event)
            return merkle_root([e.digest() for e in events])

    def events(self, tenant_id: str) -> tuple[GovernanceEvent, ...]:
        """Every event of one tenant, in order. A durable log overrides this, `append`, `governing` and `unresolved`;
        every other query is derived from these four."""
        with self._lock:
            return tuple(self._events.get(tenant_id, ()))

    def root(self, tenant_id: str) -> str:
        return merkle_root([e.digest() for e in self.events(tenant_id)])

    def changes(self, tenant_id: str) -> tuple[GovernanceEvent, ...]:
        """The committed governance changes only."""
        return tuple(e for e in self.events(tenant_id) if e.phase == COMMITTED)

    def committed(self, tenant_id: str, nonce: str) -> GovernanceEvent | None:
        return next((e for e in self.events(tenant_id) if e.nonce == nonce and e.phase == COMMITTED), None)

    def attempt(self, tenant_id: str, nonce: str) -> tuple[GovernanceEvent | None, GovernanceEvent | None]:
        """(the prepared event, its resolution) for one nonce; either may be None."""
        mine = [e for e in self.events(tenant_id) if e.nonce == nonce]
        prepared = next((e for e in mine if e.phase == PREPARED), None)
        resolved = next((e for e in mine if e.phase in (COMMITTED, NOT_COMMITTED)), None)
        return prepared, resolved

    def unresolved(self, scope: str) -> str | None:
        """The opaque key of a prepared attempt on this scope, in ANY tenant, with no outcome yet: the scope is fenced
        until it is reconciled. Only the key is returned, so a fence never discloses another tenant's change."""
        with self._lock:
            events = [e for tenant in self._events.values() for e in tenant if e.scope == scope]
        done = {(e.tenant_id, e.nonce) for e in events if e.phase in (COMMITTED, NOT_COMMITTED)}
        return next((attempt_key(e.tenant_id, e.nonce) for e in events
                     if e.phase == PREPARED and (e.tenant_id, e.nonce) not in done), None)


def publish_root(log: GovernanceLog, worm: WormStore, tenant_id: str, *, retain_us: int, now_us: int) -> WormReceipt:
    """Anchor the tenant's current governance root to write-once storage and verify it landed."""
    record = canonical_bytes({"schema": "regulated/governance-root/v1", "tenant_id": tenant_id,
                              "root": log.root(tenant_id), "events": len(log.events(tenant_id)), "at_us": now_us})
    receipt = worm.anchor(tenant_id, record, retain_us=retain_us, now_us=now_us)
    if not worm.verify(receipt):
        raise EmissionError("the governance root did not verify in write-once storage")
    return receipt


@dataclass(frozen=True, slots=True)
class SignedBootstrap:
    """A named bootstrap key's signature over installing one exact first state of one target."""
    tenant_id: str
    kind: str
    subject: str
    change_digest: str
    signature: Signature

    def body(self) -> dict[str, str]:
        return {"schema": BOOTSTRAP_SCHEMA, "tenant_id": self.tenant_id, "kind": self.kind, "subject": self.subject,
                "change_digest": self.change_digest}


def issue_bootstrap(signer: Signer, *, tenant_id: str, kind: str, subject: str, output: bytes) -> SignedBootstrap:
    """Sign the installation of the first state of one governance target, as the exact change bytes."""
    digest = sha256(output).hexdigest()
    body = {"schema": BOOTSTRAP_SCHEMA, "tenant_id": tenant_id, "kind": kind, "subject": subject,
            "change_digest": digest}
    return SignedBootstrap(tenant_id, kind, subject, digest, signer.sign(body))


class GovernanceTarget:
    """The only writer of one piece of governance state. It applies a change only under a verified, current permit.

    `state` reports the current state digest (the permit binds the approved prior state, so a change made meanwhile
    refuses); `apply` makes the change. Serialised by one lock, like the filesystem target."""

    def __init__(self, *, tenant_id: str, kind: str, subject: str, authority: TargetAuthority, uses: PermitUseStore,
                 state: Callable[[], str], apply: Callable[[Mapping[str, Any]], None], log: GovernanceLog,
                 operation_name: str, guard: GovernanceGuard | None = None,
                 expect: Callable[[Mapping[str, Any], str], str] | None = None,
                 transact: Callable[[GovernedChange], None] | None = None, scope: str | None = None,
                 receipt: ReceiptLookup | None = None,
                 bootstrap_trust: TrustDirectory | None = None,
                 bootstrap_key_ids: frozenset[str] = frozenset(), boundary: str = "governance",
                 schema: str = CHANGE_SCHEMA, validate: Callable[[Mapping[str, Any]], None] | None = None,
                 receiving_check: Callable[[SignedTargetPermit], None] | None = None,
                 initialized: Callable[[], bool] | None = None,
                 budget_binding: Any = None, budget_transaction: bool = False) -> None:
        if bootstrap_key_ids and bootstrap_trust is None:
            raise ValueError("bootstrap keys need the trust directory that verifies them")
        if budget_binding is not None:
            from .governance_transaction import PostgresGovernanceBudget
            if not isinstance(budget_binding, PostgresGovernanceBudget):
                raise TypeError("governance budget requires a durable PostgreSQL binding")
            if budget_transaction is not True or not callable(transact) or not callable(receipt):
                raise ValueError("governance budget requires an explicit owned transaction and exact receipt")
        elif budget_transaction:
            raise ValueError("governance budget transaction requires its budget binding")
        self._budget_binding = budget_binding
        self.tenant_id, self._kind, self._subject = tenant_id, kind, subject
        self._authority, self._uses, self._state, self._apply = authority, uses, state, apply
        self._log, self.operation_name, self._guard = log, operation_name, guard
        self._bootstrap_trust, self._bootstrap_keys = bootstrap_trust, bootstrap_key_ids
        # Whether the target has EVER held a state (its durable history), for the bootstrap's first-ever rule.
        self._initialized = initialized
        # The state a change produces from a prior state, so a lost acknowledgement can be resolved from the governed
        # state itself. Without it, reconcile can only prove the change did NOT happen.
        self._expect = expect
        # A host with its own lock and compare-and-set applies through `transact` with the approved prior state.
        self._transact = transact
        # The host's exact receiving receipt, the only evidence `reconcile` accepts (source review 3138).
        self._receipt = receipt
        # The governed state's identity. Pack activation is global to a registry, so the default is not per tenant.
        self.scope = scope if scope is not None else f"{kind}:{subject}"
        # The same receiving transaction serves every host-owned effect boundary (regulated_core/choke_points.py):
        # the boundary names the TargetRef kind, the schema the exact request bytes, and `validate` refuses a change
        # of the wrong shape BEFORE the nonce is claimed. The defaults are the governance boundary, unchanged.
        self._boundary, self._schema, self._validate = boundary, schema, validate
        # The receiving check, fixed at composition and bound to the AUTHENTICATED permit being received (source review 3285,
        # 3291): judged after the prepared write and again as the host's final check inside its own transaction, just
        # before its write. A governance host composes every target with the check that reads the stored review the
        # permit names and requires every approval to stand under the authority in force NOW, so no caller has to
        # install anything and a target reconstructed elsewhere carries the same check. It raises EmissionError or
        # ValueError to refuse; nothing is then written.
        self._receiving_check = receiving_check

    def _applying(self, governed: GovernedChange) -> None:
        def run() -> None:
            if self._transact is not None:
                self._transact(governed)
            else:
                self._apply(governed.change)
        if self._guard is None:
            run()
            return
        with self._guard._admitting(self._kind, self._subject):
            run()

    def _request(self, output: bytes) -> dict[str, Any]:
        request = json.loads(output)
        if (not isinstance(request, dict) or request.get("schema") != self._schema or request.get("kind") != self._kind
                or request.get("subject") != self._subject or not isinstance(request.get("change"), dict)):
            raise EmissionError("the permitted bytes are not a change to this governance target")
        if self._validate is not None:
            self._validate(request["change"])
        return request

    @property
    def target(self) -> TargetRef:
        return TargetRef(self._boundary, f"{self._kind}:{self._subject}")

    @property
    def operation(self) -> str:
        return self.operation_name

    def current_state(self) -> str:
        return self._state()

    def _event(self, p_nonce: str, digest: str, prior: str, record_id: str, phase: str, expected: str) -> GovernanceEvent:
        return GovernanceEvent(self.tenant_id, self._kind, self._subject, digest, prior, p_nonce, record_id,
                               self._authority.now_us(), phase, expected, self.operation, self.scope)

    def _governed_apply(self, nonce: str, digest: str, record_id: str, change: Mapping[str, Any], *,
                        expected_prior: str, before_apply: Callable[[], None],
                        first_state_only: bool = False,
                        transaction_check: Callable[[Callable[[], None]], Any] | None = None,
                        authority_proof: SignedTargetPermit | SignedBootstrap | None = None) -> TargetResult:
        """Compare, prepare, check, apply, record: the one receiving transaction, under the scope's shared lock."""
        with self._log.governing(self.scope):
            try:
                if self._log.unresolved(self.scope) is not None:
                    raise EmissionError("an earlier change to this governed state has an unknown outcome; "
                                        "reconcile it first")
                prior = self.current_state()
                if prior != expected_prior:
                    raise EmissionError("the governed state changed since this change was approved; nothing applied")
                expected = self._expect(change, prior) if self._expect is not None else ""
            except (EmissionError, ValueError) as refused:
                return TargetResult(Outcome.FAILED, str(refused), self.current_state())
            self._log.append(self._event(nonce, digest, prior, record_id, PREPARED, expected))
            try:
                before_apply()      # the point of decision: after the blocking prepared write, before the effect
            except (EmissionError, ValueError) as refused:
                self._log.append(self._event(nonce, digest, prior, record_id, NOT_COMMITTED, expected))
                return TargetResult(Outcome.FAILED, str(refused), self.current_state())
            def final_check() -> None:
                try:
                    before_apply()
                except (EmissionError, ValueError) as lapsed:
                    raise FinalCheckRefused(str(lapsed)) from None

            try:
                check = transaction_check(final_check) if transaction_check is not None else final_check
                governed = GovernedChange(self.tenant_id, self.operation, self._kind, self._subject, nonce, digest,
                                          change, prior, expected, check, first_state_only, authority_proof)
                self._applying(governed)
            except FinalCheckRefused as refused:
                # The host's contract: the final check precedes its write, so a refusal there wrote nothing.
                self._log.append(self._event(nonce, digest, prior, record_id, NOT_COMMITTED, expected))
                return TargetResult(Outcome.FAILED, str(refused), self.current_state())
            except Exception as lost:
                # The governed system may have changed before it raised: this is UNKNOWN, never FAILED, and the
                # scope stays fenced until `reconcile` finds the host's exact receiving receipt.
                return TargetResult(Outcome.UNKNOWN, f"the change's outcome is unknown ({type(lost).__name__}); "
                                                     "reconcile before any further change", self.current_state())
            self._log.append(self._event(nonce, digest, prior, record_id, COMMITTED, expected))
            return TargetResult(Outcome.COMMITTED, "", digest)

    def _replayed(self, signed: SignedTargetPermit, output: bytes) -> TargetResult | None:
        """A permit already received is answered from its durable outcome, never applied again (source review 3158).

        Only the exact permit counts: authenticated for this tenant, target and operation, presented with the exact
        bytes it binds. The governed state has moved since, so the ordinary prior-state check would misreport it."""
        p = signed.permit
        try:
            self._authority.authenticate(signed, tenant_id=self.tenant_id, target=self.target, operation=self.operation)
        except EmissionError:
            return None
        if sha256(output).hexdigest() != p.output_digest:
            return None
        prepared, resolved = self._log.attempt(self.tenant_id, p.nonce)
        if resolved is not None and self._mine(resolved, p.output_digest):
            if resolved.phase == COMMITTED:
                return TargetResult(Outcome.COMMITTED, "already committed under this permit; nothing applied again",
                                    p.output_digest)
            return TargetResult(Outcome.FAILED, "this permit was already refused; nothing applied",
                                self.current_state())
        if prepared is not None and self._mine(prepared, p.output_digest):
            return TargetResult(Outcome.UNKNOWN, "an earlier delivery of this permit has an unknown outcome; reconcile",
                                self.current_state())
        return None

    def _release_proven_noncommit(self, signed: SignedTargetPermit, result: TargetResult) -> TargetResult:
        if self._budget_binding is not None and result.outcome in (Outcome.FAILED, Outcome.NOT_COMMITTED):
            try:
                self._budget_binding.release(signed, authority=self._authority, tenant_id=self.tenant_id,
                                             target=self.target, operation=self.operation)
            except Exception:
                # Effect status is still definite. Capacity remains conservatively
                # held until settlement succeeds; do not recast the effect as UNKNOWN.
                return TargetResult(result.outcome, result.detail + "; budget settlement pending", result.target_state)
        return result

    def commit(self, signed: SignedTargetPermit, output: bytes) -> TargetResult:
        # Reject a missing or wrong outer permit before host reads or nonce claims.
        if not isinstance(signed, SignedTargetPermit):
            return TargetResult(Outcome.FAILED, "a signed target permit is required")
        p = signed.permit
        replayed = self._replayed(signed, output)
        if replayed is not None:
            return self._release_proven_noncommit(signed, replayed)
        try:
            self._authority.verify(signed, output, tenant_id=self.tenant_id, target=self.target,
                                   operation=self.operation, current_target_state=self.current_state())
            request = self._request(output)
        except (EmissionError, ValueError) as refused:
            return TargetResult(Outcome.FAILED, str(refused), self.current_state())
        try:
            self._uses.consume(p.tenant_id, p.nonce)
        except EmissionError:
            # A concurrent holder may have claimed the nonce before recording
            # preparation. A used nonce alone cannot establish a failed effect.
            replayed = self._replayed(signed, output)
            if replayed is not None:
                return self._release_proven_noncommit(signed, replayed)
            return TargetResult(Outcome.UNKNOWN, "permit already claimed; receiving outcome not yet recorded",
                                self.current_state())
        receiving_check = self._receiving_check

        def before_apply() -> None:
            self._authority.current(signed)
            if receiving_check is not None:
                receiving_check(signed)

        transaction_check = None
        if self._budget_binding is not None:
            def transaction_check(final_check):
                return self._budget_binding.participant(signed, authority=self._authority,
                    tenant_id=self.tenant_id, target=self.target, operation=self.operation,
                    final_check=final_check)
        result = self._governed_apply(p.nonce, p.output_digest, p.decision_record_id, request["change"],
            expected_prior=p.expected_target_state, before_apply=before_apply,
            transaction_check=transaction_check, authority_proof=signed)
        # This receiver owns the nonce, and its terminal refusal proves no effect.
        # A lost acknowledgement remains UNKNOWN and retains the reservation.
        return self._release_proven_noncommit(signed, result)

    def reconcile(self, signed: SignedTargetPermit) -> TargetResult:
        """Resolve an UNKNOWN attempt from the host's exact receiving receipt, under the scope's lock.

        Only a receipt for this very operation (tenant, operation, nonce, change digest) proves it committed, and only
        the host's proof that none exists and none can still be written proves it did not. State equality proves
        nothing: the same version may predate the attempt (source review 3138). Without a receipt lookup, or when the host
        cannot say, the attempt stays UNKNOWN and the scope stays fenced: an operator must look."""
        try:
            self._authority.authenticate(signed, tenant_id=self.tenant_id, target=self.target, operation=self.operation)
        except EmissionError as refused:
            return TargetResult(Outcome.NOT_COMMITTED, f"not a permit for this target: {refused}")
        p = signed.permit
        with self._log.governing(self.scope):
            prepared, resolved = self._log.attempt(self.tenant_id, p.nonce)
            if resolved is not None or prepared is None or not self._mine(prepared, p.output_digest):
                result = self._judge(p.nonce, p.output_digest)
                if resolved is not None and self._mine(resolved, p.output_digest) and resolved.phase == NOT_COMMITTED:
                    return self._release_proven_noncommit(signed, result)
                return result
            if self._receipt is None:
                return TargetResult(Outcome.UNKNOWN, "no receiving receipt is available for this target; "
                                                     "the outcome cannot be proved either way")
            found = self._receipt(self.tenant_id, self.operation, p.nonce, p.output_digest)
            if found is Outcome.COMMITTED:
                phase = COMMITTED
            elif found is Outcome.NOT_COMMITTED:
                phase = NOT_COMMITTED
            else:
                return TargetResult(Outcome.UNKNOWN, "the host cannot yet prove the outcome of this operation")
            self._log.append(self._event(p.nonce, p.output_digest, prepared.prior_state, prepared.decision_record_id,
                                         phase, prepared.expected_state))
            return self._release_proven_noncommit(signed, self._judge(p.nonce, p.output_digest))

    def bootstrap(self, record: SignedBootstrap, output: bytes) -> TargetResult:
        """Install the FIRST state of a target that has none, under a named bootstrap key's signature over the exact
        change. Never a way to change existing governance state, never repeatable, and logged like any change."""
        digest = sha256(output).hexdigest()
        try:
            if self._bootstrap_trust is None or record.signature.key_id not in self._bootstrap_keys:
                raise EmissionError("the signer is not a bootstrap key of this deployment")
            if not self._bootstrap_trust.verify(record.body(), record.signature):
                raise EmissionError("the bootstrap signature does not verify")
            if (record.tenant_id, record.kind, record.subject, record.change_digest) != (
                    self.tenant_id, self._kind, self._subject, digest):
                raise EmissionError("the bootstrap names another tenant, target or change")
            request = self._request(output)
            if self._log.attempt(self.tenant_id, f"bootstrap:{digest}")[0] is not None:
                raise EmissionError("this bootstrap was already attempted")
            if self._initialized is not None and self._initialized():
                raise EmissionError("bootstrap installs only a first-ever state; this target has had state before, "
                                    "so any change needs a tier-4 permit")
        except (EmissionError, ValueError) as refused:
            return TargetResult(Outcome.FAILED, str(refused), self.current_state())
        # A bootstrap installs only a first state: the compare-and-apply requires "absent".
        result = self._governed_apply(f"bootstrap:{digest}", digest, f"bootstrap:{record.signature.key_id}",
                                      request["change"], expected_prior="absent", before_apply=lambda: None,
                                      first_state_only=True, authority_proof=record)
        if result.outcome is Outcome.FAILED and "governed state changed" in result.detail:
            return TargetResult(Outcome.FAILED, "bootstrap installs only a first state; changes need a tier-4 permit",
                                result.target_state)
        return result

    def _mine(self, event: GovernanceEvent, output_digest: str) -> bool:
        return (event.tenant_id == self.tenant_id and event.kind == self._kind and event.subject == self._subject
                and event.operation == self.operation and event.scope == self.scope
                and event.change_digest == output_digest)

    def _judge(self, nonce: str, output_digest: str) -> TargetResult:
        prepared, resolved = self._log.attempt(self.tenant_id, nonce)
        if resolved is not None and self._mine(resolved, output_digest):
            if resolved.phase == COMMITTED:
                return TargetResult(Outcome.COMMITTED, "governance log", output_digest)
            return TargetResult(Outcome.NOT_COMMITTED, "reconciled: the change did not happen")
        if prepared is not None and self._mine(prepared, output_digest):
            return TargetResult(Outcome.UNKNOWN, "prepared with no recorded outcome; reconcile")
        if prepared is None and resolved is None and self._log.permit_claimed(self._uses, self.tenant_id, nonce):
            # The claimant may still be about to prepare and apply. No event is
            # not proof of no future effect once the receiving claim exists.
            return TargetResult(Outcome.UNKNOWN, "permit claimed; receiving outcome not yet recorded")
        return TargetResult(Outcome.NOT_COMMITTED, "no governance attempt for this permit at this target")

    def status(self, signed: SignedTargetPermit) -> TargetResult:
        """Answered only for a genuine permit for this target and operation (source review 3129)."""
        try:
            self._authority.authenticate(signed, tenant_id=self.tenant_id, target=self.target, operation=self.operation)
        except EmissionError as refused:
            return TargetResult(Outcome.NOT_COMMITTED, f"not a permit for this target: {refused}")
        p = signed.permit
        return self.status_of(p.tenant_id, p.nonce, p.output_digest)

    def status_of(self, tenant_id: str, nonce: str, output_digest: str) -> TargetResult:
        """Answered from this subject's governance events only: another target's commit is never this one's."""
        if tenant_id != self.tenant_id:
            return TargetResult(Outcome.NOT_COMMITTED, "no governance event for this tenant")
        return self._judge(nonce, output_digest)


def _with_registry_guard(registry: Any, options: dict[str, Any]) -> dict[str, Any]:
    """A target over a GUARDED registry must admit its writes with that same guard: composed without it, every apply
    is refused by the registry after the prepared write, which reads as UNKNOWN and fences the scope for good. So the
    registry's guard is the default, and a different guard is refused at composition, never discovered at commit."""
    registry_guard = getattr(registry, "governance_guard", None)
    if not isinstance(registry_guard, GovernanceGuard):
        return options
    given = options.get("guard")
    if given is not None and given is not registry_guard:
        raise ValueError("a governance target must use the guard of the registry it writes")
    return {**options, "guard": registry_guard}


def pack_activation_target(registry: Any, reference: str, *, tenant_id: str, authority: TargetAuthority,
                           uses: PermitUseStore, log: GovernanceLog,
    **options: Any) -> GovernanceTarget:
    """Pack activation as a governance target: the state is the pack's active reference, the change activates one
    exact installed reference. The registry's own lifecycle checks still run inside `activate`."""
    pack_id = reference.partition("#")[0]

    def state() -> str:
        active = registry.active(pack_id)
        return active.reference if active is not None else "absent"

    def apply(change: Mapping[str, Any]) -> None:
        if change.get("activate") != reference:
            raise EmissionError("the change does not name this pack reference")
        registry.activate(reference, at=str(change["at"]), reason=str(change.get("reason", "")))

    def transact(governed: GovernedChange) -> None:
        # The registry's own activation transaction (source review 3139): it compares approved_prior inside its lifecycle lock,
        # calls before_commit after every blocking read and immediately before its durable write, and records the
        # receiving receipt with the activation.
        if governed.change.get("activate") != reference:
            raise EmissionError("the change does not name this pack reference")
        registry.activate(reference, at=str(governed.change["at"]), reason=str(governed.change.get("reason", "")),
                          approved_prior=governed.approved_prior, before_commit=governed.final_check,
                          receipt=(governed.tenant_id, governed.operation, governed.nonce, governed.change_digest),
                          **({"first_state_only": True} if governed.first_state_only else {}))

    # A registry whose activation takes the governed arguments gets the full contract; one that does not is applied
    # directly, cannot be reconciled (UNKNOWN stays UNKNOWN), and its lifecycle delay is outside the final check.
    import inspect
    activation = getattr(type(registry), "activate", None)
    governed_entry = activation is not None and {"approved_prior", "before_commit", "receipt"} <= set(
        inspect.signature(activation).parameters)
    receipts = getattr(registry, "governance_receipt", None)
    options.setdefault("transact", transact if governed_entry else None)
    # "Has this pack ever had a state?" from its durable history, for the bootstrap's first-ever rule (source review 3430).
    ledger = getattr(registry, "ledger", None)
    options.setdefault("initialized", (lambda: bool(ledger.history(pack_id))) if ledger is not None else None)
    options.setdefault("receipt", receipts if callable(receipts) else None)
    options = _with_registry_guard(registry, options)
    return GovernanceTarget(tenant_id=tenant_id, kind="pack-activation", subject=pack_id, authority=authority,
                            uses=uses, state=state, apply=apply, log=log, operation_name="governance:activate-pack",
                            expect=lambda change, prior: str(change.get("activate", "")),
                            **options)


def _accepts(registry: Any, method: str, *parameters: str) -> bool:
    import inspect

    function = getattr(type(registry), method, None)
    return function is not None and set(parameters) <= set(inspect.signature(function).parameters)


def _governed_entry(registry: Any, method: str) -> bool:
    """True when the registry's method takes the receiving-transaction arguments (approved_prior, before_commit,
    receipt); then the target passes them, otherwise it applies directly and cannot reconcile."""
    import inspect

    function = getattr(type(registry), method, None)
    return function is not None and {"approved_prior", "before_commit", "receipt"} <= set(
        inspect.signature(function).parameters)


def _governed_kwargs(governed: GovernedChange) -> dict[str, Any]:
    return {"approved_prior": governed.approved_prior, "before_commit": governed.final_check,
            "receipt": (governed.tenant_id, governed.operation, governed.nonce, governed.change_digest)}


def _pack_lifecycle_target(registry: Any, pack_id: str, *, tenant_id: str, authority: TargetAuthority,
                           uses: PermitUseStore, log: GovernanceLog, operation: str, method: str,
                           state: Callable[[], str], call: Callable[[Mapping[str, Any], dict[str, Any]], None],
                           **options: Any) -> GovernanceTarget:
    """One pack lifecycle operation as a governance target on the pack's shared scope and guard kind."""

    def apply(change: Mapping[str, Any]) -> None:
        call(change, {})

    def transact(governed: GovernedChange) -> None:
        call(governed.change, _governed_kwargs(governed))

    receipts = getattr(registry, "governance_receipt", None)
    options.setdefault("transact", transact if _governed_entry(registry, method) else None)
    options.setdefault("receipt", receipts if callable(receipts) else None)
    options = _with_registry_guard(registry, options)
    return GovernanceTarget(tenant_id=tenant_id, kind="pack-activation", subject=pack_id, authority=authority,
                            uses=uses, state=state, apply=apply, log=log, operation_name=operation, **options)


def _active_reference(registry: Any, pack_id: str) -> Callable[[], str]:
    def state() -> str:
        active = registry.active(pack_id)
        return active.reference if active is not None else "absent"
    return state


def pack_rollback_target(registry: Any, pack_id: str, rollback_to: str, *, tenant_id: str,
                         authority: TargetAuthority, uses: PermitUseStore, log: GovernanceLog,
                         **options: Any) -> GovernanceTarget:
    """Rolling a pack back changes the policy in force: a tier-4 governance change. The approved bytes name the exact
    version it rolls back TO, {"rollback": pack_id, "rollback_to": reference, "at", "reason"}, because the registry
    selects its fallback later (source review 3157). The registry must compare that exact target inside its own transaction
    (`approved_target`); a registry that cannot is refused, rather than letting it choose another version."""
    if not _accepts(registry, "rollback", "approved_target"):
        raise ValueError("governed rollback requires a registry that checks the approved rollback target")

    def call(change: Mapping[str, Any], governed: dict[str, Any]) -> None:
        if change.get("rollback") != pack_id or change.get("rollback_to") != rollback_to:
            raise EmissionError("the change does not roll this pack back to this version")
        registry.rollback(pack_id, at=str(change["at"]), reason=str(change.get("reason", "")),
                          approved_target=rollback_to, **governed)

    return _pack_lifecycle_target(registry, pack_id, tenant_id=tenant_id, authority=authority, uses=uses, log=log,
                                  operation="governance:rollback-pack", method="rollback",
                                  state=_active_reference(registry, pack_id), call=call, **options)


def pack_pin_target(registry: Any, reference: str, pinned_tenant: str, *, tenant_id: str,
                    authority: TargetAuthority, uses: PermitUseStore, log: GovernanceLog,
                    **options: Any) -> GovernanceTarget:
    """Pinning a tenant to one pack version chooses the policy that tenant runs under: a tier-4 governance change.
    The state is that tenant's current resolved version."""
    pack_id = reference.partition("#")[0]

    def state() -> str:
        record = registry.activation_for(pinned_tenant, pack_id)
        return f"{pinned_tenant}:{record.reference if record is not None else 'absent'}"

    def call(change: Mapping[str, Any], governed: dict[str, Any]) -> None:
        if change.get("pin") != reference or change.get("tenant") != pinned_tenant:
            raise EmissionError("the change does not pin this tenant to this version")
        registry.pin_tenant(pinned_tenant, reference, **governed)

    return _pack_lifecycle_target(registry, pack_id, tenant_id=tenant_id, authority=authority, uses=uses, log=log,
                                  operation="governance:pin-pack", method="pin_tenant", state=state, call=call,
                                  **options)


def pack_revocation_target(registry: Any, reference: str, *, tenant_id: str, authority: TargetAuthority,
                           uses: PermitUseStore, log: GovernanceLog, **options: Any) -> GovernanceTarget:
    """Revoking a pack version withdraws authority. It is approved under GovernanceWithdrawalPolicy (one supervisor)
    and the host declares its intended use below tier 4, so no cooling-off delays an emergency withdrawal; it still
    needs a permit for the exact withdrawal, runs under the scope's fence and guard, and is logged."""
    pack_id = reference.partition("#")[0]

    def call(change: Mapping[str, Any], governed: dict[str, Any]) -> None:
        if change.get("revoke") != reference:
            raise EmissionError("the change does not revoke this pack version")
        registry.revoke(reference, at=str(change["at"]), reason=str(change.get("reason", "")), **governed)

    return _pack_lifecycle_target(registry, pack_id, tenant_id=tenant_id, authority=authority, uses=uses, log=log,
                                  operation="governance:revoke-pack", method="revoke",
                                  state=_active_reference(registry, pack_id), call=call, **options)


def qualification_target(registry: Any, report: Any, *, tenant_id: str, authority: TargetAuthority,
                         uses: PermitUseStore, log: GovernanceLog,
    **options: Any) -> GovernanceTarget:
    """Admitting a checker's qualification report as a governance target. The change names the exact signed report by
    digest; the target adds that report object only if its digest is the approved one. The registry still verifies the
    report's signature against its qualification authority when it is added."""
    klass = report.verification_class

    def state() -> str:
        return sha256(canonical_bytes([r.digest() for r in registry.history(klass)])).hexdigest()

    def apply(change: Mapping[str, Any]) -> None:
        if change.get("add_report") != report.digest():
            raise EmissionError("the change does not name this exact qualification report")
        registry.add(report)

    def transact(governed: GovernedChange) -> None:
        if governed.change.get("add_report") != report.digest():
            raise EmissionError("the change does not name this exact qualification report")
        registry.add_governed(report, governed)

    options.setdefault("transact", transact)
    options.setdefault("receipt", registry.governance_receipt)
    options = _with_registry_guard(registry, options)

    def expect(change: Mapping[str, Any], prior: str) -> str:
        return sha256(canonical_bytes([r.digest() for r in registry.history(klass)] + [report.digest()])).hexdigest()

    return GovernanceTarget(tenant_id=tenant_id, kind="checker-qualification", subject=klass, authority=authority,
                            uses=uses, state=state, apply=apply, log=log, operation_name="governance:qualify-checker",
                            expect=expect,
                            **options)


def issuer_target(registry: Any, issuer_key_id: str, *, tenant_id: str, authority: TargetAuthority,
                  uses: PermitUseStore, log: GovernanceLog,
    **options: Any) -> GovernanceTarget:
    """Recognising a credential issuer, the approvers' source of authority, as a governance target."""

    def state() -> str:
        return registry.issuer_kind(issuer_key_id) or "absent"

    def apply(change: Mapping[str, Any]) -> None:
        registry.recognise(issuer_key_id, str(change["kind"]))

    def transact(governed: GovernedChange) -> None:
        registry.recognise_governed(issuer_key_id, str(governed.change["kind"]), governed)

    options.setdefault("transact", transact)
    options.setdefault("receipt", registry.governance_receipt)
    options = _with_registry_guard(registry, options)
    return GovernanceTarget(tenant_id=tenant_id, kind="approver-issuer", subject=issuer_key_id, authority=authority,
                            uses=uses, state=state, apply=apply, log=log, operation_name="governance:recognise-issuer",
                            expect=lambda change, prior: str(change.get("kind", "")),
                            **options)


__all__ = ["BOOTSTRAP_SCHEMA", "CHANGE_SCHEMA", "COMMITTED", "NOT_COMMITTED", "PREPARED", "GOVERNANCE_CONTENT_TYPE", "GOVERNANCE_ROLE", "GovernanceEvent", "GovernanceLog", "FinalCheckRefused", "GovernedChange", "ReceiptLookup", "attempt_key", "event_body",
           "GovernancePolicy", "GovernanceTarget", "GovernanceWithdrawalPolicy", "SignedBootstrap", "change_bytes", "issue_bootstrap",
           "issuer_target", "merkle_root", "pack_pin_target", "pack_revocation_target",
           "pack_rollback_target", "WITHDRAWAL_CONTENT_TYPE", "WITHDRAWAL_ROLE",
           "pack_activation_target", "publish_root", "qualification_target"]
