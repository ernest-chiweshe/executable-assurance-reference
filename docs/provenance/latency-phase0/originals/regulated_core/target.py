"""Target-bound permits and the adapters that commit them (Paper A 4.2 and 5.2; approved plan item 5).

The original permit (`permit.py`) binds tenant, decision, exact output digest, expiry and a one-time nonce, and
`EmissionAuthority.emit` hands the bytes back to the caller. That is an in-process release: the caller then
writes them wherever it likes, so nothing at the target can refuse a changed destination, and "emitted" is
recorded before any target has committed anything.

This module closes both gaps without changing that older path, which remains for in-process callers:

* A `TargetPermit` additionally binds the operation, the TARGET (kind and identity), the target's expected prior
  state, the principal, the qualification digests and the revocation epoch, all inside the signed body.
* A `TargetAdapter` is the only code that writes to its target. Immediately before commitment it verifies the
  permit against the trust directory, the exact bytes, its own target identity and the target's current state,
  then claims the nonce, then commits. The adapter holds the only write capability for its operation.
* The outcome is a separate, later event: COMMITTED, FAILED (nothing changed at the target) or UNKNOWN (the
  acknowledgement was lost). UNKNOWN is resolved by `status`, a query of the target, and never by re-sending.

No transaction spans the nonce store, the evidence log and the target. The nonce is claimed before the write, so
two concurrent commits of one permit cannot both succeed; a crash between the claim and the write leaves the
permit spent and the target unchanged, which `status` reports as NOT_COMMITTED so a fresh authorisation is
needed. Silence is never read as success or as failure.
"""
from __future__ import annotations

import enum
import json
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from .target_lock import TargetBusy as TargetBusy, target_file_lock
from .canonical import canonical_bytes
from .clock import ClockError, ClockReading, TrustedClock, read_clock
from .evidence import SignedDecisionEnvelope
from .budget import UNBUDGETED, BudgetError, MissionBudget
from .permit import EmissionError, PermitUseStore
from .signing import Signature, Signer, TrustDirectory

PERMIT_V5_SCHEMA = "regulated/permit/v5"
PERMIT_V4_SCHEMA = "regulated/permit/v4"
PERMIT_V2_SCHEMA = "regulated/permit/v2"
PERMIT_V3_SCHEMA = "regulated/permit/v3"   # v2 plus the delegated authority chain (docs/ARCHITECTURE-OF-RECORD/13)
ABSENT = "absent"                     # the expected prior state of a target that must not exist yet


@dataclass(frozen=True, slots=True)
class TargetRef:
    """Where an effect lands: the adapter kind and the target's identity within it."""

    kind: str
    identity: str

    def digest(self) -> str:
        return sha256(canonical_bytes({"kind": self.kind, "identity": self.identity})).hexdigest()


@dataclass(frozen=True, slots=True)
class BoundEffect:
    """The one effect a decision covers: these bytes, to this target, from this prior state.

    It is never passed beside a decision. It travels INSIDE the signed action's destination, written by
    `effect_destination` and read back by `effect_of`, so the decision record, and any approval of that record,
    covers exactly this effect. A caller cannot hold a genuine approval and name a different effect: changing
    the effect changes the action, and the approval no longer matches (source review 2972, 2978)."""

    output_digest: str
    target: TargetRef
    target_state: str
    mission: str = ""        # whose budget this effect draws on; "" names none, and then no budget can apply

    def as_fields(self) -> dict[str, str]:
        return {"output_digest": self.output_digest, "target_kind": self.target.kind,
                "target_identity": self.target.identity, "target_state": self.target_state,
                "mission": self.mission}


EFFECT_FIELD = "effect"


def effect_destination(fields: Mapping[str, Any], effect: BoundEffect) -> str:
    """A signed action destination that names `effect`, beside whatever else the caller's destination carries."""
    if EFFECT_FIELD in fields:
        raise ValueError(f"a destination may name its effect only through {EFFECT_FIELD!r}")
    return json.dumps({**fields, EFFECT_FIELD: effect.as_fields()}, sort_keys=True, separators=(",", ":"))


def effect_of(destination: str) -> BoundEffect | None:
    """The effect a signed action's destination names, or None when it names none or names it malformed."""
    try:
        named = json.loads(destination).get(EFFECT_FIELD)
    except (ValueError, AttributeError):
        return None
    if not isinstance(named, dict) or set(named) != {"output_digest", "target_kind", "target_identity",
                                                     "target_state", "mission"}:
        return None
    if not all(isinstance(value, str) for value in named.values()):
        return None
    if not all(named[key] for key in ("output_digest", "target_kind", "target_identity", "target_state")):
        return None
    return BoundEffect(named["output_digest"], TargetRef(named["target_kind"], named["target_identity"]),
                       named["target_state"], named["mission"])


@dataclass(frozen=True, slots=True)
class TargetPermit:
    """Everything the target adapter checks before commitment, bound under one signature."""

    tenant_id: str
    principal: str
    mission: str
    budget_reservation: str          # the reservation id, or UNBUDGETED where no limit is declared
    budget_units: int
    policy_version: str              # the policy reference and version the decision was made under
    decision_record_id: str
    decision_record_hash: str
    approval_ref: str
    assertion_id: str
    action_id: str
    operation: str
    target_kind: str
    target_digest: str
    expected_target_state: str
    output_digest: str
    qualification_digests: tuple[str, ...]
    revocation_epoch: int
    expires_at_us: int
    nonce: str
    # Delegated authority (v3). Empty for an ordinary root release, whose signed body stays exactly v2.
    grant_digest: str = ""
    chain_digest: str = ""
    root_digest: str = ""
    preparation_digest: str = ""
    clock_domain: str = ""
    issued_at_us: int = 0

    def __post_init__(self) -> None:
        if self.clock_domain or self.issued_at_us:
            ClockReading(self.clock_domain, self.issued_at_us).require_live(
                domain=self.clock_domain, issued_at_us=self.issued_at_us,
                expires_at_us=self.expires_at_us,
            )

    def signed_body(self) -> dict[str, Any]:
        body = {name: getattr(self, name) for name in self.__dataclass_fields__}  # every field is signed
        body["qualification_digests"] = list(self.qualification_digests)
        if self.clock_domain:
            return {"schema": PERMIT_V5_SCHEMA, **body}
        del body["clock_domain"]
        del body["issued_at_us"]
        if self.preparation_digest:
            return {"schema": PERMIT_V4_SCHEMA, **body}
        del body["preparation_digest"]
        if not self.grant_digest:
            # Existing v2 permits keep their exact bytes and verification (no new field, no new schema).
            for name in ("grant_digest", "chain_digest", "root_digest"):
                del body[name]
            return {"schema": PERMIT_V2_SCHEMA, **body}
        return {"schema": PERMIT_V3_SCHEMA, **body}


@dataclass(frozen=True, slots=True)
class SignedTargetPermit:
    permit: TargetPermit
    signature: Signature


class Outcome(enum.Enum):
    COMMITTED = "committed"          # the target holds exactly the permitted bytes
    FAILED = "failed"                # the target was not changed
    UNKNOWN = "unknown"              # the acknowledgement was lost; resolve with status, never by re-sending
    NOT_COMMITTED = "not_committed"  # status only: the target does not hold the permitted bytes


@dataclass(frozen=True, slots=True)
class TargetResult:
    """What an adapter observed. `target_state` is the target's state digest after the attempt, when known."""

    outcome: Outcome
    detail: str = ""
    target_state: str = ""


DEFAULT_EFFECT_MARGIN_US = 1_000_000
"""Margin the managed hosts configure between the final clock read before an effect and the permit's expiry.

It is configured, not a measured or enforced bound on how long the effect takes. Reported commits never rest on
it: a commit is reported only when a clock reading taken after the effect falls inside the permit's window. The
margin only makes such certifiable commits the usual case."""


def require_permit_clock(
    permit: TargetPermit, clock: TrustedClock | None, *, connection: Any = None, effect_margin_us: int = 0,
) -> ClockReading | None:
    """Require a fresh reading for qualified permits; never qualify legacy bytes.

    With ``effect_margin_us`` the reading must also leave that much of the window unused, so an effect that
    completes within the declared bound of this read still completes before the permit expires.
    """
    if clock is None and not permit.clock_domain:
        return None
    if clock is None or not permit.clock_domain:
        raise EmissionError("permit and receiver require the same qualified clock domain")
    try:
        reading = read_clock(clock, connection=connection)
        reading.require_live(domain=permit.clock_domain, issued_at_us=permit.issued_at_us,
                             expires_at_us=permit.expires_at_us)
    except ClockError as exc:
        raise EmissionError("permit clock domain or absolute window refused") from exc
    if effect_margin_us and reading.now_us + effect_margin_us >= permit.expires_at_us:
        raise EmissionError("permit window too short for the declared effect margin")
    return reading


class TargetAuthority:
    """Issues and verifies target-bound permits. Its signer is a distinct identity from decision and approval.

    It owns the time permits are judged by. A permit's expiry is set from this clock when it is issued, and checked
    against this clock at the moment the target validates it, inside the target's lock: a timestamp taken earlier
    by a caller never counts as the present, however long the caller or the lock kept it waiting (source review 3039)."""

    def __init__(self, signer: Signer, trust: TrustDirectory, *, revocation_epoch: Callable[[str], int],
                 clock_us: Callable[[], int] | None = None,
                 clock: TrustedClock | None = None,
                 chain_status: Callable[[str, str], None] | None = None,
                 preparation_verifier: Callable[[Any, SignedTargetPermit], None] | None = None,
                 require_preparation: bool = False,
                 effect_margin_us: int = 0) -> None:
        if type(effect_margin_us) is not int or effect_margin_us < 0:
            raise ValueError("effect margin must be a non-negative integer of microseconds")
        self.effect_margin_us = effect_margin_us
        self._signer = signer
        self._trust = trust
        self._epoch = revocation_epoch   # per tenant; raising it invalidates every outstanding permit
        if clock is not None and clock_us is not None:
            raise ValueError("configure one authority clock, not a clock and a callback")
        if clock_us is not None or not isinstance(clock, TrustedClock):
            raise ValueError("target authority requires a named trusted clock")
        ClockReading(clock.domain, 0)
        self._trusted_clock = clock
        # (tenant, grant digest) -> None, or raise EmissionError when any ancestor is revoked or the chain broken.
        self._chain_status = chain_status
        self._preparation_verifier = preparation_verifier
        self._require_preparation = require_preparation

    @property
    def checks_delegation(self) -> bool:
        return self._chain_status is not None or (self._require_preparation and self._preparation_verifier is not None)

    @property
    def clock(self) -> TrustedClock:
        """The explicit authority source used for every new permit and effect."""
        return self._trusted_clock

    def now_us(self) -> int:
        """The authority's trusted present, read afresh on every call."""
        try:
            return read_clock(self.clock).now_us
        except ClockError as exc:
            raise EmissionError("authority clock unavailable") from exc

    def epoch(self, tenant_id: str) -> int:
        """The tenant's current revocation epoch, as every permit and admission is judged against."""
        return self._epoch(tenant_id)

    def draft(self, envelope: SignedDecisionEnvelope, output: bytes, *, target: TargetRef, operation: str,
              expected_target_state: str, principal: str, approval_ref: str,
              qualification_digests: tuple[str, ...], ttl_us: int, nonce: str, not_after_us: int = 0,
              mission: str = "", budget_reservation: str = UNBUDGETED, budget_units: int = 0,
              policy_version: str = "", grant_digest: str = "", chain_digest: str = "",
              root_digest: str = "") -> TargetPermit:
        """Build unsigned terms using this authority's configured clock."""
        try:
            reading = read_clock(self.clock)
        except ClockError as exc:
            raise EmissionError("authority clock unavailable") from exc
        return self._draft_at(
            reading.now_us, envelope, output, target=target, operation=operation,
            expected_target_state=expected_target_state, principal=principal,
            approval_ref=approval_ref, qualification_digests=qualification_digests,
            ttl_us=ttl_us, nonce=nonce, not_after_us=not_after_us, mission=mission,
            budget_reservation=budget_reservation, budget_units=budget_units,
            policy_version=policy_version, grant_digest=grant_digest,
            chain_digest=chain_digest, root_digest=root_digest, clock_reading=reading,
        )

    def _draft_at(self, now: int, envelope: SignedDecisionEnvelope, output: bytes, *, target: TargetRef, operation: str,
              expected_target_state: str, principal: str, approval_ref: str,
              qualification_digests: tuple[str, ...], ttl_us: int, nonce: str, not_after_us: int = 0,
              mission: str = "", budget_reservation: str = UNBUDGETED, budget_units: int = 0,
              policy_version: str = "", grant_digest: str = "", chain_digest: str = "",
              root_digest: str = "", clock_reading: ClockReading | None = None) -> TargetPermit:
        """Build terms at a time sampled by trusted authority composition."""
        if (clock_reading is None or clock_reading.domain != self.clock.domain
                or clock_reading.now_us != now):
            raise EmissionError("qualified draft requires its configured clock reading")
        expires_at = now + ttl_us if not not_after_us else min(now + ttl_us, not_after_us)
        if expires_at <= now:
            raise EmissionError("the authority window for this request has closed")
        if envelope.clock_domain != self.clock.domain:
            raise EmissionError("decision and target clock domains differ")
        record = envelope.record
        permit = TargetPermit(
            tenant_id=record.tenant_id, principal=principal, mission=mission,
            budget_reservation=budget_reservation, budget_units=budget_units, policy_version=policy_version,
            decision_record_id=record.record_id,
            decision_record_hash=envelope.record_hash, approval_ref=approval_ref,
            assertion_id=record.assertion_id, action_id=record.action.action_id, operation=operation,
            target_kind=target.kind, target_digest=target.digest(), expected_target_state=expected_target_state,
            output_digest=sha256(output).hexdigest(), qualification_digests=tuple(sorted(qualification_digests)),
            revocation_epoch=self._epoch(record.tenant_id), expires_at_us=expires_at, nonce=nonce,
            grant_digest=grant_digest, chain_digest=chain_digest, root_digest=root_digest,
            clock_domain=clock_reading.domain if clock_reading is not None else "",
            issued_at_us=now if clock_reading is not None else 0)
        if grant_digest and not self.checks_delegation:
            raise EmissionError("a delegated permit needs a target authority that re-checks the chain")
        return permit

    def issue(self, envelope: SignedDecisionEnvelope, output: bytes, *, target: TargetRef, operation: str,
              expected_target_state: str, principal: str, approval_ref: str,
              qualification_digests: tuple[str, ...], ttl_us: int, nonce: str, not_after_us: int = 0,
              mission: str = "", budget_reservation: str = UNBUDGETED, budget_units: int = 0,
              policy_version: str = "", grant_digest: str = "", chain_digest: str = "",
              root_digest: str = "") -> SignedTargetPermit:
        """Issue current named-clock terms and recheck after signing completes.

        A preparation-required authority uses its retained issuer instead.
        Historical permit encodings remain available for authentication only.
        """
        if self._require_preparation:
            raise EmissionError("this authority requires retained preparation before signing")
        permit = self.draft(
            envelope, output, target=target, operation=operation,
            expected_target_state=expected_target_state, principal=principal,
            approval_ref=approval_ref, qualification_digests=qualification_digests,
            ttl_us=ttl_us, nonce=nonce, not_after_us=not_after_us,
            mission=mission, budget_reservation=budget_reservation,
            budget_units=budget_units, policy_version=policy_version,
            grant_digest=grant_digest, chain_digest=chain_digest, root_digest=root_digest,
        )
        signed = SignedTargetPermit(permit, self._signer.sign(permit.signed_body()))
        self.current(signed)
        return signed

    def authenticate(self, signed: SignedTargetPermit, *, tenant_id: str, target: TargetRef, operation: str,
                     connection: Any = None) -> None:
        """Raise `EmissionError` unless this is a genuine permit for this tenant, target and operation."""
        p = signed.permit
        if signed.signature.key_id != self._signer.key_id or not self._trust.verify(p.signed_body(), signed.signature):
            raise EmissionError("permit signature invalid or untrusted")
        if p.preparation_digest:
            if self._preparation_verifier is None:
                raise EmissionError("v4 permit requires retained preparation verification")
            self._preparation_verifier(connection, signed)
        elif self._require_preparation:
            raise EmissionError("receiver requires a preparation-bound permit")
        if p.tenant_id != tenant_id:
            raise EmissionError("permit tenant mismatch")
        if p.operation != operation:
            raise EmissionError("permit is for a different operation")
        if p.target_kind != target.kind or p.target_digest != target.digest():
            raise EmissionError("permit is for a different target")

    def current(self, signed: SignedTargetPermit, *, connection: Any = None, at_effect: bool = False) -> None:
        """Raise `EmissionError` unless the permit is unrevoked and unexpired by this authority's clock, now.
        The adapter asks again at the effect itself, after its blocking IO (source review 3053).

        The epoch lookup may itself block (a durable ledger), so it is read FIRST and the clock LAST: the time
        decision is the final act before the caller's effect (source review 3058). A revocation recorded after that epoch
        read is ordered after this commit and refuses every later one.

        ``at_effect`` marks that final check: it also requires ``effect_margin_us`` of the window to remain."""
        p = signed.permit
        if p.preparation_digest and connection is not None:
            epoch = int(connection.execute(
                "SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1 WHERE tenant=%s",
                (p.tenant_id,)).fetchone()[0])
        else:
            epoch = self._epoch(p.tenant_id)
        if p.grant_digest and p.preparation_digest:
            if connection is None or self._preparation_verifier is None:
                raise EmissionError("delegated prepared authority requires the effect transaction")
            self._preparation_verifier(connection, signed)
        elif p.grant_digest:
            # Read with the epoch, before the clock: an ancestor revoked at any time up to here refuses.
            if self._chain_status is None:
                raise EmissionError("this target authority cannot re-check a delegated chain")
            self._chain_status(p.tenant_id, p.grant_digest)
        require_permit_clock(p, self.clock, connection=connection,
                             effect_margin_us=self.effect_margin_us if at_effect else 0)
        if p.revocation_epoch != epoch:
            raise EmissionError("permit revoked: the tenant's revocation epoch has moved")

    def completed_before_expiry(self, signed: SignedTargetPermit) -> bool:
        """Read the clock after an effect: True proves the effect finished before the permit expired.

        The effect completed no later than this read, so a reading inside the window certifies it. A reading
        at or past expiry, or no reading at all, leaves the effect's timing uncertified."""
        try:
            require_permit_clock(signed.permit, self.clock)
        except EmissionError:
            return False
        return True

    def verify(self, signed: SignedTargetPermit, output: bytes, *, tenant_id: str, target: TargetRef,
               operation: str, current_target_state: str, connection: Any = None) -> None:
        """Raise `EmissionError` unless this permit authorises exactly these bytes, for this tenant, here, now.
        Now is this authority's clock, read at this call; the adapter calls it inside its lock."""
        self.authenticate(signed, tenant_id=tenant_id, target=target, operation=operation, connection=connection)
        self.current(signed, connection=connection)
        p = signed.permit
        if sha256(output).hexdigest() != p.output_digest:
            raise EmissionError("output does not match the authorized digest")
        if current_target_state != p.expected_target_state:
            raise EmissionError("target state changed since authorization")


class TargetAdapter(Protocol):
    """The only writer for one tenant's target. It checks the permit at the target, commits, and answers status."""

    tenant_id: str

    @property
    def target(self) -> TargetRef: ...

    @property
    def operation(self) -> str: ...

    def current_state(self) -> str:
        """The target's state digest now, or `ABSENT`."""
        ...

    def commit(self, signed: SignedTargetPermit, output: bytes) -> TargetResult: ...

    def status(self, signed: SignedTargetPermit) -> TargetResult:
        """Authenticate the permit as one for THIS tenant, target and operation, then answer from the target's
        own durable commit receipts: never from content equality.

        Status never changes the target's content. It writes in two cases only. It completes an interrupted
        cancellation (retiring the nonce, releasing the reservation and writing the cancelled receipt), as
        before. And when it observes, inside the permit's window, that an effect which already happened did so
        before expiry, it writes a certificate receipt so the observation outlives the window and the process."""
        ...

    def status_of(self, tenant_id: str, nonce: str, output_digest: str) -> TargetResult:
        """The same answer by nonce, for reconciliation after a restart, when the permit object is gone."""
        ...


def file_state(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest() if path.is_file() else ABSENT


def _file_identity(path: str | Path) -> str:
    """The file-system identity of a file: survives a rename, differs for any other file with equal bytes."""
    stat = os.stat(path)
    return f"{stat.st_dev}:{stat.st_ino}"


class ReleaseAdmissionUnavailable(RuntimeError):
    """Session authority could not be confirmed; reconcile any possible effect."""


@dataclass
class FilesystemTargetAdapter:
    """Commits permitted bytes to one file path, serialized, atomically, with durable receipts.

    Guarantee boundary. Every commit through ANY adapter for this path holds one exclusive lock file for the whole
    check, claim and write, so two permits for one target cannot both pass the expected-state check (source review 2938,
    counterexample 1). A target expected ABSENT is created with a hard link, which fails if anything exists, so
    even a writer outside this protocol cannot be silently overwritten on first release. A writer that ignores
    the lock and replaces an EXISTING file is outside the guarantee: that is the unmanaged-writer boundary.

    Receipts. Before the rename the adapter durably records a `prepared` receipt naming the tenant, nonce,
    target, output digest and the staged file's identity; after it, a `committed` receipt. Status answers only
    from these receipts for the exact tenant, nonce, target and bytes (counterexample 2): equal bytes written by
    anyone else, or a permit for another tenant or target, are never COMMITTED. After a crash between the two
    receipts, the destination's file identity decides: it equals the staged file's only if this rename happened.
    Anything else that cannot be decided is UNKNOWN.

    Linearization (source review 3053). The permit is verified when the lock is taken, and its freshness (expiry and
    revocation) is decided AGAIN after every blocking step of the protocol (nonce claim, staging, prepared receipt),
    immediately before the rename or link. That final check is the commit's linearization point: no IO of this
    protocol lies between it and the effect. A filesystem offers no rename conditional on time, so the one honest
    limit is the scheduler: the process may be paused between the check and the system call. A permit that lapses
    before the check is refused with an `aborted` receipt and its target unchanged.

    Budget. The permit's reservation already counts against the mission limit, so the cap holds whether or not it
    is converted. It is converted to consumption only AFTER the effect; an attempt aborted before the effect
    releases it, so a lapsed or refused commit never spends the mission's unit. The nonce stays spent: a new
    attempt needs a new authorization.

    `fail_after_write` exists for fault drills: it simulates an acknowledgement lost after the committed receipt.
    """

    path: Path
    tenant_id: str
    authority: TargetAuthority
    uses: PermitUseStore
    operation_name: str = "write-file"
    budget: MissionBudget | None = None
    lock_wait_s: float = 10.0
    fail_after_write: bool = field(default=False, repr=False)
    # Composed by the host while retaining its admission transaction.
    effect_check: Callable[[], None] | None = field(default=None, repr=False)

    @property
    def target(self) -> TargetRef:
        return TargetRef("filesystem", str(self.path.resolve()))

    @property
    def operation(self) -> str:
        return self.operation_name

    def current_state(self) -> str:
        return file_state(self.path)

    # â”€â”€ receipts â”€â”€

    def _receipts(self) -> Path:
        return self.path.parent / ".commit-receipts"

    def _receipt_path(self, nonce: str, kind: str) -> Path:
        token = sha256(canonical_bytes({"target": self.target.digest(), "operation": self.operation, "nonce": nonce})).hexdigest()
        return self._receipts() / f"{token}.{kind}.json"

    def _write_receipt(self, nonce: str, kind: str, body: dict[str, str]) -> None:
        self._receipts().mkdir(parents=True, exist_ok=True)
        final = self._receipt_path(nonce, kind)
        handle, staging = tempfile.mkstemp(prefix=".receipt-", dir=self._receipts())
        with os.fdopen(handle, "wb") as out:
            out.write(canonical_bytes({"kind": kind, **body}))
            out.flush()
            os.fsync(out.fileno())
        os.replace(staging, final)

    def _read_receipt(self, nonce: str, kind: str) -> dict[str, str] | None:
        path = self._receipt_path(nonce, kind)
        if not path.is_file():
            return None
        return dict(json.loads(path.read_text(encoding="utf-8")))

    # â”€â”€ the lock â”€â”€

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock = self.path.with_name(self.path.name + ".commit-lock")
        with target_file_lock(lock, wait_s=self.lock_wait_s):
            yield

    # â”€â”€ commit â”€â”€

    def commit(self, signed: SignedTargetPermit, output: bytes) -> TargetResult:
        p = signed.permit
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._locked():
                try:
                    # Validated only now, holding the lock, against the authority's live clock.
                    self.authority.verify(signed, output, tenant_id=self.tenant_id, target=self.target,
                                          operation=self.operation, current_target_state=self.current_state())
                    if p.budget_reservation != UNBUDGETED and self.budget is None:
                        raise EmissionError("a budgeted permit reached a target with no mission budget to consume")
                    if (self._read_receipt(p.nonce, "cancelling") is not None
                            or self._read_receipt(p.nonce, "cancelled") is not None):
                        found = self._judge(p.tenant_id, p.nonce, p.output_digest)
                        if found.outcome is Outcome.NOT_COMMITTED:
                            return TargetResult(Outcome.FAILED, "permit was cancelled")
                        return found
                    self.uses.consume(p.tenant_id, p.nonce)            # claimed BEFORE anything is staged
                except (EmissionError, BudgetError) as refused:
                    return TargetResult(Outcome.FAILED, str(refused), self.current_state())
                return self._write(signed, output)
        except TargetBusy as busy:
            return TargetResult(Outcome.FAILED, str(busy), self.current_state())

    def cancel(self, signed: SignedTargetPermit) -> TargetResult:
        """Retire exact authority before reclaiming its unconsumed reservation.

        Cancellation shares the effect lock. It never changes a committed or
        uncertain effect. A durable signed-permit receipt lets status finish
        interrupted cleanup without issuing or replaying any effect.
        """
        p = signed.permit
        try:
            self.authority.authenticate(signed, tenant_id=self.tenant_id,
                                        target=self.target, operation=self.operation)
        except EmissionError as refused:
            return TargetResult(Outcome.FAILED, str(refused))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._locked():
                found = self._judge(p.tenant_id, p.nonce, p.output_digest)
                if found.outcome is not Outcome.NOT_COMMITTED:
                    return found
                if p.budget_reservation != UNBUDGETED and self.budget is None:
                    return TargetResult(Outcome.UNKNOWN, "reservation allocator unavailable")
                # Persist intent before retirement, so a lost store acknowledgement
                # can be reconciled using this exact signed permit.
                body = {
                    "tenant": p.tenant_id, "target": p.target_digest,
                    "operation": p.operation, "output_digest": p.output_digest,
                    "signed_permit": json.dumps(asdict(signed), sort_keys=True),
                }
                self._write_receipt(p.nonce, "cancelling", body)
                return self._finish_cancellation(p.nonce, body)
        except Exception:
            # Includes database and filesystem acknowledgement failures. Keep
            # the reservation held unless durable retirement is known.
            return TargetResult(Outcome.UNKNOWN, "permit cancellation needs receipt reconciliation")

    def _finish_cancellation(self, nonce: str, body: dict[str, str]) -> TargetResult:
        """Authenticate persisted cleanup authority before any budget mutation."""
        try:
            raw = json.loads(body["signed_permit"])
            fields = dict(raw["permit"])
            fields["qualification_digests"] = tuple(fields["qualification_digests"])
            signed = SignedTargetPermit(TargetPermit(**fields), Signature(**raw["signature"]))
            p = signed.permit
            self.authority.authenticate(signed, tenant_id=self.tenant_id,
                                        target=self.target, operation=self.operation)
            if (p.nonce != nonce or p.tenant_id != body.get("tenant")
                    or p.output_digest != body.get("output_digest")
                    or p.target_digest != body.get("target")
                    or p.operation != body.get("operation")):
                raise EmissionError("cancellation receipt does not match its authority")
            if p.budget_reservation != UNBUDGETED and self.budget is None:
                raise BudgetError("reservation allocator unavailable")
            if not self.uses.used(p.tenant_id, nonce):
                self.uses.consume(p.tenant_id, nonce)
            self._release(p)
            self._write_receipt(nonce, "cancelled", body)
            return TargetResult(Outcome.NOT_COMMITTED, "permit retired and reservation reclaimed")
        except Exception:
            return TargetResult(Outcome.UNKNOWN, "reservation cleanup awaits authenticated reconciliation")

    def _write(self, signed: SignedTargetPermit, output: bytes) -> TargetResult:
        p = signed.permit
        handle, staging = tempfile.mkstemp(prefix=".commit-", dir=self.path.parent)
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(output)
                out.flush()
                os.fsync(out.fileno())
            staged_identity = _file_identity(staging)
            mode = "create" if p.expected_target_state == ABSENT else "replace"
            self._write_receipt(p.nonce, "prepared", {
                "tenant": p.tenant_id, "target": p.target_digest, "operation": p.operation, "output_digest": p.output_digest,
                "staged_identity": staged_identity, "staged_path": staging, "mode": mode,
                # The permit's window, so status can certify the effect's timing without the signed permit.
                "clock_domain": p.clock_domain, "expires_at_us": str(p.expires_at_us)})
        except OSError as broken:
            # Nothing was renamed: no prepared receipt exists, so status already answers NOT_COMMITTED.
            if os.path.exists(staging):
                os.remove(staging)
            self._release(p)
            return TargetResult(Outcome.FAILED, f"could not stage the release: {broken}", self.current_state())
        try:
            # The linearization point: freshness decided after every blocking step, nothing of ours after it but
            # the rename. The configured effect margin must also remain; it does not bound the rename itself.
            self.authority.current(signed, at_effect=True)
            if self.effect_check is not None:
                # The composed check covers both session and permit deadlines
                # on its database clock after all blocking target work.
                self.effect_check()
        except (EmissionError, ReleaseAdmissionUnavailable) as lapsed:
            return self._abort(p, staging, f"authority unavailable before the effect: {lapsed}")
        try:
            if mode == "create":
                os.link(staging, self.path)                 # atomic create-if-absent: fails if anything exists
                os.remove(staging)
            else:
                os.replace(staging, self.path)
        except OSError as broken:
            if self.path.is_file() and _file_identity(self.path) == staged_identity:
                # The rename happened; only the cleanup failed.
                return self._committed(p, self.authority.completed_before_expiry(signed))
            # Decided in-process: the target was not changed.
            return self._abort(p, staging, "target state changed since authorization: it now exists"
                               if isinstance(broken, FileExistsError) else f"write interrupted: {broken}")
        return self._committed(p, self.authority.completed_before_expiry(signed))

    def _abort(self, p: TargetPermit, staging: str, why: str) -> TargetResult:
        """The target was not changed: record it, so status need not guess, and return the mission's unit."""
        self._write_receipt(p.nonce, "aborted", {"tenant": p.tenant_id, "target": p.target_digest, "operation": p.operation,
                                                 "output_digest": p.output_digest, "why": why})
        if os.path.exists(staging):
            os.remove(staging)
        self._release(p)
        return TargetResult(Outcome.FAILED, why, self.current_state())

    def _release(self, p: TargetPermit) -> None:
        if p.budget_reservation != UNBUDGETED and self.budget is not None:
            self.budget.release(p.tenant_id, p.mission, p.budget_reservation)

    def _committed(self, p: TargetPermit, before_expiry: bool) -> TargetResult:
        """Record an effect that exists. ``before_expiry`` is the post-effect clock certificate."""
        if p.budget_reservation != UNBUDGETED:
            assert self.budget is not None
            try:
                # Converted only now the effect exists: one effect, one unit. The live reservation already held the
                # unit against the limit, so a failure here cannot let the mission exceed it; it is reported.
                self.budget.consume(p.tenant_id, p.mission, p.budget_reservation)
            except (BudgetError, OSError) as unrecorded:
                return TargetResult(Outcome.UNKNOWN, f"committed, but the mission consumption could not be recorded: "
                                                     f"{unrecorded}; the reservation still holds the unit; reconcile by status")
        try:
            # Self-describing: the receipt names the nonce and the decision its permit carried, so a host can check
            # it against the signed outcome record (it is not itself signed; the outcome record is).
            self._write_receipt(p.nonce, "committed", {"tenant": p.tenant_id, "target": p.target_digest,
                                                       "operation": p.operation, "output_digest": p.output_digest,
                                                       "nonce": p.nonce, "decision_record_hash": p.decision_record_hash,
                                                       "completed_before_expiry": "certified" if before_expiry
                                                       else "uncertified"})
        except OSError as broken:
            # The effect happened and its receipt did not: a discrepancy, reported as UNKNOWN rather than
            # hidden. The prepared receipt and the destination's file identity still let status resolve it.
            return TargetResult(Outcome.UNKNOWN, f"committed, but the committed receipt could not be written: "
                                                 f"{broken}; reconcile by status")
        if self.fail_after_write:
            return TargetResult(Outcome.UNKNOWN, "acknowledgement lost after commit (drill)")
        if not before_expiry:
            # The effect exists, but no clock reading places its completion before expiry: the declared effect
            # margin was exceeded or the clock failed. Reported, never presented as a clean commit.
            return TargetResult(Outcome.UNKNOWN, "committed, but completion before the permit's expiry is "
                                                 "uncertified; the receipt records it; reconcile by status")
        return TargetResult(Outcome.COMMITTED, "", p.output_digest)

    # â”€â”€ status â”€â”€

    def status(self, signed: SignedTargetPermit) -> TargetResult:
        p = signed.permit
        try:
            self.authority.authenticate(signed, tenant_id=self.tenant_id, target=self.target,
                                        operation=self.operation)
        except EmissionError as refused:
            return TargetResult(Outcome.NOT_COMMITTED, f"not a permit for this target: {refused}")
        return self.status_of(p.tenant_id, p.nonce, p.output_digest)

    def status_of(self, tenant_id: str, nonce: str, output_digest: str) -> TargetResult:
        """Resolve receipts under the effect lock; a busy lock gives UNKNOWN.

        An authenticated pending cancellation may finish nonce retirement and
        budget reclamation here. Resolution never sends or repeats an effect.
        """
        if tenant_id != self.tenant_id:
            return TargetResult(Outcome.NOT_COMMITTED, "no receipt for this tenant at this target")
        if not self.path.parent.is_dir():
            # Every commit creates the target's directory before it takes the lock, stages or writes a receipt, so
            # with no directory there is no receipt and no commit for any nonce; the lock itself cannot be taken.
            return TargetResult(Outcome.NOT_COMMITTED, "no receipt: this operation never reached the target")
        try:
            with self._locked():
                return self._judge(tenant_id, nonce, output_digest)
        except TargetBusy:
            return TargetResult(Outcome.UNKNOWN, "a commit for this target is in flight or its legacy lock is unresolved; "
                                                 "query again, or reconcile after the lock is cleared")

    def _certify_now(self, nonce: str, prepared: dict[str, str] | None, output_digest: str,
                     occurred: str) -> TargetResult | None:
        """Certify, durably, an effect that has already happened, if a clock reading now is inside its window.

        The effect preceded this reading, so a reading before expiry, in the permit's own domain, certifies it.
        Only a retained certificate is reported COMMITTED: the receipt keeps the answer once the window passes
        or the process restarts. A certificate that cannot be stored is reported UNKNOWN, since the result could
        not be kept. ``occurred`` states how the effect is known to have happened. Returns None when no reading
        can certify (no recorded window, no clock, or at or past expiry). Called with the target lock held."""
        if prepared is None or not prepared.get("clock_domain") or not prepared.get("expires_at_us", "").isdigit():
            return None
        try:
            reading = read_clock(self.authority.clock)
        except ClockError:
            return None
        if reading.domain != prepared["clock_domain"] or not reading.now_us < int(prepared["expires_at_us"]):
            return None
        try:
            self._write_receipt(nonce, "certificate", {
                "tenant": prepared["tenant"], "target": prepared["target"], "operation": prepared["operation"],
                "output_digest": prepared["output_digest"], "completed_before_expiry": "certified",
                "clock_domain": reading.domain, "certified_at_us": str(reading.now_us)})
        except OSError as broken:
            return TargetResult(Outcome.UNKNOWN, f"{occurred}; inside its window now, but the timing certificate "
                                                 f"could not be retained: {broken}; query again")
        return TargetResult(Outcome.COMMITTED, f"{occurred}; certified inside the permit's window", output_digest)

    def _judge(self, tenant_id: str, nonce: str, output_digest: str) -> TargetResult:
        target = self.target.digest()

        def ours(receipt: dict[str, str] | None) -> bool:
            return (receipt is not None and receipt.get("tenant") == tenant_id and receipt.get("target") == target and receipt.get("operation") == self.operation
                    and receipt.get("output_digest") == output_digest)

        prepared = self._read_receipt(nonce, "prepared")
        committed = self._read_receipt(nonce, "committed")
        if ours(committed):
            assert committed is not None
            certificate = committed.get("completed_before_expiry")
            if certificate == "certified":
                return TargetResult(Outcome.COMMITTED, "committed receipt", output_digest)
            if certificate == "uncertified":
                return TargetResult(Outcome.UNKNOWN, "the effect occurred; its completion before the permit's expiry "
                                                     "is uncertified (committed receipt)")
            if ours(self._read_receipt(nonce, "certificate")):
                return TargetResult(Outcome.COMMITTED, "committed receipt, certified before expiry by a later "
                                                       "observation", output_digest)
            certified = self._certify_now(nonce, prepared if ours(prepared) else None, output_digest,
                                          "committed receipt without a certificate")
            if certified is not None:
                return certified
            return TargetResult(Outcome.UNKNOWN, "the effect occurred; the committed receipt carries no certificate "
                                                 "and the permit's window cannot certify it now")
        cancelled = self._read_receipt(nonce, "cancelled")
        if ours(cancelled):
            return TargetResult(Outcome.NOT_COMMITTED, "cancelled receipt: permit retired")
        cancelling = self._read_receipt(nonce, "cancelling")
        if ours(cancelling):
            assert cancelling is not None
            return self._finish_cancellation(nonce, cancelling)
        if ours(self._read_receipt(nonce, "aborted")):
            return TargetResult(Outcome.NOT_COMMITTED, "aborted receipt: the target was not changed")
        if not ours(prepared):
            # The nonce is claimed before staging and the prepared receipt is durable before any rename,
            # so without one no rename by this operation can have happened.
            return TargetResult(Outcome.NOT_COMMITTED, "no receipt: this operation never reached the target")
        assert prepared is not None
        if ours(self._read_receipt(nonce, "certificate")):
            # Written only after occurrence was proven, so it stands even after a later permitted update has
            # replaced the target and its identity no longer matches this nonce's staged file.
            return TargetResult(Outcome.COMMITTED, "the effect occurred, certified before expiry by an earlier "
                                                   "observation", output_digest)
        try:
            landed = self.path.is_file() and _file_identity(self.path) == prepared["staged_identity"]
        except OSError:
            return TargetResult(Outcome.UNKNOWN, "the target cannot be inspected")
        if landed:
            # Identity proves the rename happened, not when. A reading inside the window now proves it was in time,
            # and the certificate receipt keeps that proof once the window has passed.
            certified = self._certify_now(nonce, prepared, output_digest,
                                          "the staged file is the target: the rename happened")
            if certified is not None:
                return certified
            return TargetResult(Outcome.UNKNOWN, "the staged file is the target: the rename happened; its completion "
                                                 "before the permit's expiry is uncertified")
        # A rename consumes the staged name atomically, so in replace mode a staged file still present proves the
        # rename never happened, whatever any other writer did since. A hard link leaves the staged name in place,
        # so in create mode it proves nothing: the link may have happened and the target been changed afterwards
        # by a writer outside this protocol (source review 2964). That case stays UNKNOWN.
        staged = prepared.get("staged_path", "")
        try:
            still_staged = bool(staged) and os.path.isfile(staged) and _file_identity(staged) == prepared["staged_identity"]
        except OSError:
            still_staged = False
        if still_staged and prepared.get("mode") == "replace":
            return TargetResult(Outcome.NOT_COMMITTED, "the staged file was never renamed onto the target")
        return TargetResult(Outcome.UNKNOWN, "prepared but not proven committed; resolve by the authorised procedure")


__all__ = ["ABSENT", "EFFECT_FIELD", "PERMIT_V2_SCHEMA", "PERMIT_V3_SCHEMA", "PERMIT_V5_SCHEMA", "BoundEffect", "FilesystemTargetAdapter", "Outcome", "SignedTargetPermit",
           "TargetAdapter", "TargetAuthority", "TargetBusy", "TargetPermit", "TargetRef", "TargetResult",
           "effect_destination", "effect_of", "file_state"]
