"""Egress admission: inside regulated scope, workspace content leaves only under a door permit (Paper A 4.2, rows
A01 and A02; docs/ARCHITECTURE-OF-RECORD/14-egress-admission.md, corrected under review in ledger 3339 and 3343).

Scope, not labels, decides. A tenant is in regulated scope once a regulated pack has been enrolled for it, in an
append-only, tenant-scoped history that nothing removes: deactivating a pack never makes retained governed content
unregulated. A tenant reads as verified unregulated only after an initial inventory of its existing data has been
recorded and no enrolment exists; before that, or when the history cannot be read, its scope is Unknown and every
send refuses. Unknown is never the same answer as unregulated.

Inside regulated scope, a send is admissible only if every pack in the tenant's scope declares an egress action that
admits it (the floor). A tenant policy may add requirements, never relax the floor, and lineage may only add packs to
it: a copy, an excerpt or a paraphrase that loses its lineage falls back to the same floor, never to a looser policy.
No pack declares an egress action today, so every in-scope send refuses. Every refusal goes to the host's signed
refusal sink before it is raised.

The outside-scope answer is a Passthrough bound to the scope revision it was decided on. The sending path never checks
it and then sends: it hands the transport to `send`, which holds the tenant's scope lock (the same lock every enrolment
takes) across a fresh read of the history and the start of the transport, so no host can enrol the tenant between the
check and the bytes leaving (source review 3347). The outgoing request must be exactly the admitted one.
"""
from __future__ import annotations

import hashlib
import re
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

T = TypeVar("T")

SCOPE_SCHEMA = "regulated/egress-scope/v1"
# The policy a refused send is recorded under when a host records straight onto its recorder.
EGRESS_POLICY_ID, EGRESS_POLICY_VERSION = "egress-admission", "1.0.0"
_DIGEST = re.compile(r"[0-9a-f]{64}")


# ── scope ──────────────────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Unregulated:
    """Verified: the initial inventory is recorded and no regulated pack has ever been enrolled for the tenant."""
    revision: int


@dataclass(frozen=True, slots=True)
class Regulated:
    """At least one regulated pack has been enrolled for the tenant; `packs` is every one ever enrolled."""
    packs: frozenset[str]
    revision: int


@dataclass(frozen=True, slots=True)
class Unknown:
    """The scope cannot be established: no recorded inventory, or the history could not be read."""
    reason: str


ScopeState = Unregulated | Regulated | Unknown

ENROLLED, INVENTORIED = "enrolled", "inventoried"


@dataclass(frozen=True, slots=True)
class ScopeEvent:
    """One immutable entry of a tenant's scope history. `revision` counts from 1 and never repeats."""
    tenant: str
    revision: int
    kind: str                     # ENROLLED or INVENTORIED
    pack_ref: str                 # the enrolled pack reference; "" for an inventory
    packs: tuple[str, ...]        # an inventory's regulated packs found in existing data; () for an enrolment
    source: str                   # what enrolled it, or the inventory's evidence reference


class EgressScopeStore(Protocol):
    def enroll(self, tenant: str, pack_ref: str, *, source: str) -> int:
        """Record that `pack_ref` is in the tenant's scope, once; return the tenant's revision after it."""
        ...

    def record_inventory(self, tenant: str, packs: frozenset[str], *, evidence: str) -> int:
        """Record a completed inventory of the tenant's existing data and the regulated packs it found."""
        ...

    def events(self, tenant: str) -> tuple[ScopeEvent, ...]:
        """The tenant's whole scope history, in revision order."""
        ...

    def guard(self, tenant: str) -> AbstractContextManager[Callable[[], tuple[ScopeEvent, ...]]]:
        """Hold the tenant's scope lock, the one every enrolment and inventory takes, for the whole `with` block, and
        yield a reader of the history under that lock. No enrolment for the tenant can commit until the block ends."""
        ...


def _checked_text(value: object, what: str) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise ValueError(f"{what} must be a non-empty string")
    return value


class InMemoryEgressScopeStore:
    """One process's scope history: append-only, one lock ordering every write."""

    def __init__(self) -> None:
        self._events: dict[str, list[ScopeEvent]] = {}
        self._lock = threading.Lock()
        self._tenant_locks: dict[str, threading.RLock] = {}

    def _tenant_lock(self, tenant: str) -> threading.RLock:
        with self._lock:
            return self._tenant_locks.setdefault(tenant, threading.RLock())

    def enroll(self, tenant: str, pack_ref: str, *, source: str) -> int:
        tenant, pack_ref, source = (_checked_text(tenant, "tenant"), _checked_text(pack_ref, "pack reference"),
                                    _checked_text(source, "enrolment source"))
        with self._tenant_lock(tenant), self._lock:
            history = self._events.setdefault(tenant, [])
            if not any(e.kind == ENROLLED and e.pack_ref == pack_ref for e in history):
                history.append(ScopeEvent(tenant, len(history) + 1, ENROLLED, pack_ref, (), source))
            return len(history)

    def record_inventory(self, tenant: str, packs: frozenset[str], *, evidence: str) -> int:
        tenant, evidence = _checked_text(tenant, "tenant"), _checked_text(evidence, "inventory evidence")
        found = tuple(sorted(_checked_text(p, "pack reference") for p in packs))
        with self._tenant_lock(tenant), self._lock:
            history = self._events.setdefault(tenant, [])
            history.append(ScopeEvent(tenant, len(history) + 1, INVENTORIED, "", found, evidence))
            return len(history)

    def events(self, tenant: str) -> tuple[ScopeEvent, ...]:
        with self._lock:
            return tuple(self._events.get(tenant, ()))

    @contextmanager
    def guard(self, tenant: str) -> Iterator[Callable[[], tuple[ScopeEvent, ...]]]:
        with self._tenant_lock(tenant):
            yield lambda: self.events(tenant)


def _well_formed(event: object, tenant: str, revision: int) -> bool:
    """Every field of a history entry, exactly: anything else makes the whole history Unknown (source review 3347 R3)."""
    if not isinstance(event, ScopeEvent) or event.tenant != tenant or event.revision != revision:
        return False
    if type(event.source) is not str or not event.source or type(event.packs) is not tuple:
        return False
    if event.kind == ENROLLED:
        return type(event.pack_ref) is str and bool(event.pack_ref) and event.packs == ()
    if event.kind == INVENTORIED:
        return event.pack_ref == "" and all(type(p) is str and p for p in event.packs)
    return False


def history_state(history: tuple[ScopeEvent, ...], tenant: str) -> ScopeState:
    """The scope a history establishes; a malformed or non-contiguous history is Unknown."""
    if not all(_well_formed(e, tenant, i) for i, e in enumerate(history, start=1)):
        return Unknown("the scope history is not one well-formed, contiguous record for this tenant")
    packs = frozenset(e.pack_ref for e in history if e.kind == ENROLLED)
    packs |= frozenset(p for e in history if e.kind == INVENTORIED for p in e.packs)
    revision = len(history)
    if packs:
        return Regulated(packs, revision)
    if any(e.kind == INVENTORIED for e in history):
        return Unregulated(revision)
    return Unknown("no inventory of this tenant's existing data has been recorded")


def scope_state(store: EgressScopeStore, tenant: str) -> ScopeState:
    """The tenant's scope from its history alone. Any failure to read it, or a malformed history, is Unknown."""
    try:
        history = store.events(tenant)
    except Exception as exc:  # noqa: BLE001 - an unreadable history must refuse, never pass
        return Unknown(f"the scope history could not be read ({type(exc).__name__})")
    return history_state(history, tenant)


# ── admission ──────────────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class EgressRequest:
    """One outbound send, every field filled by the host from server-owned state, never by the caller."""
    tenant: str
    subject: str        # who is sending: the authenticated actor or executor
    purpose: str        # the declared purpose of the send, e.g. "publish:youtube" or "message:email"
    endpoint_id: str    # the registered receiving endpoint
    digest: str         # sha256 of the exact bytes that would leave
    byte_size: int


@dataclass(frozen=True, slots=True)
class Passthrough:
    """Admission for a verified unregulated tenant, bound to the scope revision it was decided on."""
    request: EgressRequest
    revision: int


class EgressRefused(RuntimeError):
    """A refused send. `record` is the signed refusal's reference, or "" when the sink could not record it."""

    def __init__(self, code: str, reason: str, record: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code, self.reason, self.record = code, reason, record


class EgressFloor(Protocol):
    def refusal(self, packs: frozenset[str], request: EgressRequest) -> str | None:
        """None when EVERY pack in `packs` declares an egress action admitting this send; otherwise why not."""
        ...


class NoDeclaredEgress:
    """The floor today: no pack's signed rulebook declares an egress action, so no in-scope send is admissible."""

    def refusal(self, packs: frozenset[str], request: EgressRequest) -> str | None:
        return "no pack in this tenant's regulated scope declares an egress action admitting this send"


class EgressLineage(Protocol):
    def packs(self, tenant: str, digest: str) -> frozenset[str]:
        """Packs trusted host state ties these exact bytes to. Only ever adds to the floor."""
        ...


class EgressPermitIssuer(Protocol):
    def issue(self, request: EgressRequest, packs: frozenset[str]) -> object:
        """The A02 egress choke-point permit for exactly this send (regulated_core/choke_points.py)."""
        ...


RefusalSink = Callable[[EgressRequest, str, str], str]


class EgressAdmission:
    """The one seam every covered outbound path reaches after resolving its exact bytes and before sending them."""

    def __init__(self, *, store: EgressScopeStore, refusal_sink: RefusalSink, floor: EgressFloor | None = None,
                 lineage: EgressLineage | None = None, issuer: EgressPermitIssuer | None = None) -> None:
        if not callable(refusal_sink):
            raise ValueError("egress admission needs a signed refusal sink")
        self._store, self._sink, self._lineage, self._issuer = store, refusal_sink, lineage, issuer
        self._floor: EgressFloor = floor if floor is not None else NoDeclaredEgress()

    def _refuse(self, request: EgressRequest, code: str, reason: str) -> EgressRefused:
        try:
            record = self._sink(request, code, reason)
        except Exception:  # noqa: BLE001 - a refusal whose record failed is still a refusal, and says so
            return EgressRefused(code, reason + " (the refusal could not be recorded)", "")
        return EgressRefused(code, reason, record if isinstance(record, str) else "")

    @staticmethod
    def _malformed(request: EgressRequest) -> str | None:
        texts = (request.tenant, request.subject, request.purpose, request.endpoint_id)
        if any(type(v) is not str or not v or len(v) > 512 for v in texts):
            return "an egress request names its tenant, subject, purpose and endpoint"
        if type(request.digest) is not str or _DIGEST.fullmatch(request.digest) is None:
            return "an egress request binds the sha256 of its exact bytes"
        if type(request.byte_size) is not int or request.byte_size < 0:
            return "an egress request states its byte size"
        return None

    def admit(self, request: EgressRequest) -> Passthrough | object:
        malformed = self._malformed(request)
        if malformed is not None:
            raise self._refuse(request, "EGRESS_REQUEST_MALFORMED", malformed)
        state = scope_state(self._store, request.tenant)
        if isinstance(state, Unknown):
            raise self._refuse(request, "EGRESS_SCOPE_UNKNOWN", state.reason)
        if isinstance(state, Unregulated):
            return Passthrough(request, state.revision)
        packs = state.packs
        if self._lineage is not None:
            try:
                packs = packs | self._lineage.packs(request.tenant, request.digest)
            except Exception as exc:  # noqa: BLE001 - lineage that cannot be read cannot be shown not to add a floor
                raise self._refuse(request, "EGRESS_LINEAGE_UNKNOWN",
                                   f"the content's lineage could not be read ({type(exc).__name__})") from exc
        refusal = self._floor.refusal(packs, request)
        if refusal is not None:
            raise self._refuse(request, "EGRESS_NOT_DECLARED", refusal)
        if self._issuer is None:
            raise self._refuse(request, "EGRESS_UNMEDIATED", "no egress permit issuer is composed")
        return self._issuer.issue(request, packs)

    def send(self, admitted: Passthrough, request: EgressRequest, transport: Callable[[], T]) -> T:
        """Start the transport only while the tenant's scope lock is held and a fresh read shows it still verified
        unregulated at the admitted revision, for exactly the admitted request. Holding the lock across the start of
        the transport means no enrolment can commit between the check and the send. The transport's own result or
        exception passes through unchanged; a refusal is raised before it is called."""
        if not isinstance(admitted, Passthrough) or request != admitted.request:
            raise self._refuse(request, "EGRESS_REQUEST_CHANGED",
                               "the outgoing request is not the one that was admitted; nothing was sent")
        with ExitStack() as held:
            try:
                read = held.enter_context(self._store.guard(request.tenant))
                state = history_state(read(), request.tenant)
            except EgressRefused:
                raise
            except Exception as exc:  # noqa: BLE001 - an unobtainable lock or unreadable history must refuse
                raise self._refuse(request, "EGRESS_SCOPE_UNKNOWN",
                                   f"the scope could not be held for the send ({type(exc).__name__})") from exc
            if not isinstance(state, Unregulated) or state.revision != admitted.revision:
                raise self._refuse(request, "EGRESS_SCOPE_CHANGED",
                                   "the tenant's scope changed after admission; nothing was sent")
            return transport()


class RefusalRecorder(Protocol):
    """The part of the regulated engine a signed refusal needs (regulated_core/engine.py record_refusal)."""

    def record_refusal(self, *, assertion: Any, action: Any, ctx: Any, code: str, reason: str) -> Any: ...


def evidence_refusal_sink(engine: RefusalRecorder, *, clock_us: Callable[[], int]) -> RefusalSink:
    """The refusal sink a host composes: every refused send becomes a signed deny on the tenant's evidence chain,
    about exactly the request that was refused (its bytes, endpoint, purpose and subject), and returns the record's
    id. A failure to record propagates to the admission, which then refuses and says the refusal is unrecorded."""
    from .canonical import canonical_bytes
    from .models import Action, ActionEffect, Actor, Assertion, PolicyContext, ProducerLineage

    def sink(request: EgressRequest, code: str, reason: str) -> str:
        now = clock_us()
        subject = {"tenant": request.tenant, "subject": request.subject, "purpose": request.purpose,
                   "endpoint_id": request.endpoint_id, "digest": request.digest, "byte_size": request.byte_size}
        # A host-generated nonce per refusal: two refusals of the same request in the same clock tick, or through two
        # sink instances, are distinct records with distinct references (source review 3375).
        identity = hashlib.sha256(canonical_bytes({**subject, "code": code, "at_us": now,
                                                   "nonce": uuid.uuid4().hex})).hexdigest()
        lineage = ProducerLineage("agent-factory", "egress-admission", "none", request.digest,
                                  hashlib.sha256(code.encode()).hexdigest(),
                                  hashlib.sha256(SCOPE_SCHEMA.encode()).hexdigest())
        assertion = Assertion(assertion_id="egress:" + identity, tenant_id=request.tenant, content_type="egress:payload",
                              content_digest=request.digest, lineage=lineage,
                              payload_ref="egress://" + request.endpoint_id)
        action = Action("egress:send", ActionEffect.EXTERNAL,
                        destination=canonical_bytes(subject).decode("utf-8"))
        ctx = PolicyContext(tenant_id=request.tenant,
                            actor=Actor(actor_id=request.subject, tenant_id=request.tenant, roles=frozenset()),
                            purpose=request.purpose, correlation_id="egress:" + identity, now_us=now)
        envelope = engine.record_refusal(assertion=assertion, action=action, ctx=ctx, code=code, reason=reason)
        return str(envelope.record.record_id)

    return sink


class RecorderRefusals:
    """Record egress refusals straight onto a regulated decision recorder, under the egress admission's own policy
    reference, for a host that shares one recorder across its engines (the managed host)."""

    def __init__(self, recorder: Any) -> None:
        if not callable(getattr(recorder, "record", None)):
            raise ValueError("egress refusals need a regulated decision recorder")
        self._recorder = recorder

    def record_refusal(self, *, assertion: Any, action: Any, ctx: Any, code: str, reason: str) -> Any:
        from .models import Decision, PolicyRef

        policy = PolicyRef(vertical="core", policy_id=EGRESS_POLICY_ID, version=EGRESS_POLICY_VERSION)
        return self._recorder.record(assertion, action, ctx, policy, Decision.deny(code, reason))


class TenantBoundAdmission:
    """An admission bound to one tenant: a request naming any other tenant is refused, and the refusal is recorded on
    the BOUND tenant's chain, so a caller can never switch the tenant its admission speaks for (source review 3382)."""

    def __init__(self, admission: EgressAdmission, tenant: str) -> None:
        self._admission, self.tenant = admission, _checked_text(tenant, "tenant")

    def _check(self, request: EgressRequest) -> None:
        if request.tenant != self.tenant:
            from dataclasses import replace

            raise self._admission._refuse(replace(request, tenant=self.tenant), "EGRESS_TENANT_MISMATCH",
                                          "the request names a tenant other than the one this admission is bound to")

    def admit(self, request: EgressRequest) -> Passthrough | object:
        self._check(request)
        return self._admission.admit(request)

    def send(self, admitted: Passthrough, request: EgressRequest, transport: Callable[[], T]) -> T:
        self._check(request)
        return self._admission.send(admitted, request, transport)


def project_enrollment(store: EgressScopeStore, tenant: str) -> Callable[[str, str], None]:
    """The Project OS port a host composes into every regulated vertical's engine (ProjectEngine regulated_scope):
    it enrols the tenant for the project's pack before the project's state is created."""
    tenant = _checked_text(tenant, "tenant")

    def enrol(pack_ref: str, project_id: str) -> None:
        store.enroll(tenant, pack_ref, source="project:" + _checked_text(project_id, "project id"))

    return enrol


def inventory_tenant(store: EgressScopeStore, tenant: str, sources: tuple[Callable[[str], frozenset[str]], ...], *,
                     evidence: str) -> ScopeState:
    """The initial inventory of a tenant's existing data: every source (retained regulated projects, the tenant's
    evidence chain, its pins) names the regulated packs it finds. The inventory is recorded only after EVERY source
    answered; a source that fails records nothing. On a tenant's first inventory that leaves it Unknown, so its sends
    keep refusing; on a later refresh the existing history stands unchanged (an enrolment is never erased)."""
    if not sources:
        raise ValueError("an inventory needs at least one source of the tenant's existing data")
    found: set[str] = set()
    for source in sources:
        answer = source(tenant)
        if not isinstance(answer, frozenset) or any(type(p) is not str or not p for p in answer):
            raise ValueError("an inventory source answers with a set of pack references")
        found |= answer
    store.record_inventory(tenant, frozenset(found), evidence=evidence)
    return scope_state(store, tenant)


__all__ = ["EGRESS_POLICY_ID", "EGRESS_POLICY_VERSION", "ENROLLED", "INVENTORIED", "SCOPE_SCHEMA",
           "EgressAdmission", "EgressFloor", "EgressLineage", "EgressPermitIssuer", "EgressRefused", "EgressRequest",
           "EgressScopeStore", "InMemoryEgressScopeStore", "NoDeclaredEgress", "Passthrough", "RecorderRefusals",
           "RefusalRecorder", "RefusalSink", "Regulated", "ScopeEvent", "ScopeState", "TenantBoundAdmission",
           "Unknown", "Unregulated", "evidence_refusal_sink", "history_state", "inventory_tenant",
           "project_enrollment", "scope_state"]
