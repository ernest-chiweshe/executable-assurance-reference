"""Bounded host capture around an existing material review route.

Presentation means generated material, not proof of delivery or human reading.
Grant and journal transactions are separate; ambiguous outcomes require explicit
reconciliation. This adapter never retries a grant or invokes a release.
"""

from threading import Lock
import uuid

from assurance_reference.approval_observations import ApprovalObservations, SCHEMA
from assurance_reference.review_material import MaterialReview
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from regulated_core.approval_evidence import ReviewError
from regulated_core.clock import read_clock


class CaptureUncertain(RuntimeError):
    """Host must reconcile; a grant or observation may already be retained."""

    def __init__(self, *, phase, grant_returned, grant_result=None, event=None, signature=None):
        super().__init__("review capture requires reconciliation: " + phase)
        self.phase = phase
        self.grant_returned = grant_returned
        self.grant_result = grant_result
        self.event, self.signature = event, signature


class ObservedMaterialReview:
    """One host-authenticated session and bounded, single-use presentation tickets.

    Hosts choose the material route (including its assignment/screening controls),
    clock, observer signer and synthetic label. Requests cannot replace them.
    Tickets are process-local and lost on restart. Protect the host ports and route
    all intended UI actions here; direct underlying gate calls remain available.
    """

    def __init__(self, route, *, observations, signer, clock, sessions, authenticated,
                 synthetic, maximum_pending=64, ticket_lifetime_us=300_000_000):
        if (not isinstance(route, MaterialReview)
                or not isinstance(observations, ApprovalObservations)
                or not isinstance(authenticated, AuthenticatedSession)
                or not callable(getattr(signer, "sign", None))
                or not callable(getattr(sessions, "admit", None))
                or type(synthetic) is not bool
                or type(maximum_pending) is not int or not 1 <= maximum_pending <= 256
                or type(ticket_lifetime_us) is not int or not 1 <= ticket_lifetime_us <= 900_000_000):
            raise ValueError("explicit host capture policy and guarded ports required")
        read_clock(clock)
        self._route, self._observations, self._signer = route, observations, signer
        self._clock, self._sessions, self._identity = clock, sessions, authenticated
        self._synthetic, self._maximum, self._lifetime = synthetic, maximum_pending, ticket_lifetime_us
        self._pending, self._lock = {}, Lock()

    def _context(self, context):
        if ((context.tenant, context.actor_id) != (self._identity.tenant, self._identity.principal)
                or context.actor_roles or context.is_producer):
            raise SessionRefused("capture requires the exact authenticated human context")

    def present(self, **request):
        self._context(request["context"])
        with self._sessions.admit(self._identity) as current:
            current()
            view = self._route.view(**request)
            reading = read_clock(self._clock)
            current()
        bound = view["bound"]
        event = {"schema": SCHEMA, "tenant": bound["tenant"], "reviewer": bound["reviewer"],
            "review_id": bound["review_id"], "decision_sha256": bound["decision_record_hash"],
            "display_sha256": view["display_sha256"], "outcome": "approved",
            "clock_domain": reading.domain, "presented_us": reading.now_us,
            "decided_us": reading.now_us, "synthetic": self._synthetic}
        self._observations.validate_signed(event, self._signer.sign(event))
        token = uuid.uuid4().hex
        with self._lock:
            # Bounded capacity; expired tickets can be reclaimed without extending
            # any ticket's validity. A changed clock domain invalidates old tickets.
            self._pending = {k: v for k, v in self._pending.items()
                if v["clock_domain"] == reading.domain
                and 0 <= reading.now_us - v["presented_us"] < self._lifetime}
            if len(self._pending) >= self._maximum:
                raise ReviewError("pending presentation capacity reached")
            self._pending[token] = event
        return {"view": view, "presentation_ticket": token}

    def finish(self, *, presentation_ticket, displayed_sha256, outcome, role=None, **request):
        """Capture an explicit human choice; enforcement errors are not refusals.

        'refused' and 'escalated' record a choice only: neither revokes an earlier
        grant nor delivers an escalation. An original grant exception is UNKNOWN,
        never a fabricated refusal. A consumed ticket is never automatically retried.
        """
        if outcome not in ("approved", "refused", "escalated"):
            raise ValueError("explicit review outcome required")
        if type(presentation_ticket) is not str or len(presentation_ticket) != 32:
            raise ReviewError("host presentation ticket required")
        self._context(request["context"])
        with self._lock:
            event = self._pending.pop(presentation_ticket, None)
        if event is None:
            raise ReviewError("presentation ticket absent, consumed or lost on restart")
        grant_result = None
        attempted = returned = False
        signature = None
        phase = "pre-grant"
        try:
            with self._sessions.admit(self._identity) as current:
                current()
                reading = read_clock(self._clock)
                if (reading.domain != event["clock_domain"]
                        or not 0 <= reading.now_us - event["presented_us"] < self._lifetime):
                    raise ReviewError("presentation ticket expired or clock differs")
                view = self._route.view(**request)
                if displayed_sha256 != event["display_sha256"] or view["display_sha256"] != displayed_sha256:
                    raise ReviewError("renewed exact material presentation required")
                event = {**event, "outcome": outcome, "decided_us": reading.now_us}
                self._observations.validate_signed(event, self._signer.sign(event))
                current()
                if outcome == "approved":
                    phase, attempted = "grant-outcome-unknown", True
                    grant_result = self._route.grant(**request, role=role, displayed_sha256=displayed_sha256)
                    returned = True
                    if (type(grant_result) is not dict or grant_result.get("review_id") != event["review_id"]
                            or grant_result.get("decision_record_hash") != event["decision_sha256"]
                            or self._identity.principal not in grant_result.get("approver_ids", ())):
                        raise ReviewError("grant return does not confirm the captured reviewer")
                phase = "observation-retention-unconfirmed"
                # Timing describes choice submission before the grant call. It is
                # not grant latency, authoritative effect time or human reading time.
                signature = self._signer.sign(event)
                reference = self._observations.record(event, signature)
                phase = "post-retention-session-unconfirmed"
                current()
            return {"grant": grant_result, "observation_id": reference, "outcome": outcome}
        except Exception as exc:
            if attempted or phase != "pre-grant":
                # For grant errors there is no signed approved observation to
                # replay: reconcile original authority first. For later errors,
                # the exact event can be reconciled without granting again.
                raise CaptureUncertain(phase=phase, grant_returned=returned, grant_result=grant_result,
                    event=event if phase != "grant-outcome-unknown" else None,
                    signature=signature if phase != "grant-outcome-unknown" else None) from exc
            raise
