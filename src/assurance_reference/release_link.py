"""Bounded release-link admission over host-owned goal and review ports.

This service publishes a task and its review link atomically through the goal
store. It neither signs, issues authority nor performs an effect. A concrete
host must implement the documented transaction contract and compose the existing
signed-review verifier and receiving gate. These references alone grant nothing.
"""
from dataclasses import dataclass
from typing import Callable, Protocol

from assurance_reference.session_credentials import AuthenticatedSession
from factory.projectos.regulated import ReleaseAuthorityBinding


class ReleaseLinkRefused(ValueError):
    """A known mismatch or expired authority prevents task/link publication."""


@dataclass(frozen=True)
class ReleaseLinkRequest:
    goal_id: str
    task_id: str
    vertical: str
    project_id: str
    review_id: str
    destination: str

    def __post_init__(self):
        for value in vars(self).values():
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ReleaseLinkRefused("release link requires bounded explicit references")


@dataclass(frozen=True)
class GoalReleaseBinding:
    tenant: str
    goal_id: str
    owner: str
    envelope_digest: str
    revision_digest: str
    expires_at_us: int
    vertical: str
    project_id: str
    project_instance: str
    executor: str


@dataclass(frozen=True)
class VerifiedReleaseBinding:
    """Projection from the host's existing full signed-review verification.

    Never construct this from request fields or an unverified stored dictionary.
    Inside the goal transaction, the host compares current contract and inherited
    authority against this verified projection without opening a signing path.
    """
    tenant: str
    executor: str
    vertical: str
    project_id: str
    project_instance: str
    review_id: str
    destination: str
    action_id: str
    nonce: str
    decision_hash: str
    contract_digest: str
    expires_at_us: int
    authority: ReleaseAuthorityBinding


@dataclass(frozen=True)
class ReleaseLink:
    request: ReleaseLinkRequest
    goal: GoalReleaseBinding
    review: VerifiedReleaseBinding


class GoalReleaseStore(Protocol):
    """Trusted durable goal transaction, not a request-supplied callback.

    read returns the current goal and owned project binding. transact locks the
    same authoritative goal and ownership rows, rereads them after locking, then
    calls mutation with (locked goal, existing exact task/link or None, connection).
    It publishes the task AND link in that one transaction, only if mutation
    succeeds. It rejects occupied task identifiers with different semantics.
    The connection belongs to this transaction; nested ports must not borrow a
    second connection or release its locks. Exceptions roll back publication.
    """
    def read(self, tenant: str, request: ReleaseLinkRequest) -> GoalReleaseBinding: ...

    def transact(self, tenant: str, request: ReleaseLinkRequest, mutation: Callable) -> ReleaseLink: ...


class ReleaseLinkReviews(Protocol):
    """Read-only adapters to existing review verification and current authority."""

    def verify(self, goal: GoalReleaseBinding, request: ReleaseLinkRequest) -> VerifiedReleaseBinding: ...

    def current_on(self, connection, goal: GoalReleaseBinding,
                   request: ReleaseLinkRequest, verified: VerifiedReleaseBinding) -> VerifiedReleaseBinding: ...


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class ReleaseLinkAdmission:
    """One authenticated caller, held current through atomic goal publication."""

    def __init__(self, *, authenticated, sessions, goals: GoalReleaseStore,
                 reviews: ReleaseLinkReviews, authorize):
        if not isinstance(authenticated, AuthenticatedSession):
            raise ValueError("release linking requires the host-authenticated session")
        for owner, names in ((sessions, ("admit",)), (goals, ("read", "transact")),
                             (reviews, ("verify", "current_on"))):
            if any(not callable(getattr(owner, name, None)) for name in names):
                raise ValueError("release linking requires complete host ports")
        if not callable(getattr(getattr(sessions, "clock", None), "now_us", None)) or not callable(authorize):
            raise ValueError("release linking requires current clock and authority")
        self.identity, self.sessions = authenticated, sessions
        self.goals, self.reviews, self.authorize = goals, reviews, authorize

    def _now(self):
        now = self.sessions.clock.now_us()
        if type(now) is not int or now <= 0:
            raise ReleaseLinkRefused("release-link time is unavailable")
        return now

    def _goal(self, goal, request):
        if (not isinstance(goal, GoalReleaseBinding)
                or (goal.tenant, goal.owner, goal.goal_id, goal.vertical, goal.project_id) !=
                (self.identity.tenant, self.identity.principal, request.goal_id,
                 request.vertical, request.project_id)
                or not _text(goal.project_instance) or not _text(goal.executor)
                or not _digest(goal.envelope_digest) or not _digest(goal.revision_digest)
                or type(goal.expires_at_us) is not int or goal.expires_at_us <= self._now()):
            raise ReleaseLinkRefused("current goal owner, envelope and project binding required")

    def _review(self, review, goal, request):
        if (not isinstance(review, VerifiedReleaseBinding)
                or (review.tenant, review.executor, review.vertical, review.project_id,
                    review.project_instance, review.review_id, review.destination) !=
                (goal.tenant, goal.executor, request.vertical, request.project_id,
                 goal.project_instance, request.review_id, request.destination)
                or not _text(review.action_id) or not _text(review.nonce)
                or not _digest(review.decision_hash) or not _digest(review.contract_digest)
                or not isinstance(review.authority, ReleaseAuthorityBinding)
                or type(review.expires_at_us) is not int or review.expires_at_us <= self._now()):
            raise ReleaseLinkRefused("current executor signed review and inherited authority required")

    def admit(self, request):
        if not isinstance(request, ReleaseLinkRequest):
            raise ReleaseLinkRefused("typed release references required")
        with self.sessions.admit(self.identity) as session_current:
            session_current()
            self.authorize(self.identity, request, connection=None)
            goal = self.goals.read(self.identity.tenant, request)
            self._goal(goal, request)
            verified = self.reviews.verify(goal, request)
            self._review(verified, goal, request)
            self.authorize(self.identity, request, connection=None)
            session_current()
            # Recheck time after potentially blocking authority reads.
            self._goal(goal, request)
            self._review(verified, goal, request)

            def publish(locked, existing, connection):
                session_current()
                self.authorize(self.identity, request, connection=connection)
                self._goal(locked, request)
                if locked != goal:
                    raise ReleaseLinkRefused("goal or project changed before publication")
                current = self.reviews.current_on(connection, locked, request, verified)
                self._review(current, locked, request)
                if current != verified:
                    raise ReleaseLinkRefused("review or inherited authority changed before publication")
                self.authorize(self.identity, request, connection=connection)
                session_current()
                self._goal(locked, request)
                self._review(current, locked, request)
                proposed = ReleaseLink(request, locked, verified)
                if existing is not None and existing != proposed:
                    raise ReleaseLinkRefused("task already binds a different release link")
                return proposed

            result = self.goals.transact(self.identity.tenant, request, publish)
            if result != ReleaseLink(request, goal, verified):
                raise RuntimeError("goal store returned an unexpected link; reconcile publication")
            # A close failure remains an exception with unknown publication.
            return result
