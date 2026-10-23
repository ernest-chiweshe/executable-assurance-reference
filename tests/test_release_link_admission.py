"""Synthetic host-port contracts, not a durable store or signed-review integration."""
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused
from factory.projectos.regulated import ReleaseAuthorityBinding
from assurance_reference.release_link import (
    GoalReleaseBinding, ReleaseLinkAdmission, ReleaseLinkRefused,
    ReleaseLinkRequest, VerifiedReleaseBinding,
)


class Sessions:
    def __init__(self):
        self.now, self.depth, self.revoked = 10, 0, False
        self.clock = SimpleNamespace(now_us=lambda: self.now)

    @contextmanager
    def admit(self, identity):
        self.depth += 1
        def current():
            if self.depth != 1 or self.revoked or self.now >= identity.expires_at_us:
                raise SessionRefused("synthetic session is no longer current")
        try:
            current()
            yield current
        finally:
            self.depth -= 1


@pytest.fixture
def scene():
    sessions = Sessions()
    request = ReleaseLinkRequest("goal", "task", "education", "project", "review", "target")
    goal = GoalReleaseBinding("tenant", "goal", "owner", "a"*64, "b"*64, 100,
                              "education", "project", "instance", "executor")
    review = VerifiedReleaseBinding("tenant", "executor", "education", "project", "instance",
        "review", "target", "action", "nonce", "c"*64, "d"*64, 80,
        ReleaseAuthorityBinding("e"*64, "f"*64, "1"*64, "root-mission"))
    s = SimpleNamespace(sessions=sessions, request=request, goal=goal, review=review,
        locked=None, existing=None, publications=0, verifications=0, authorization=[],
        before_transaction=lambda: None, on_current=lambda: None, on_authorize=lambda: None)
    connection = object()
    def authorize(identity, request, *, connection):
        assert sessions.depth == 1
        s.authorization.append(connection)
        s.on_authorize()
    class Goals:
        def read(self, tenant, request):
            assert tenant == "tenant" and sessions.depth == 1
            return s.goal
        def transact(self, tenant, request, mutation):
            s.before_transaction()
            result = mutation(s.locked or s.goal, s.existing, connection)
            if result != s.existing:
                s.publications += 1
            s.existing = result
            return result
    class Reviews:
        def verify(self, goal, request):
            s.verifications += 1
            return s.review
        def current_on(self, conn, goal, request, verified):
            assert conn is connection
            s.on_current()
            return s.review
    s.service = ReleaseLinkAdmission(authenticated=AuthenticatedSession(
        "tenant", "owner", "owner.local", "session", 200), sessions=sessions,
        goals=Goals(), reviews=Reviews(), authorize=authorize)
    return s


def test_lawful_atomic_link_is_exact_and_repeat_is_idempotent(scene):
    s = scene
    result = s.service.admit(s.request)
    assert result.request == s.request and result.goal == s.goal and result.review == s.review
    assert s.publications == 1 and s.verifications == 1
    assert len(s.authorization) == 4
    assert s.authorization[:2] == [None, None]
    assert all(x is not None for x in s.authorization[2:])
    assert s.service.admit(s.request) == result
    assert s.publications == 1 and s.verifications == 2
    assert s.sessions.depth == 0


@pytest.mark.parametrize("change", [
    {"owner": "someone-else"}, {"tenant": "other"}, {"project_id": "other"},
    {"expires_at_us": 10}, {"expires_at_us": True}, {"executor": ""},
])
def test_invalid_current_goal_refuses_before_publication(scene, change):
    s = scene
    s.goal = replace(s.goal, **change)
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 0 and s.existing is None


@pytest.mark.parametrize("change", [
    {"executor": "owner"}, {"review_id": "other"}, {"expires_at_us": 10},
    {"authority": None}, {"destination": "other"}, {"project_instance": "replacement"},
])
def test_missing_or_inapplicable_review_refuses_before_publication(scene, change):
    s = scene
    s.review = replace(s.review, **change)
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 0 and s.existing is None


def test_missing_review_refuses(scene):
    scene.review = None
    with pytest.raises(ReleaseLinkRefused):
        scene.service.admit(scene.request)
    assert scene.publications == 0


@pytest.mark.parametrize("field,value", [
    ("owner", "new-owner"), ("revision_digest", "2"*64),
    ("project_instance", "new-instance"), ("envelope_digest", "3"*64),
])
def test_goal_rechecked_inside_transaction(scene, field, value):
    s = scene
    s.locked = replace(s.goal, **{field: value})
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 0


def test_review_changed_during_reads_refuses(scene):
    s = scene
    s.on_current = lambda: setattr(s, "review", replace(s.review, contract_digest="4"*64))
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 0


@pytest.mark.parametrize("when", ["transaction", "after_current"])
def test_review_expiry_during_reads_refuses(scene, when):
    s = scene
    def expire():
        s.sessions.now = 80
    if when == "transaction":
        s.before_transaction = expire
    else:
        s.on_current = expire
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 0


def test_session_revocation_during_current_read_refuses(scene):
    s = scene
    s.on_current = lambda: setattr(s.sessions, "revoked", True)
    with pytest.raises(SessionRefused):
        s.service.admit(s.request)
    assert s.publications == 0 and s.sessions.depth == 0


def test_authority_failure_rolls_back_publication(scene):
    s = scene
    def unavailable():
        if len(s.authorization) == 4:
            raise RuntimeError("synthetic authority unavailable")
    s.on_authorize = unavailable
    with pytest.raises(RuntimeError, match="unavailable"):
        s.service.admit(s.request)
    assert s.publications == 0 and s.existing is None


def test_existing_task_with_other_semantics_refuses(scene):
    s = scene
    first = s.service.admit(s.request)
    s.existing = replace(first, request=replace(s.request, destination="other"))
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.publications == 1


def test_rolled_back_store_call_can_retry_exactly(scene):
    s = scene
    def fail():
        raise RuntimeError("synthetic transaction unavailable")
    s.before_transaction = fail
    with pytest.raises(RuntimeError):
        s.service.admit(s.request)
    assert s.existing is None
    s.before_transaction = lambda: None
    assert s.service.admit(s.request) == s.existing and s.publications == 1
