"""Joining a held admission never creates authority or extends a deadline."""

from contextlib import contextmanager
from dataclasses import replace
from threading import Thread
from types import SimpleNamespace

import pytest

from assurance_reference.session_admission_scope import SessionAdmissionScope
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable


class Authority:
    def __init__(self):
        self.now, self.calls, self.revoked = 10, 0, False
        self.clock = SimpleNamespace(now_us=lambda: self.now)

    @contextmanager
    def admit(self, identity, *, not_after_us=None):
        self.calls += 1
        deadline = min(identity.expires_at_us, not_after_us or identity.expires_at_us)
        active = True
        def current():
            if not active or self.revoked or self.now >= deadline:
                raise SessionRefused("underlying session refused")
        try:
            current()
            yield current
        finally:
            active = False


@pytest.fixture
def scene():
    source = Authority()
    identity = AuthenticatedSession("school", "teacher", "teacher.local", "fictional-session", 100)
    return source, identity, SessionAdmissionScope(source, identity)


def test_nested_checks_share_real_admission_and_expire_with_their_scope(scene):
    source, identity, scoped = scene
    with scoped.admit(identity) as outer:
        with scoped.admit(identity) as inner:
            outer()
            inner()
            assert source.calls == 1
        with pytest.raises(SessionRefused, match="scope has ended"):
            inner()
        outer()
    with pytest.raises(SessionRefused):
        outer()
    with scoped.admit(identity):
        assert source.calls == 2


@pytest.mark.parametrize("outer_deadline,inner_deadline,expiry", [(30, 80, 30), (80, 30, 30)])
def test_nested_and_parent_deadlines_are_both_enforced(scene, outer_deadline, inner_deadline, expiry):
    source, identity, scoped = scene
    with scoped.admit(identity, not_after_us=outer_deadline):
        with scoped.admit(identity, not_after_us=inner_deadline):
            with scoped.admit(identity) as check:
                source.now = expiry
                with pytest.raises(SessionRefused):
                    check()
    assert source.calls == 1


def test_different_session_is_never_joined_and_revocation_is_still_checked(scene):
    source, identity, scoped = scene
    with scoped.admit(identity) as check:
        with pytest.raises(SessionRefused, match="different"):
            with scoped.admit(replace(identity, reference="other")):
                pytest.fail("must refuse")
        source.revoked = True
        with pytest.raises(SessionRefused):
            check()
    assert source.calls == 1


def test_parallel_thread_acquires_its_own_real_admission(scene):
    source, identity, scoped = scene
    completed = []
    def other():
        with scoped.admit(identity) as current:
            current()
            completed.append(True)
    with scoped.admit(identity):
        worker = Thread(target=other)
        worker.start()
        worker.join(2)
        assert not worker.is_alive() and completed == [True] and source.calls == 2


def test_failed_nested_deadline_clock_does_not_grant_authority(scene):
    source, identity, scoped = scene
    def unavailable():
        raise RuntimeError("fixture clock unavailable")
    with scoped.admit(identity):
        source.clock.now_us = unavailable
        with pytest.raises(SessionUnavailable):
            with scoped.admit(identity, not_after_us=30):
                pytest.fail("must refuse")
