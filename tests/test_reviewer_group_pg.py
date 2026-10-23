"""Intact local group/session locks using ordinary concurrent operations."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import fields
import os
from threading import Barrier, Event

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.session_credentials import SessionRefused
from regulated_core.clock_pg import DbClock


@pytest.fixture
def group():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
        sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
        identities = []
        for principal in ("reviewer-b", "reviewer-a", "requester"):
            sessions.provision_identity("fixture-school", principal, principal + ".local", "fictional-password-001")
            token = sessions.login("fixture-school", principal + ".local", "fictional-password-001")
            identities.append(sessions.authenticate("fixture-school", token))
        yield sessions, tuple(identities), clock
    finally:
        for field in fields(roles):
            value = getattr(roles, field.name)
            if isinstance(value, LocalPool):
                value.close()


def test_group_then_requester_admission_within_three_connection_bound(group):
    sessions, identities, clock = group
    with sessions.admit_many(identities[:2], not_after_us=clock.now_us() + 30_000_000) as reviewers:
        with sessions.admit(identities[2]) as requester:
            reviewers()
            requester()
            reviewers()
    with pytest.raises(SessionRefused, match="ended"):
        reviewers()


def test_group_holds_reviewer_revocation_until_requester_operation_finishes(group):
    sessions, identities, clock = group
    entered = Event()
    def revoke():
        entered.set()
        sessions.revoke(identities[0])
    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.admit_many(identities[:2], not_after_us=clock.now_us() + 30_000_000) as reviewers:
            with sessions.admit(identities[2]) as requester:
                pending = executor.submit(revoke)
                assert entered.wait(2)
                with pytest.raises(TimeoutError):
                    pending.result(timeout=0.2)
                reviewers()
                requester()
                reviewers()
        pending.result(timeout=8)
    with pytest.raises(SessionRefused, match="changed"):
        with sessions.admit_many(identities[:2], not_after_us=clock.now_us() + 30_000_000):
            pytest.fail("revoked reviewer was admitted")


def test_overlapping_groups_in_reverse_input_order_complete(group):
    sessions, identities, clock = group
    meet = Barrier(2)
    deadline = clock.now_us() + 30_000_000
    def observe(order):
        with sessions.admit_many(order, not_after_us=deadline) as current:
            meet.wait(timeout=4)
            current()
            return True
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(observe, identities[:2])
        second = executor.submit(observe, tuple(reversed(identities[:2])))
        assert first.result(timeout=8)
        assert second.result(timeout=8)
