"""Synthetic authority observations; no database or released application artifact."""
from contextlib import contextmanager
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from assurance_reference.local_sessions import LocalSessions
from assurance_reference.reviewer_session_admission import admit_reviewer_sessions
from assurance_reference.session_credentials import AuthenticatedSession, SessionRefused, SessionUnavailable
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.reviewer_sessions import ReviewerSessionBinding, issue_session_credential
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import ReleaseAdmissionUnavailable


class ObservedReader:
    def __init__(self, identities):
        self.accounts = {(x.tenant, x.principal): (x.username, True) for x in identities}
        self.sessions = {(x.tenant, x.reference): (x.principal, x.expires_at_us, False) for x in identities}
        self.connections = self.depth = 0
        self.read_order = []

    @contextmanager
    def connection(self):
        self.connections += 1
        self.depth += 1
        try:
            yield self
        finally:
            self.depth -= 1

    @contextmanager
    def transaction(self):
        yield

    def execute(self, query, args=None):
        if "set_config" in query or query.startswith("SET LOCAL "):
            return SimpleNamespace(fetchone=lambda: None)
        if "reference_identities_v1" in query:
            self.read_order.append(("identity", args))
            return SimpleNamespace(fetchone=lambda: self.accounts.get(args))
        if "reference_sessions_v1" in query:
            self.read_order.append(("session", args))
            return SimpleNamespace(fetchone=lambda: self.sessions.get(args))
        raise AssertionError("unexpected operation")


@pytest.fixture
def group():
    identities = tuple(AuthenticatedSession("school", f"teacher-{i:02}", f"teacher{i}.local",
                                            f"retained-{i:02}", 700) for i in range(12))
    reader = ObservedReader(identities)
    clock = SimpleNamespace(now=100)
    clock.now_us = lambda: clock.now
    source = LocalSessions(reader=reader, issuer=None, clock=clock)
    return identities, reader, clock, source


def test_group_uses_one_connection_and_expires_after_context(group):
    identities, reader, _, source = group
    with source.admit_many(tuple(reversed(identities)), not_after_us=600) as current:
        current()
        assert reader.connections == 1 and reader.depth == 1
        assert [kind for kind, _ in reader.read_order] == ["identity"] * 12 + ["session"] * 12
        assert reader.read_order[:12] == sorted(reader.read_order[:12])
    assert reader.depth == 0
    with pytest.raises(SessionRefused, match="ended"):
        current()


@pytest.mark.parametrize("deadline,now", [(600, 600), (900, 700)])
def test_group_checks_earliest_session_or_effect_deadline(group, deadline, now):
    identities, _, clock, source = group
    with source.admit_many(identities, not_after_us=deadline) as current:
        clock.now = now
        with pytest.raises(SessionRefused, match="expired"):
            current()


def test_revoked_observation_refuses_entire_group_and_releases_connection(group):
    identities, reader, _, source = group
    last = identities[-1]
    reader.sessions[(last.tenant, last.reference)] = (last.principal, last.expires_at_us, True)
    with pytest.raises(SessionRefused, match="authority changed"):
        with source.admit_many(identities, not_after_us=600):
            pytest.fail("group must not be admitted")
    assert reader.depth == 0 and reader.connections == 1


@pytest.mark.parametrize("now", [None, True, 0])
def test_invalid_authority_time_is_unavailable(group, now):
    identities, _, clock, source = group
    clock.now = now
    with pytest.raises(SessionUnavailable):
        with source.admit_many(identities, not_after_us=600):
            pytest.fail("invalid clock must refuse")


@pytest.fixture
def receipts(group):
    identities, _, _, source = group
    signer = Ed25519Signer("fictional-reviewer-signer")
    trust = TrustDirectory()
    trust.register_signer(signer)
    signed = tuple(issue_session_credential(signer,
        reviewer_session=ReviewerSessionBinding(**asdict(x)), subject_id=x.principal,
        tenant=x.tenant, role="teacher", licence_type="fixture", jurisdiction="ZA",
        status="active", expires_at_us=800, verified_at_us=100, provider="fixture") for x in identities)
    return signed, source, trust, signer


def test_signed_receipts_hold_all_current_sessions_through_callback(group, receipts):
    _, reader, clock, _ = group
    signed, source, trust, signer = receipts
    with admit_reviewer_sessions(receipts=signed, tenant="school", not_after_us=600,
                                sessions=source, trust=trust, signer_id=signer.key_id) as check:
        check()
        assert reader.depth == 1
        clock.now = 600
        with pytest.raises(EmissionError, match="expired"):
            check()
    assert reader.depth == 0


def test_observed_clock_unavailability_has_unknown_effect_class(group, receipts):
    _, _, clock, _ = group
    signed, source, trust, signer = receipts
    with admit_reviewer_sessions(receipts=signed, tenant="school", not_after_us=600,
                                sessions=source, trust=trust, signer_id=signer.key_id) as check:
        clock.now = None
        with pytest.raises(ReleaseAdmissionUnavailable):
            check()


def test_missing_group_authority_refuses_before_admission(receipts):
    signed, _, trust, signer = receipts
    with pytest.raises(CredentialError):
        with admit_reviewer_sessions(receipts=signed, tenant="school", not_after_us=600,
                sessions=SimpleNamespace(), trust=trust, signer_id=signer.key_id):
            pytest.fail("missing authority")


def test_external_trust_is_required_before_opening_group(group, receipts):
    _, reader, _, _ = group
    signed, source, _, signer = receipts
    with pytest.raises(CredentialError):
        with admit_reviewer_sessions(receipts=signed, tenant="school", not_after_us=600,
                sessions=source, trust=TrustDirectory(), signer_id=signer.key_id):
            pytest.fail("untrusted observation")
    assert reader.connections == 0

