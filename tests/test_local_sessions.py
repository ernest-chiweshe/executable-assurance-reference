"""Real restricted-logins session contracts in an explicitly isolated database."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import os
from threading import Event

import psycopg
import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.session_credentials import SessionBoundCredentials, SessionRefused
from factory.projectos.regulated import EmissionContext
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE, issue_certificate
from regulated_core.clock_pg import DbClock
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Ed25519Signer, TrustDirectory


@pytest.fixture
def configured():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    sessions.provision_identity("school-a", "teacher", "teacher.local", "fictional-password-001")
    return roles, clock, sessions


def test_login_restart_hashed_token_and_tenant_boundaries(configured):
    roles, clock, sessions = configured
    with pytest.raises(SessionRefused):
        sessions.login("school-a", "teacher.local", "incorrect-password")
    token = sessions.login("school-a", "teacher.local", "fictional-password-001")
    restarted = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    identity = restarted.authenticate("school-a", token)
    assert identity.reference == hashlib.sha256(token.encode()).hexdigest()
    with pytest.raises(SessionRefused):
        restarted.authenticate("school-b", token)
    with roles.session_reader.connection() as conn, conn.transaction():
        assert conn.execute("SELECT count(*) FROM reference_sessions_v1").fetchone() == (0,)
        conn.execute("SELECT set_config('app.tenant','school-a',true)")
        assert conn.execute("SELECT reference FROM reference_sessions_v1").fetchone() == (identity.reference,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT password_hash FROM reference_identities_v1")
    with roles.receiver.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM reference_identities_v1")


def test_admission_exact_identity_deadline_and_context_lifetime(configured):
    _, clock, sessions = configured
    token = sessions.login("school-a", "teacher.local", "fictional-password-001")
    identity = sessions.authenticate("school-a", token)
    with pytest.raises(SessionRefused):
        with sessions.admit(replace(identity, principal="other")):
            pytest.fail("wrong principal admitted")
    with pytest.raises(SessionRefused, match="expired"):
        with sessions.admit(identity, not_after_us=clock.now_us() - 1):
            pytest.fail("past deadline admitted")
    with sessions.admit(identity) as current:
        current()
    with pytest.raises(SessionRefused, match="ended"):
        current()


def test_revocation_serializes_with_admitted_operation(configured):
    _, _, sessions = configured
    token = sessions.login("school-a", "teacher.local", "fictional-password-001")
    identity = sessions.authenticate("school-a", token)
    attempted = Event()

    def revoke():
        attempted.set()
        sessions.revoke(identity)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.admit(identity) as current:
            pending = executor.submit(revoke)
            assert attempted.wait(2)
            current()
            assert not pending.done()
        pending.result(timeout=8)
    with pytest.raises(SessionRefused):
        with sessions.admit(identity):
            pytest.fail("revoked session admitted")


def test_authenticated_certificate_review_and_read_only_revalidation(configured):
    _, clock, sessions = configured
    identity = sessions.authenticate("school-a", sessions.login(
        "school-a", "teacher.local", "fictional-password-001"))
    trust = TrustDirectory()
    issuer, signer = Ed25519Signer("fixture:issuer"), Ed25519Signer("fixture:credential")
    for key in (issuer, signer):
        trust.register_signer(key)
    registry = CertificateRegistry(trust, {issuer.key_id: DEMONSTRATION_CERTIFICATE})
    registry.present(issue_certificate(issuer, subject_id="teacher", role="teacher",
                                       jurisdiction="ZA", expires_at_us=clock.now_us()+60_000_000))
    credentials = SessionBoundCredentials(trust, signer, sessions, registry,
                                          sessions=sessions, authenticated=identity)
    context = EmissionContext(tenant="school-a", actor_id="teacher", now_us=clock.now_us())
    receipt = credentials.verify_review("teacher", "school-a", "teacher", contract={}, context=context)
    credentials.validate_review(receipt, contract={}, context=context)
    assert not credentials.provider_backed
    with pytest.raises(CredentialError, match="self-supplied"):
        credentials.verify_review("teacher", "school-a", "teacher", contract={},
                                  context=replace(context, actor_roles=("teacher",)))
    registry.present(issue_certificate(issuer, subject_id="teacher", role="teacher",
                                       jurisdiction="ZW", expires_at_us=clock.now_us()+60_000_000))
    with pytest.raises(CredentialError, match="changed"):
        credentials.validate_review(receipt, contract={}, context=context)
