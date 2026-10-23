"""X-5: the exact approved session is admitted at the effect; any other session is refused.

Real restricted session logins in an isolated database; synthetic identities only.
The permit projection carries only the two fields admit_release reads.
"""
from types import SimpleNamespace
import time

import pytest

from assurance_reference.session_credentials import SESSION_FIELD, SessionBoundCredentials
from factory.projectos.regulated import EmissionContext
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_local_sessions import configured  # noqa: F401


def _login(sessions, principal="teacher"):
    username = principal + ".local"
    return sessions.authenticate("school-a", sessions.login("school-a", username, "fictional-password-001"))


def _credentials(sessions, identity):
    trust = TrustDirectory()
    issuer, signer = Ed25519Signer("fixture:issuer"), Ed25519Signer("fixture:credential")
    for key in (issuer, signer):
        trust.register_signer(key)
    registry = CertificateRegistry(trust, {issuer.key_id: DEMONSTRATION_CERTIFICATE})
    return SessionBoundCredentials(trust, signer, sessions, registry, sessions=sessions, authenticated=identity)


def _authorization(principal, expires_at_us):
    return SimpleNamespace(permit=SimpleNamespace(permit=SimpleNamespace(
        principal=principal, expires_at_us=expires_at_us)))


def _release(credentials, identity, clock, *, contract=None, principal=None, ttl_us=60_000_000):
    contract = {SESSION_FIELD: identity.binding()} if contract is None else contract
    context = EmissionContext(tenant=identity.tenant, actor_id=identity.principal, now_us=clock.now_us())
    authorization = _authorization(identity.principal if principal is None else principal, clock.now_us() + ttl_us)
    return credentials.admit_release(contract=contract, context=context, authorization=authorization)


def test_exact_approved_session_is_admitted_at_the_effect(configured):  # noqa: F811
    _, clock, sessions = configured
    identity = _login(sessions)
    with _release(_credentials(sessions, identity), identity, clock) as before_effect:
        before_effect()


def test_contract_bound_to_another_session_is_refused(configured):  # noqa: F811
    _, clock, sessions = configured
    approved, current = _login(sessions), _login(sessions)
    assert approved.binding() != current.binding()
    with pytest.raises(CredentialError, match="exact approved authenticated session"):
        with _release(_credentials(sessions, current), current, clock,
                      contract={SESSION_FIELD: approved.binding()}):
            pytest.fail("a different session was admitted")


def test_permit_for_another_principal_is_refused(configured):  # noqa: F811
    _, clock, sessions = configured
    identity = _login(sessions)
    with pytest.raises(CredentialError, match="exact approved authenticated session"):
        with _release(_credentials(sessions, identity), identity, clock, principal="someone-else"):
            pytest.fail("a permit for another principal was admitted")


def test_other_users_session_is_refused(configured):  # noqa: F811
    _, clock, sessions = configured
    sessions.provision_identity("school-a", "other", "other.local", "fictional-password-001")
    approved, other = _login(sessions), _login(sessions, "other")
    with pytest.raises(CredentialError, match="exact approved authenticated session"):
        with _release(_credentials(sessions, other), other, clock,
                      contract={SESSION_FIELD: approved.binding()}):
            pytest.fail("another user's session was admitted")


def test_session_past_its_effect_deadline_is_refused_before_the_effect(configured):  # noqa: F811
    _, clock, sessions = configured
    identity = _login(sessions)
    with _release(_credentials(sessions, identity), identity, clock, ttl_us=400_000) as before_effect:
        time.sleep(0.6)
        with pytest.raises(EmissionError):
            before_effect()


def test_revoked_session_is_refused_at_admission(configured):  # noqa: F811
    _, clock, sessions = configured
    identity = _login(sessions)
    credentials = _credentials(sessions, identity)
    sessions.revoke(identity)
    with pytest.raises(CredentialError):
        with _release(credentials, identity, clock):
            pytest.fail("a revoked session was admitted")
