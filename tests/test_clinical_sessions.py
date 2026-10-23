"""Real restricted-session admission through the pinned clinical effect adapter."""

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from assurance_reference.clinical_sessions import RetainedClinicalSessions
from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_sessions import LocalSessions
from factory.health_ui.identity import SessionAdmissionRefused
from factory.health_ui.session_release import ClinicalSessionCredentials, SESSION_FIELD
from factory.projectos.regulated import EmissionContext
from regulated_core import Ed25519Signer, TrustDirectory
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE
from regulated_core.clock_pg import DbClock
from regulated_core.identity_provider import CredentialError

from test_local_roles import roles  # noqa: F401


@pytest.fixture
def clinical_session(roles):  # noqa: F811 - imported pytest fixture
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    tenant = "clinic-" + uuid4().hex
    sessions.provision_identity(tenant, "fixture-user", "fixture.user", "fictional-password-001")
    authenticated = sessions.authenticate(tenant, sessions.login(
        tenant, "fixture.user", "fictional-password-001"))
    bridge = RetainedClinicalSessions(sessions, authenticated)
    trust, signer = TrustDirectory(), Ed25519Signer("clinical-session-fixture")
    trust.register_signer(signer)
    # No certificates are presented: no membership/licence or review is granted
    # by these admission contracts. Only the original receiving port is used.
    credentials = ClinicalSessionCredentials(trust, signer, sessions,
        CertificateRegistry(trust, {signer.key_id: DEMONSTRATION_CERTIFICATE}), sessions=bridge)
    context = EmissionContext(tenant=tenant, actor_id="fixture-user", project_id="fixture-case",
        vertical_name="health", action_id="release", nonce="clinical-session-fixture")
    authorization = SimpleNamespace(permit=SimpleNamespace(permit=SimpleNamespace(
        principal=authenticated.principal, expires_at_us=clock.now_us() + 30_000_000)))
    return SimpleNamespace(clock=clock, sessions=sessions, authenticated=authenticated,
        bridge=bridge, credentials=credentials, context=context, authorization=authorization)


def test_original_clinical_port_holds_admission_and_rejects_reuse_after_exit(clinical_session):
    case = clinical_session
    with case.credentials.admit_release(contract={SESSION_FIELD: case.bridge.binding()},
            context=case.context, authorization=case.authorization) as check:
        check()
    from regulated_core.permit import EmissionError
    with pytest.raises(EmissionError, match="ended"):
        check()


def test_revocation_refuses_before_clinical_effect(clinical_session, tmp_path):
    case = clinical_session
    case.sessions.revoke(case.authenticated)
    target = tmp_path / "must-not-be-created.txt"
    with pytest.raises(CredentialError, match="session authority changed"):
        with case.credentials.admit_release(contract={SESSION_FIELD: case.bridge.binding()},
                context=case.context, authorization=case.authorization) as check:
            check()
            target.write_text("fictional effect", encoding="utf-8")
    assert not target.exists()


@pytest.mark.parametrize("field,value", [("workspace_id", "clinic-b"), ("user_id", "other-user"),
                                         ("session_reference", "0" * 64)])
def test_clinical_bridge_requires_exact_host_authenticated_identity(clinical_session, field, value):
    case = clinical_session
    other = replace(case.bridge.identity, **{field: value})
    with pytest.raises(SessionAdmissionRefused, match="authenticated retained session"):
        with case.bridge.admit_session(other):
            pytest.fail("different identity was admitted")


def test_expired_clinical_effect_window_is_refused(clinical_session):
    case = clinical_session
    with pytest.raises(SessionAdmissionRefused, match="expired"):
        with case.bridge.admit_session(case.bridge.identity, not_after=(case.clock.now_us() - 1) / 1_000_000):
            pytest.fail("expired clinical effect window was admitted")


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), -1, True])
def test_invalid_clinical_effect_window_is_refused(clinical_session, deadline):
    with pytest.raises(SessionAdmissionRefused, match="finite and positive"):
        with clinical_session.bridge.admit_session(clinical_session.bridge.identity, not_after=deadline):
            pytest.fail("invalid effect window was admitted")
