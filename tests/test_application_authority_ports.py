"""Pinned credential/session contracts using explicit synthetic observations.

No fabricated observation is passed to an actual effect. These port tests do
not qualify a login service, clinical source, or complete application release.
"""

from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from factory.health_ui.identity import IdentityStoreDegraded, SessionAdmissionRefused
from factory.health_ui.session_release import ClinicalSessionCredentials, SESSION_FIELD, SESSION_SCHEMA
from factory.packs.demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from factory.projectos.regulated import EmissionContext
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE, issue_certificate
from regulated_core.identity_provider import CredentialError, IdentitySubject, LocalIdentityProvider
from regulated_core.models import Outcome
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import ReleaseAdmissionUnavailable


class ObservedSessions:
    """Injected synthetic session observations, with no login or effect authority."""

    def __init__(self):
        self.failure = None
        self.exit_failure = False
        self.observed = None

    @contextmanager
    def admit_session(self, identity, *, not_after):
        self.observed = (identity, not_after)

        def current():
            if self.failure is not None:
                raise self.failure

        yield current
        if self.exit_failure:
            raise IdentityStoreDegraded("synthetic acknowledgement loss")


def credential_fixture():
    trust = TrustDirectory()
    issuer, signer = Ed25519Signer("fixture:institution"), Ed25519Signer("fixture:credential")
    for key in (issuer, signer):
        trust.register_signer(key)
    identity = LocalIdentityProvider()
    identity.add(IdentitySubject("teacher", "school-a", "Fictional teacher"))
    certificates = CertificateRegistry(trust, {issuer.key_id: DEMONSTRATION_CERTIFICATE})
    certificate = issue_certificate(issuer, subject_id="teacher", role="teacher",
                                    jurisdiction="ZA", expires_at_us=1_000_000)
    certificates.present(certificate)
    sessions = ObservedSessions()
    verifier = ClinicalSessionCredentials(trust, signer, identity, certificates, sessions=sessions)
    return verifier, sessions, certificates, certificate


def session_request():
    context = EmissionContext(tenant="school-a", actor_id="teacher")
    contract = {SESSION_FIELD: {
        "schema": SESSION_SCHEMA, "user_id": "teacher", "username": "fixture.teacher",
        "workspace_id": "school-a", "reference": "a" * 64, "expires_at": 1.0,
    }}
    # A port observation, never a signed permit and never sent to a target.
    authorization = SimpleNamespace(permit=SimpleNamespace(permit=SimpleNamespace(
        principal="teacher", expires_at_us=900_000,
    )))
    return contract, context, authorization


def test_certificate_kind_is_issuer_bound_and_receipt_is_current():
    verifier, _, certificates, certificate = credential_fixture()
    receipt = verifier.verify("teacher", "school-a", "teacher", jurisdiction="ZA", now_us=100)
    assert receipt.licence_type == DEMONSTRATION_CERTIFICATE
    assert verifier.verify_receipt(receipt, now_us=101)
    assert not verifier.provider_backed  # the identity adapter is explicitly local
    for tenant, jurisdiction, now in (("school-b", "ZA", 100), ("school-a", "ZW", 100),
                                       ("school-a", "ZA", 1_000_000)):
        with pytest.raises(CredentialError):
            verifier.verify("teacher", tenant, "teacher", jurisdiction=jurisdiction, now_us=now)
    certificates.present(replace(certificate, role="head-of-department"))
    with pytest.raises(CredentialError):
        verifier.verify("teacher", "school-a", "head-of-department", now_us=100)


@pytest.mark.parametrize("field,value", [("user_id", "someone-else"), ("workspace_id", "school-b"),
                                          ("schema", "other"), ("reference", "")])
def test_session_binding_refuses_mismatched_observations(field, value):
    verifier, sessions, _, _ = credential_fixture()
    contract, context, authorization = session_request()
    contract[SESSION_FIELD][field] = value
    with pytest.raises(CredentialError):
        with verifier.admit_release(contract=contract, context=context, authorization=authorization):
            pytest.fail("mismatched session was admitted")
    assert sessions.observed is None


def test_final_session_check_and_lost_ack_keep_distinct_outcomes():
    verifier, sessions, _, _ = credential_fixture()
    contract, context, authorization = session_request()
    with verifier.admit_release(contract=contract, context=context, authorization=authorization) as current:
        current()
        assert sessions.observed[1] == 0.9  # actual permit deadline reaches the session port
        sessions.failure = SessionAdmissionRefused("synthetic expired observation")
        with pytest.raises(EmissionError):
            current()
        sessions.failure = IdentityStoreDegraded("synthetic unavailable observation")
        with pytest.raises(ReleaseAdmissionUnavailable):
            current()
    sessions.failure, sessions.exit_failure = None, True
    with pytest.raises(ReleaseAdmissionUnavailable, match="reconcile"):
        with verifier.admit_release(contract=contract, context=context, authorization=authorization) as current:
            current()


def test_snapshot_check_uses_host_evidence_tenant_time_and_exact_output():
    snapshot = EvidenceSnapshot(
        "school-a", "geometry", "1", "Fictional formative feedback",
        (("rubric", "fixture-v1", "Label the equal sides before using the angle rule."),),
        (("rubric", "Label the equal sides before using the angle rule."),),
        ("Synthetic geometry evidence; no learner record or qualification claim.",), 100, 200,
    )
    verifier, contract = SnapshotVerifier((snapshot,)), snapshot.contract()
    context = EmissionContext(tenant="school-a", actor_id="teacher", now_us=150)
    assert verifier.verify_context(snapshot.render(), contract, context) == (Outcome.PASS, ())
    assert verifier(snapshot.render(), contract)[0] is Outcome.FAIL
    for admitted_time in (100, 199):
        assert verifier.verify_context(
            snapshot.render(), contract, replace(context, now_us=admitted_time),
        ) == (Outcome.PASS, ())
    for alternate in (replace(context, tenant="school-b"), replace(context, now_us=99),
                      replace(context, now_us=200)):
        assert verifier.verify_context(snapshot.render(), contract, alternate)[0] is Outcome.FAIL
    assert verifier.verify_context("Invented feedback", contract, context)[0] is Outcome.FAIL
    assert verifier.verify_context(snapshot.render(), {**contract, "evidence_revision": "2"}, context)[0] is Outcome.FAIL
    for changed_contract in ({**contract, "case_id": "different-fictional-case"},
                             {**contract, "evidence_digest": "0" * 64}):
        assert verifier.verify_context(
            snapshot.render(), changed_contract, context,
        )[0] is Outcome.FAIL
    conflicted = replace(snapshot, conflicts=("Two synthetic sources disagree.",))
    assert SnapshotVerifier((conflicted,)).verify_context(
        conflicted.render(), conflicted.contract(), context,
    )[0] is Outcome.FAIL


def test_snapshot_verifier_requires_trusted_context_on_both_entry_points():
    verifier = SnapshotVerifier(())
    expected = (Outcome.FAIL, ("TRUSTED_CONTEXT_REQUIRED",))
    assert verifier("Synthetic draft", {"case_id": "fixture-case"}) == expected
    assert verifier.verify_context(
        "Synthetic draft", {"case_id": "fixture-case"}, None,
    ) == expected


@pytest.mark.parametrize("contract", [{}, {"case_id": None}, {"case_id": 17}])
def test_snapshot_verifier_requires_string_case_id(contract):
    verifier = SnapshotVerifier(())
    context = EmissionContext(tenant="school-a", actor_id="teacher", now_us=150)
    assert verifier.verify_context("Synthetic draft", contract, context) == (
        Outcome.FAIL, ("CASE_ID_REQUIRED",),
    )
