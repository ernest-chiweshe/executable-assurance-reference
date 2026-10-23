"""X-6 offline validity matrix: local-CA clinician certificates and owner-signed reviewer appointments.

Fictional issuers, owners and people; an in-memory collection store and a temporary certificate root. Each frozen
refusal category (expired, revoked, unsigned or wrongly signed, wrong scope) is refused at verification, and each
lawful credential verifies. The local certificate authority is a fixture, never a real professional register.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from factory.education_workbench.appointments import POLICY, ROLE, ReviewerAppointments
from factory.education_workbench.service import WorkbenchError
from factory.health_ui.clinician_certificates import (ClinicianCertificateStore, CertificateRefused,
                                                      certificate_document, mint_demonstration_certificate)
from factory.health_ui.clinician_credentials import CLINICIAN_ROLE
from factory.packs.collections import InMemoryPackCollectionStore
from factory.packs.examples import build_education_pack
from factory.packs.registry import PackRegistry
from regulated_core.certificates import DEMONSTRATION_CERTIFICATE, issue_certificate
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory

INSTITUTION = "institutional-attestation"
WORKSPACE = "fictional-workspace-a"
HOUR = 3_600_000_000


class Members:
    """Current workspace membership as the store asks for it; a fixture set, mutable to withdraw a member."""

    def __init__(self, *members):
        self.active = set(members)

    def active_member(self, user_id, workspace_id):
        return object() if (user_id, workspace_id) in self.active else None


@pytest.fixture
def certificates(tmp_path):
    trust = TrustDirectory()
    keys = {name: Ed25519Signer("fictional-local-ca:" + name) for name in ("institution", "demo", "undeclared")}
    for key in keys.values():
        trust.register_signer(key)
    clock = {"now": 1_000 * HOUR}
    members = Members(("clinician-a", WORKSPACE))
    issuers = {keys["institution"].key_id: INSTITUTION, keys["demo"].key_id: DEMONSTRATION_CERTIFICATE}
    store = ClinicianCertificateStore(tmp_path / "records", issuers, members, clock_us=lambda: clock["now"])

    def document(issuer="institution", *, subject="clinician-a", role=CLINICIAN_ROLE, workspace=WORKSPACE,
                 expires=None):
        certificate = issue_certificate(keys[issuer], subject_id=subject, role=role, jurisdiction="ZA",
                                        expires_at_us=clock["now"] + HOUR if expires is None else expires)
        return certificate_document(certificate, workspace)

    def lookup(subject="clinician-a"):
        return store.provider()(trust, WORKSPACE).lookup(subject, CLINICIAN_ROLE)

    return SimpleNamespace(trust=trust, keys=keys, clock=clock, members=members, store=store, issuers=issuers,
                           document=document, lookup=lookup)


def test_certificate_from_a_declared_issuer_verifies_with_the_issuers_registered_kind(certificates):
    c = certificates
    assert c.store.import_certificate(c.trust, c.document(), workspace_id=WORKSPACE) == INSTITUTION
    record = c.lookup()
    assert (record.subject_id, record.role, record.licence_type, record.status) == (
        "clinician-a", CLINICIAN_ROLE, INSTITUTION, "active")


def test_unsigned_or_forged_certificate_is_refused(certificates):
    c = certificates
    forged = c.document()
    forged["signature"] = {**forged["signature"], "value": c.document(subject="clinician-b")["signature"]["value"]}
    with pytest.raises(CertificateRefused, match="does not verify"):
        c.store.import_certificate(c.trust, forged, workspace_id=WORKSPACE)
    unsigned = {**c.document(), "signature": {"key_id": c.keys["institution"].key_id, "value": "", "alg": "ed25519"}}
    with pytest.raises(CertificateRefused, match="signature is malformed"):
        c.store.import_certificate(c.trust, unsigned, workspace_id=WORKSPACE)
    assert c.lookup() is None


def test_certificate_signed_by_another_key_or_an_undeclared_issuer_is_refused(certificates):
    c = certificates
    with pytest.raises(CertificateRefused, match="not declared"):
        c.store.import_certificate(c.trust, c.document("undeclared"), workspace_id=WORKSPACE)
    claimed = c.document("undeclared")
    claimed["issuer"] = c.keys["institution"].key_id
    with pytest.raises(CertificateRefused, match="declared issuer's trust anchor"):
        c.store.import_certificate(c.trust, claimed, workspace_id=WORKSPACE)


@pytest.mark.parametrize("change, reason", [
    ({"expires": 1_000 * HOUR}, "expired"),
    ({"expires": 1_000 * HOUR + 3 * 366 * 24 * HOUR}, "bounded validity"),
    ({"role": "nurse"}, "clinician role"),
    ({"subject": "not-a-member"}, "active clinician"),
])
def test_invalid_certificate_is_refused_at_import(certificates, change, reason):
    c = certificates
    with pytest.raises(CertificateRefused, match=reason):
        c.store.import_certificate(c.trust, c.document(**change), workspace_id=WORKSPACE)


def test_certificate_for_another_workspace_is_refused(certificates):
    c = certificates
    with pytest.raises(CertificateRefused, match="another workspace"):
        c.store.import_certificate(c.trust, c.document(workspace="fictional-workspace-b"), workspace_id=WORKSPACE)


@pytest.mark.parametrize("loss", ["expired", "revoked", "membership-withdrawn"])
def test_held_certificate_stops_verifying_after_expiry_revocation_or_membership_loss(certificates, loss):
    c = certificates
    c.store.import_certificate(c.trust, c.document(), workspace_id=WORKSPACE)
    assert c.lookup() is not None
    if loss == "expired":
        c.clock["now"] += HOUR
    elif loss == "revoked":
        assert c.store.revoke(WORKSPACE, "clinician-a")
    else:
        c.members.active.clear()
    assert c.lookup() is None


def test_demonstration_issuer_never_yields_a_stronger_kind(certificates):
    c = certificates
    document = mint_demonstration_certificate(c.keys["demo"], c.issuers, workspace_id=WORKSPACE,
                                              subject_id="clinician-a", jurisdiction="ZA",
                                              expires_at_us=c.clock["now"] + HOUR)
    assert c.store.import_certificate(c.trust, document, workspace_id=WORKSPACE) == DEMONSTRATION_CERTIFICATE
    assert c.lookup().licence_type == DEMONSTRATION_CERTIFICATE
    with pytest.raises(CertificateRefused, match="demonstration-certificate"):
        mint_demonstration_certificate(c.keys["institution"], c.issuers, workspace_id=WORKSPACE,
                                       subject_id="clinician-a", jurisdiction="ZA",
                                       expires_at_us=c.clock["now"] + HOUR)


@pytest.fixture
def appointments(tmp_path):
    trust = TrustDirectory()
    keys = {name: Ed25519Signer("fictional-x6-appointments:" + name)
            for name in ("publisher", "school", "owner", "other")}
    for key in keys.values():
        trust.register_signer(key)
    manifest = build_education_pack(tmp_path / "pack", publisher=keys["publisher"], rulebook_authority=keys["school"])
    store = InMemoryPackCollectionStore()
    registry = PackRegistry(trust=trust, collections=store)
    registry.install(tmp_path / "pack", publisher_key_id=keys["publisher"].key_id, today="2026-09-10")
    registry.activate(manifest.reference, at="2026-09-10T00:00:00Z")
    service = ReviewerAppointments(registry, store, trust=trust, owner_authority=keys["owner"].key_id,
                                   schools={"workspace-a": "school-a"})

    def appointment(signer="owner", *, version="1", status="active", start=10, until=100, supersedes="", **content):
        return document_policy(keys[signer], vertical="education", policy_id=POLICY, version=version,
            content={"tenant_id": "workspace-a", "school_id": "school-a", "principal": "head",
                     "class_id": "class-a", "role": ROLE, "status": status, "given_name": "Fictional",
                     "family_name": "Reviewer", "owner_approval_ref": "fictional-local-fixture-only", **content},
            jurisdictions=(), effective_from_us=start, effective_until_us=until, supersedes=supersedes)

    def current(now_us, principal="head", class_id="class-a"):
        return service.current("workspace-a", principal, class_id, now_us=now_us)

    return SimpleNamespace(service=service, appointment=appointment, current=current)


def test_owner_signed_current_appointment_verifies(appointments):
    a = appointments
    grant = a.appointment()
    a.service.provision(grant, now_us=20)
    assert a.current(30) == grant


@pytest.mark.parametrize("signer", ["other", "school"])
def test_appointment_not_signed_by_the_pinned_owner_is_refused(appointments, signer):
    a = appointments
    with pytest.raises(WorkbenchError, match="owner-signed appointment"):
        a.service.provision(a.appointment(signer), now_us=20)
    with pytest.raises(WorkbenchError, match="No owner-approved appointment"):
        a.current(30)


def test_tampered_appointment_is_refused(appointments):
    a = appointments
    tampered = replace(a.appointment(), content={**a.appointment().content, "class_id": "class-b"})
    with pytest.raises(WorkbenchError, match="owner-signed appointment"):
        a.service.provision(tampered, now_us=20)
    unsigned = replace(a.appointment(), signature=Signature(a.appointment().signature.key_id, "", "ed25519"))
    with pytest.raises(WorkbenchError, match="owner-signed appointment"):
        a.service.provision(unsigned, now_us=20)


@pytest.mark.parametrize("now", [5, 100, 150])
def test_appointment_outside_its_signed_validity_is_refused(appointments, now):
    a = appointments
    a.service.provision(a.appointment(), now_us=20)
    with pytest.raises(WorkbenchError, match="owner-signed appointment"):
        a.current(now)


def test_owner_signed_revocation_is_refused_at_verification(appointments):
    a = appointments
    grant = a.appointment()
    a.service.provision(grant, now_us=20)
    a.service.provision(a.appointment(version="2", status="revoked", start=30, supersedes=grant.digest()),
                        now_us=40, expected_revision=1)
    with pytest.raises(WorkbenchError, match="revoked"):
        a.current(50)


@pytest.mark.parametrize("principal, class_id", [("other-head", "class-a"), ("head", "class-b")])
def test_appointment_for_another_person_or_class_does_not_apply(appointments, principal, class_id):
    a = appointments
    a.service.provision(a.appointment(), now_us=20)
    with pytest.raises(WorkbenchError):
        a.current(30, principal=principal, class_id=class_id)
