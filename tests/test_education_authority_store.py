"""Signed enrollment and scoped review under actual isolated restricted logins."""

from dataclasses import replace
import os
from threading import Event, Thread
from types import SimpleNamespace

import psycopg
import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.education_authority_store import compose_education_provisioner, compose_education_reader
from assurance_reference.education_review_sessions import SessionEnrollmentReviewer
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.session_credentials import SessionRefused, SessionUnavailable
from factory.education_workbench.appointments import ReviewerAppointments
from factory.education_workbench.provisioning import provision_enrollment
from factory.education_workbench.reviewer_credentials import AssessmentScope
from factory.packs.examples import EDUCATION_ID, build_education_pack
from factory.packs.registry import PackRegistry
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import digest_hex
from regulated_core.clock_pg import DbClock
from regulated_core.identity_provider import CredentialError
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, TrustDirectory


@pytest.fixture
def school(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
    sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)
    identities = {}
    for tenant in ("school-a", "school-b"):
        sessions.provision_identity(tenant, "teacher", "teacher.local", "fictional-password-001")
        identities[tenant] = sessions.authenticate(tenant, sessions.login(
            tenant, "teacher.local", "fictional-password-001"))
    trust = TrustDirectory()
    keys = {n: Ed25519Signer("fictional-pg-education:" + n)
            for n in ("publisher", "school", "owner", "credential")}
    for key in keys.values():
        trust.register_signer(key)
    manifest = build_education_pack(tmp_path / "pack", publisher=keys["publisher"],
                                    rulebook_authority=keys["school"])
    registry = PackRegistry(trust=trust)
    registry.install(tmp_path / "pack", publisher_key_id=keys["publisher"].key_id, today="2026-10-14")
    # Lifecycle is an explicit memory fixture here; this test qualifies the
    # collection roles and scoped reviewer, not the complete release host.
    registry.activate(manifest.reference, at="2026-10-14T00:00:00Z")
    stores = {t: compose_education_provisioner(pool=roles.education_governor, tenant=t) for t in identities}
    readers = {t: compose_education_reader(pool=roles.education_reader, sessions=sessions,
                                          authenticated=i) for t, i in identities.items()}
    now = clock.now_us()
    def enroll(tenant, *, version="1", status="active"):
        doc = document_policy(keys["school"], vertical="education", policy_id="school-enrollment",
            version=version, content={"tenant_id": tenant, "principal": "teacher", "class_id": "class-a",
                "role": "teacher", "status": status, "given_name": "Fictional", "family_name": tenant},
            jurisdictions=(), effective_from_us=now, effective_until_us=now + 120_000_000)
        return provision_enrollment(registry, stores[tenant], doc, trust=trust,
            school_authority=keys["school"].key_id, now_us=clock.now_us(),
            expected_revision=None if version == "1" else int(version) - 1)
    documents = {t: enroll(t) for t in identities}
    appointments = ReviewerAppointments(registry, readers["school-a"], trust=trust,
        owner_authority=keys["owner"].key_id, schools={"school-a": "school-a"})
    contract = {"body": "Fictional scoped feedback"}
    scope = AssessmentScope("school-a", "school-a", "class-a", "assessment-a", "project-a",
                            digest_hex(contract), now + 110_000_000)
    def member_active(tenant, principal):
        identity = sessions.resolve(principal, tenant)
        return identity is not None and identity.active
    reviewer = SessionEnrollmentReviewer(appointments, signer=keys["credential"],
        school_authorities={"school-a": keys["school"].key_id},
        assessment_scope=lambda t, p: scope if (t, p) == (scope.tenant, scope.project_id) else None,
        member_active=member_active, sessions=sessions, authenticated=identities["school-a"])
    context = EmissionContext("school-a", "teacher", project_id="project-a", now_us=1)
    return SimpleNamespace(roles=roles, sessions=sessions, identities=identities, readers=readers,
        stores=stores, documents=documents, enroll=enroll, reviewer=reviewer, context=context,
        contract=contract, registry=registry)


def test_signed_teacher_grant_is_durable_and_revocation_invalidates_receipt(school):
    s = school
    receipt = s.reviewer.verify_review("teacher", "school-a", "teacher", contract=s.contract, context=s.context)
    assert receipt.verified_at_us > 1 and receipt.provider.startswith("owner-enrollment:")
    s.reviewer.validate_review(receipt, contract=s.contract, context=s.context)
    reopened = compose_education_reader(pool=s.roles.education_reader, sessions=s.sessions,
                                       authenticated=s.identities["school-a"])
    assert reopened.get(EDUCATION_ID, "roster-user", "school-a", s.documents["school-a"].key) == s.documents["school-a"]
    s.enroll("school-a", version="2", status="tobedeleted")
    with pytest.raises(CredentialError, match="current signed teacher enrollment"):
        s.reviewer.validate_review(receipt, contract=s.contract, context=s.context)


def test_foreign_tenant_is_invisible_and_cross_tenant_write_is_refused(school):
    s = school
    foreign = s.documents["school-b"]
    assert s.readers["school-a"].get(EDUCATION_ID, "roster-user", "school-b", foreign.key) is None
    assert s.readers["school-a"].list(EDUCATION_ID, "roster-user", "school-b") == ()
    spec = s.registry.for_tenant("school-a", EDUCATION_ID).collection("roster-user")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        s.stores["school-a"].put(spec, replace(foreign, tenant_id="school-c"), expected_version=None)
    assert s.readers["school-b"].get(EDUCATION_ID, "roster-user", "school-b", foreign.key) == foreign


def test_receiver_and_reader_cannot_write_or_delete_authority(school):
    s = school
    spec = s.registry.for_tenant("school-a", EDUCATION_ID).collection("roster-user")
    with pytest.raises(SessionUnavailable) as refused:
        s.readers["school-a"].put(spec, replace(s.documents["school-a"], version=2), expected_version=1)
    # The session admission boundary wraps downstream PostgreSQL failures.
    # Require the precise underlying privilege refusal, not any runtime error.
    assert isinstance(refused.value.__cause__, psycopg.errors.InsufficientPrivilege)
    for pool in (s.roles.receiver, s.roles.education_reader, s.roles.education_governor):
        with pool.connection() as conn:
            assert not conn.execute("SELECT has_table_privilege(session_user,'pack_documents','DELETE,TRUNCATE')").fetchone()[0]
            if pool is s.roles.receiver:
                assert not conn.execute("SELECT has_table_privilege(session_user,'pack_documents','SELECT,INSERT,UPDATE')").fetchone()[0]
            else:
                # A raw login without the host tenant context sees no rows.
                assert conn.execute("SELECT count(*) FROM pack_documents").fetchone() == (0,)
                assert conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='pack_documents'::regclass").fetchone() == (True, True)


def test_revoked_authenticated_session_cannot_read_authority(school):
    s = school
    s.sessions.revoke(s.identities["school-a"])
    with pytest.raises(SessionRefused):
        s.readers["school-a"].list(EDUCATION_ID, "roster-user", "school-a")


def test_signed_revocation_waits_for_the_complete_review_guard(school):
    s = school
    receipt = s.reviewer.verify_review("teacher", "school-a", "teacher", contract=s.contract, context=s.context)
    entered, completed = Event(), Event()
    errors = []
    def revoke():
        entered.set()
        try:
            s.enroll("school-a", version="2", status="tobedeleted")
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()
    worker = Thread(target=revoke)
    try:
        # Match the source-review host order: session -> lifecycle -> reviewer.
        # Taking reviewer locks before lifecycle would invert the provisioner's
        # order and cause a bounded lock timeout instead of a completed revocation.
        with s.reviewer._admitted(s.context):
            with s.registry.resolution_guard("school-a", EDUCATION_ID,
                    now_us=s.sessions.clock.now_us()) as active:
                assert active is not None
                with s.reviewer.review_guard(contract=s.contract, context=s.context, actors=("teacher",)):
                    worker.start()
                    assert entered.wait(2)
                    assert not completed.wait(0.15)
                    s.reviewer.validate_review(receipt, contract=s.contract, context=s.context)
    finally:
        if worker.ident is not None:
            worker.join(10)
    assert not worker.is_alive() and completed.is_set() and errors == []
    with pytest.raises(CredentialError, match="current signed teacher enrollment"):
        s.reviewer.validate_review(receipt, contract=s.contract, context=s.context)
