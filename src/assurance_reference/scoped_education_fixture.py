"""Explicit fictional signed Education authority on the restricted PG host.

All grants, people, source content and confirmations are test fixtures. This
composes the real scoped authority path, without claiming an actual human has
judged the educational content or that an owner signed a real appointment.
"""

from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

from assurance_reference.education_authority_store import (
    compose_education_provisioner, compose_education_reader,
)
from assurance_reference.education_release_authority import EducationReleaseAuthority
from assurance_reference.education_gate import EducationGate
from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.session_admission_scope import SessionAdmissionScope
from factory.education_workbench.appointments import POLICY, ROLE, ReviewerAppointments
from factory.education_workbench.provisioning import provision_enrollment
from factory.education_workbench.reviewer_credentials import AssessmentScope
from factory.education_workbench.source_material import work_digest
from regulated_core.policy_document import document_policy


def compose_scoped_fixture(app, *, authorities, keys, registry, pack, alerts,
                           qualifications, signer_factory, fixture_validity_us=120_000_000):
    if type(fixture_validity_us) is not int or not 0 < fixture_validity_us <= 600_000_000:
        raise ValueError("fictional evidence validity must be positive and at most ten minutes")
    trust, now = authorities.trust, app.clock.now_us()
    domain_keys = {name: signer_factory("reference-scoped-education-fixture:" + name)
                   for name in ("school", "appointment-owner", "source-witness")}
    for key in domain_keys.values():
        trust.register_signer(key)
        app.public_keys[key.key_id] = key.public_key_bytes.hex()
    retained = {"learner_draft": "Fictional learner: a triangle has equal sides.",
                "rubric": "Label the equal sides.", "rubric_identifier": "fixture-rubric",
                "rubric_criteria": ["reasoning"]}
    rubric = {"identifier": retained["rubric_identifier"], "text": retained["rubric"],
              "criteria": retained["rubric_criteria"]}
    app.contract.update(rubric_identifier=retained["rubric_identifier"],
        learner_draft_digest=sha256(retained["learner_draft"].encode()).hexdigest(),
        feedback_digest=sha256(app.body).hexdigest(),
        rubric_digest=sha256(json.dumps(rubric, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    scope = AssessmentScope("school-a", "school-a", "class-a", "assessment-a", "geometry",
                            work_digest(app.contract), now + fixture_validity_us)
    scopes = {(scope.tenant, scope.project_id): scope}
    app.context = replace(app.context, retained_state=retained)
    provisioner = compose_education_provisioner(pool=app.roles.education_governor, tenant="school-a")
    appointments = ReviewerAppointments(registry, provisioner, trust=trust,
        owner_authority=domain_keys["appointment-owner"].key_id, schools={"school-a": "school-a"})
    grants = {}

    def enroll(status="active"):
        generation = grants.get("enrollment_generation", 0) + 1
        document = document_policy(domain_keys["school"], vertical="education", policy_id="school-enrollment",
            version=str(generation), content={"tenant_id": "school-a", "principal": "teacher",
                "class_id": "class-a", "role": "teacher", "status": status,
                "given_name": "Fictional", "family_name": "Teacher"},
            jurisdictions=(), effective_from_us=now, effective_until_us=scope.expires_at_us)
        provision_enrollment(registry, provisioner, document, trust=trust,
            school_authority=domain_keys["school"].key_id, now_us=app.clock.now_us(),
            expected_revision=None if generation == 1 else generation - 1)
        grants["enrollment_generation"] = generation

    def appoint(status="active"):
        previous = grants.get("appointment")
        generation = 1 if previous is None else int(previous.version) + 1
        document = document_policy(domain_keys["appointment-owner"], vertical="education", policy_id=POLICY,
            version=str(generation), content={"tenant_id": "school-a", "school_id": "school-a",
                "principal": "head", "class_id": "class-a", "role": ROLE, "status": status,
                "given_name": "Fictional", "family_name": "Head",
                "owner_approval_ref": "SCRIPTED-FIXTURE-NOT-OWNER-APPROVAL"},
            jurisdictions=(), effective_from_us=now, effective_until_us=scope.expires_at_us,
            supersedes="" if previous is None else previous.digest())
        appointments.provision(document, now_us=app.clock.now_us(),
            expected_revision=None if previous is None else generation - 1)
        grants["appointment"] = document

    enroll()
    appoint()

    def member_active(tenant, principal):
        identity = app.sessions.resolve(principal, tenant)
        return identity is not None and identity.active

    def make_gate(authenticated):
        admission = SessionAdmissionScope(app.sessions, authenticated)
        reader = compose_education_reader(pool=app.roles.education_reader,
            sessions=admission, authenticated=authenticated)
        appointments = ReviewerAppointments(registry, reader, trust=trust,
            owner_authority=domain_keys["appointment-owner"].key_id, schools={"school-a": "school-a"})
        credentials = EducationReleaseAuthority(appointments, signer=keys["credential"],
            school_authorities={"school-a": domain_keys["school"].key_id},
            assessment_scope=lambda tenant, project: scopes.get((tenant, project)),
            member_active=member_active, sessions=admission, authenticated=authenticated,
            review_store=app.stores.reviews, witness_signer=domain_keys["source-witness"])
        host = compose_reference_host(app.stores, replace(authorities,
            credential_verifier=credentials, review_extension_factory=credentials.review_extension),
            alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
        gate = host(pack, registry, SimpleNamespace(spec=app.spec))
        credentials.bind_receiving_gate(gate, app.spec)
        from assurance_reference.lineage_gate import QualificationEvidenceGate
        return QualificationEvidenceGate(EducationGate(gate))

    app.gates = {principal: make_gate(session) for principal, session in app.identities.items()}
    app.make_gate = make_gate
    app.scoped = SimpleNamespace(retained=retained, scope=scope, scopes=scopes,
                                 enroll=enroll, appoint=appoint)
