"""Scripted confirmation protocol with real signatures; no actual human-review claim."""

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from threading import RLock
from types import SimpleNamespace

import pytest

from assurance_reference.education_review_sessions import SessionEnrollmentReviewer
from assurance_reference.education_source_sessions import SessionHumanSourceReviews
from assurance_reference.session_credentials import AuthenticatedSession
from factory.education_workbench.appointments import ReviewerAppointments
from factory.education_workbench.provisioning import provision_enrollment
from factory.education_workbench.reviewer_credentials import AssessmentScope
from factory.education_workbench.source_material import work_digest
from factory.education_workbench.source_witness import HOUR_US, SourceWitnessError
from factory.packs.collections import InMemoryPackCollectionStore
from factory.packs.examples import build_education_pack
from factory.packs.registry import PackRegistry
from factory.projectos.regulated import EmissionContext
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Outcome
from regulated_core.policy_document import document_policy
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_education_review_sessions import Sessions


class MemoryReviews:
    durable = False

    def __init__(self):
        self.rows, self.lock = {}, RLock()

    def get(self, tenant, key):
        with self.lock:
            return deepcopy(self.rows.get((tenant, key)))

    def transact(self, tenant, key, mutation):
        with self.lock:
            value = mutation(deepcopy(self.rows.get((tenant, key))))
            self.rows[(tenant, key)] = deepcopy(value)
            return deepcopy(value)


@pytest.fixture
def witness(tmp_path):
    now = 1_789_056_000_000_000
    trust = TrustDirectory()
    keys = {n: Ed25519Signer("fictional-source-review:" + n)
            for n in ("publisher", "school", "owner", "credential", "witness")}
    for key in keys.values():
        trust.register_signer(key)
    root = tmp_path / "pack"
    manifest = build_education_pack(root, publisher=keys["publisher"], rulebook_authority=keys["school"])
    collections = InMemoryPackCollectionStore()
    registry = PackRegistry(trust=trust, collections=collections)
    registry.install(root, publisher_key_id=keys["publisher"].key_id, today="2026-09-10")
    registry.activate(manifest.reference, at="2026-09-10T00:00:00Z")
    appointments = ReviewerAppointments(registry, collections, trust=trust,
        owner_authority=keys["owner"].key_id, schools={"workspace-a": "school-a"})
    def enrollment(version="1", status="active"):
        document = document_policy(keys["school"], vertical="education", policy_id="school-enrollment",
            version=version, content={"tenant_id": "workspace-a", "principal": "teacher",
                "class_id": "class-a", "role": "teacher", "status": status,
                "given_name": "Fictional", "family_name": "Teacher"},
            jurisdictions=(), effective_from_us=now - 1, effective_until_us=now + 2 * HOUR_US)
        return provision_enrollment(registry, collections, document, trust=trust,
            school_authority=keys["school"].key_id, now_us=now,
            expected_revision=None if version == "1" else int(version) - 1)
    enrollment()
    state = {"learner_draft": "Fictional triangle answer", "rubric": "Explain equal sides",
             "rubric_identifier": "fixture-rubric", "rubric_criteria": ["reasoning"]}
    body = "Fictional feedback: explain the reasoning."
    rubric = {"identifier": state["rubric_identifier"], "text": state["rubric"],
              "criteria": state["rubric_criteria"]}
    contract = {"body": body, "rubric_identifier": state["rubric_identifier"],
                "rubric_criteria": state["rubric_criteria"],
                "learner_draft_digest": sha256(state["learner_draft"].encode()).hexdigest(),
                "feedback_digest": sha256(body.encode()).hexdigest(),
                "rubric_digest": sha256(json.dumps(rubric, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    scope = AssessmentScope("workspace-a", "school-a", "class-a", "assessment-a", "project-a",
                            work_digest(contract), now + 2 * HOUR_US)
    scopes = {(scope.tenant, scope.project_id): scope}
    sessions = Sessions()
    sessions.now = now
    authority = SessionEnrollmentReviewer(appointments, signer=keys["credential"],
        school_authorities={"workspace-a": keys["school"].key_id},
        assessment_scope=lambda tenant, project: scopes.get((tenant, project)),
        member_active=lambda tenant, actor: tenant == "workspace-a" and actor == "teacher",
        sessions=sessions, authenticated=AuthenticatedSession(
            "workspace-a", "teacher", "teacher.local", "fictional-session", now + 2 * HOUR_US))
    signed = []
    def sign(value):
        assert sessions.depth == 1
        signed.append(deepcopy(value))
        return keys["witness"].sign(value)
    signer = SimpleNamespace(key_id=keys["witness"].key_id, sign=sign)
    reviews = MemoryReviews()
    service = SessionHumanSourceReviews(authority=authority, store=reviews, signer=signer, trust=trust)
    context = EmissionContext("workspace-a", "teacher", project_id="project-a", now_us=1,
                              retained_state=state)
    return SimpleNamespace(service=service, contract=contract, context=context, signed=signed,
        sessions=sessions, enrollment=enrollment, state=state, scopes=scopes, scope=scope, now=now)


def confirm(s, *, yes=True, request="fixture-decision", context=None, displayed=None):
    material = s.service.material(s.contract, s.context)
    return s.service.confirm_from_context(contract=s.contract, context=context or s.context,
        expected_material_digest=displayed or material.digest(), confirmed=yes, request_id=request)


def verdict(s):
    return s.service.verify_context(s.contract["body"], s.contract, s.context)[0]


def test_view_is_not_confirmation_and_current_verification_never_resigns(witness):
    s = witness
    view = s.service.view(s.contract, s.context)
    assert view["can_confirm"] and not view["confirmed"] and s.signed == []
    assert verdict(s) == Outcome.FAIL
    result = confirm(s)
    assert result["confirmed"] and result["expires_at_us"] == s.now + HOUR_US
    assert s.signed[0]["issued_at_us"] == s.now
    assert verdict(s) == Outcome.PASS and len(s.signed) == 1
    assert confirm(s) == result and len(s.signed) == 1
    assert s.sessions.depth == 0


def test_negative_confirmation_supersedes_positive_without_verifier_signing(witness):
    s = witness
    confirm(s)
    assert not confirm(s, yes=False, request="fixture-rejection")["confirmed"]
    assert verdict(s) == Outcome.FAIL
    with pytest.raises(SourceWitnessError, match="superseded"):
        confirm(s)
    assert len(s.signed) == 2


@pytest.mark.parametrize("change", [dict(actor_id="another"), dict(tenant="other"),
    dict(actor_roles=("teacher",)), dict(is_producer=True)])
def test_wrong_session_or_asserted_role_cannot_confirm(witness, change):
    with pytest.raises((CredentialError, SourceWitnessError)):
        confirm(witness, context=replace(witness.context, **change))
    assert witness.signed == [] and witness.sessions.depth == 0


def test_old_display_and_changed_retained_material_refuse(witness):
    s = witness
    with pytest.raises(ValueError, match="changed"):
        confirm(s, displayed="0" * 64)
    assert s.signed == []
    confirm(s)
    s.state["learner_draft"] = "Changed retained work"
    assert verdict(s) == Outcome.FAIL and len(s.signed) == 1


@pytest.mark.parametrize("change", ["enrollment", "assessment", "session", "expiry"])
def test_current_authority_and_one_hour_limit_are_rechecked(witness, change):
    s = witness
    confirm(s)
    if change == "enrollment":
        s.enrollment(version="2", status="tobedeleted")
    elif change == "assessment":
        s.scopes[("workspace-a", "project-a")] = replace(s.scope, assessment_id="replacement")
    elif change == "session":
        s.sessions.revoked = True
    else:
        s.sessions.now += HOUR_US
    assert verdict(s) == Outcome.FAIL and len(s.signed) == 1
    assert s.sessions.depth == 0


def test_signing_delay_does_not_report_expired_confirmation_as_current(witness):
    s = witness
    original = s.service.signer.sign
    def delayed(value):
        signature = original(value)
        s.sessions.now += HOUR_US
        return signature
    s.service.signer.sign = delayed
    with pytest.raises(SourceWitnessError, match="recorded but is no longer current"):
        confirm(s)
    assert verdict(s) == Outcome.FAIL and len(s.signed) == 1


def test_original_requester_policy_lookup_requires_existing_authenticated_scope_guard(witness):
    s = witness
    confirm(s)
    requester = replace(s.context, actor_id="requester")
    assert s.service.verify_context(s.contract["body"], s.contract, requester)[0] == Outcome.FAIL
    with s.service.release_guard(s.contract, s.context):
        assert s.service.verify_context(s.contract["body"], s.contract, requester)[0] == Outcome.PASS
        for changed in (replace(requester, tenant="other"), replace(requester, project_id="other"),
                        replace(requester, actor_roles=("teacher",)), replace(requester, is_producer=True)):
            assert s.service.verify_context(s.contract["body"], s.contract, changed)[0] == Outcome.FAIL
    assert len(s.signed) == 1 and s.sessions.depth == 0
