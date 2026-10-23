"""Pack builders: the Education reference pack, its South African overlay, and the minimal pack.

``build_education_pack`` writes a complete, signed, conformant pack directory from Python data, the
way an SDK scaffold would: the schema, the signed rulebook with DECLARATIVE checks (host capabilities
plus parameters, no code), the conformance cases by category, the sources lock, the typed workflow,
the collections in the domain's own vocabulary (OneRoster users and enrollments, a CASE rubric,
Caliper-shaped mastery signals), the cards, the starting kit, the required expert roles, the content
index, the signature and the provenance. ``build_za_overlay`` is the third layer of the research's
separation: a jurisdiction overlay that tightens the base and adds its regulation to the lock.
``build_minimal_pack`` is the least a domain needs to be governed, for the fourth-pack law.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from regulated_core.policy_document import document_policy
from regulated_core.signing import Signer

from . import PACK_SCHEMA, PLATFORM_CONTRACT
from .attestations import sign_attestation, write_attestation
from .manifest import UNINDEXED, PackManifest, file_digest, manifest_from_dict
from .rulebook import OVERLAY_SCHEMA, RULEBOOK_SCHEMA, content_digest
from .schema import SCHEMA_ID
from .signing import sign_pack, write_provenance

NOW_US = 1_780_000_000_000_000
BUILDER_ID = "https://lumiwright.com/packkit/0.2"
BUILD_TYPE = "https://lumiwright.com/packkit/build/v1"
EDUCATION_ID = "lumiwright.education.formative-feedback"

EDUCATION_SCHEMA: dict[str, Any] = {
    "schema": SCHEMA_ID,
    "namespace": "education",
    "entity_types": {
        "Teacher": {"parents": [], "roles": ["teacher", "head-of-department"],
                    "attributes": {"sourcedId": {"type": "string"}, "orgSourcedId": {"type": "string"}}},
        "Learner": {"parents": [], "roles": ["learner"],
                    "attributes": {"sourcedId": {"type": "string"}, "gradeLevel": {"type": "string", "required": False}}},
        "Guardian": {"parents": [], "roles": ["guardian"], "attributes": {"sourcedId": {"type": "string"}}},
        "Submission": {"parents": [], "attributes": {
            "submissionId": {"type": "string"}, "exerciseId": {"type": "string"}, "learnerSourcedId": {"type": "string"},
            "rubricIdentifier": {"type": "string"}, "media": {"type": "set"}, "submittedAt": {"type": "timestamp"}}},
        "Feedback": {"parents": [], "attributes": {
            "feedbackId": {"type": "string"}, "submissionId": {"type": "string"}, "draftDigest": {"type": "string"},
            "confidence": {"type": "decimal", "required": False}, "misconceptionCodes": {"type": "set"}}},
        "ProgressRecord": {"parents": [], "attributes": {
            "learnerSourcedId": {"type": "string"}, "competencyUri": {"type": "string"}, "score": {"type": "decimal"},
            "eventTime": {"type": "timestamp"}}},
    },
    "actions": {
        "education:draft-feedback": {"effect": "reversible",
                                     "applies_to": {"principal_types": ["Teacher"], "resource_types": ["Submission"]},
                                     "context": {"lane": {"type": "string"}, "rubricIdentifier": {"type": "string"}}},
        "education:release-feedback": {"effect": "external",
                                       "applies_to": {"principal_types": ["Teacher"], "resource_types": ["Feedback"]},
                                       "context": {"nonce": {"type": "string"}, "confidence": {"type": "decimal", "required": False}}},
        "education:record-progress": {"effect": "authoritative",
                                      "applies_to": {"principal_types": ["Teacher"], "resource_types": ["ProgressRecord"]},
                                      "context": {"eventTime": {"type": "timestamp"}}},
    },
}

OVERRIDE_REASONS = [
    {"code": "rubric-mismatch", "display": "The feedback does not follow the rubric"},
    {"code": "factually-wrong", "display": "The feedback is wrong about the work"},
    {"code": "tone", "display": "The tone is not right for this learner"},
    {"code": "needs-teacher", "display": "This needs a conversation, not written feedback"},
]

EDUCATION_RULEBOOK: dict[str, Any] = {
    "schema": RULEBOOK_SCHEMA,
    "content_types": ["education:formative-feedback"],
    "data_classes": ["pii"],
    "requires_payload_ref": False,
    "retention_years": 7,
    "checks": {
        "education:rubric-bound": {"kind": "deterministic", "version": "1", "capability": "contract.list-covers@1",
                                   "params": {"required_field": "rubric_criteria", "covered_field": "criteria_addressed",
                                              "reason_missing": "CRITERION_UNADDRESSED", "reason_empty": "NO_RUBRIC"}},
        "education:no-final-grade": {"kind": "deterministic", "version": "1", "capability": "text.prohibited-terms@1",
                                     "params": {"terms": ["final grade", "pass/fail", "you failed"],
                                                "patterns": ["\\b\\d{1,3}\\s?%"], "reason": "FINAL_GRADE_LEAKED"}},
        "education:hint-ladder-no-answer": {"kind": "deterministic", "version": "1", "capability": "text.excludes-contract-field@1",
                                            "params": {"field": "reference_answer", "reason": "ANSWER_LEAKED"}},
        "education:region-normalized": {"kind": "deterministic", "version": "1", "capability": "contract.regions-normalized@1",
                                        "params": {"items_field": "findings", "region_field": "region", "media_field": "media"}},
        "source:fidelity": {"kind": "platform", "version": "1"},
    },
    "rules": {
        "education:draft-feedback": {
            "required_checks": ["education:rubric-bound", "education:no-final-grade", "education:hint-ladder-no-answer"],
            "annotations": [{"kind": "disclaimer", "text": "advisory feedback; not yet reviewed by the teacher"}],
            "card": {"indicator": "info", "summary": "Advisory feedback is ready for your review.",
                     "override_reasons": OVERRIDE_REASONS},
        },
        "education:release-feedback": {
            "required_checks": ["education:rubric-bound", "education:no-final-grade", "education:hint-ladder-no-answer",
                                "education:region-normalized", "source:fidelity"],
            "requires_lineage": True,
            "approval": {"role_groups": [["teacher"]], "minimum_approvers": 1, "expires_after_hours": 72,
                         "reason": "a teacher releases feedback to a learner and their guardian"},
            "second_review": {"below_confidence": "0.70", "role_groups": [["teacher"], ["head-of-department"]],
                              "minimum_approvers": 2, "expires_after_hours": 72},
            "card": {"indicator": "warning", "summary": "Release this feedback? The learner and guardian will see it.",
                     "override_reasons": OVERRIDE_REASONS},
        },
        "education:record-progress": {
            "required_checks": ["education:rubric-bound"],
            "approval": {"role_groups": [["teacher"]], "minimum_approvers": 1, "expires_after_hours": 72,
                         "reason": "a teacher records an attempt against a competency"},
            "card": {"indicator": "info", "summary": "Record this attempt against the competency?",
                     "override_reasons": [{"code": "not-representative", "display": "This attempt does not show what the learner can do"}]},
        },
    },
    "prohibited_language": ["final grade", "pass/fail", "you failed", "disciplinary"],
}

_RUBRIC_CONTRACT = {"rubric_identifier": "drawing-first-angle/v1",
                    "rubric_criteria": ["projection", "line-types", "dimensioning"],
                    "criteria_addressed": ["projection", "line-types", "dimensioning"]}

#: Cases by check and category. Boundary cases record honest edges (an over-block the teacher card absorbs);
#: adversarial cases are inputs written to slip past the check and must still be caught.
EDUCATION_CASES: dict[str, dict[str, list[dict[str, Any]]]] = {
    "education:rubric-bound": {
        "golden": [
            {"name": "every criterion addressed", "draft": "...", "contract": _RUBRIC_CONTRACT, "expected": "pass"},
            {"name": "a criterion missed", "draft": "...", "contract": {**_RUBRIC_CONTRACT, "criteria_addressed": ["projection"]},
             "expected": "fail", "expected_reasons": ["CRITERION_UNADDRESSED"]},
            {"name": "no rubric", "draft": "...", "contract": {}, "expected": "fail", "expected_reasons": ["NO_RUBRIC"]},
        ],
        "adversarial": [
            {"name": "criterion named with different case is not the same criterion", "draft": "...",
             "contract": {**_RUBRIC_CONTRACT, "criteria_addressed": ["Projection", "line-types", "dimensioning"]},
             "expected": "fail", "expected_reasons": ["CRITERION_UNADDRESSED"]},
        ],
    },
    "education:no-final-grade": {
        "golden": [
            {"name": "advisory wording", "draft": "Your projection is right; check the hidden line on the left face.",
             "contract": {}, "expected": "pass"},
            {"name": "a percentage leaks", "draft": "This is worth 42% overall.", "contract": {}, "expected": "fail",
             "expected_reasons": ["FINAL_GRADE_LEAKED"]},
            {"name": "the words final grade", "draft": "Your final grade is B.", "contract": {}, "expected": "fail"},
        ],
        "boundary": [
            {"name": "an encouraging percentage is over-blocked on purpose; the teacher card absorbs it",
             "draft": "100% effort on the hatching, keep it up.", "contract": {}, "expected": "fail",
             "expected_reasons": ["FINAL_GRADE_LEAKED"]},
        ],
        "adversarial": [
            {"name": "upper case", "draft": "FINAL GRADE: 7/10", "contract": {}, "expected": "fail"},
            {"name": "space before the percent sign", "draft": "you scored 85 %", "contract": {}, "expected": "fail"},
            {"name": "pass/fail inside a sentence", "draft": "On a pass/fail basis this would not pass.", "contract": {}, "expected": "fail"},
        ],
    },
    "education:hint-ladder-no-answer": {
        "golden": [
            {"name": "hint without the answer", "draft": "Try moving the term across and watch the sign.",
             "contract": {"reference_answer": "x = -3"}, "expected": "pass"},
            {"name": "the answer leaks", "draft": "The answer is x = -3, so try again.",
             "contract": {"reference_answer": "x = -3"}, "expected": "fail", "expected_reasons": ["ANSWER_LEAKED"]},
        ],
        "adversarial": [
            {"name": "spacing and case do not hide the answer", "draft": "so X=-3 is where you should land",
             "contract": {"reference_answer": "x = -3"}, "expected": "fail", "expected_reasons": ["ANSWER_LEAKED"]},
        ],
    },
    "education:region-normalized": {
        "golden": [
            {"name": "localised finding", "draft": "...", "contract": {"media": ["scan.jpg"],
             "findings": [{"rubric_code": "dimensioning", "region": [0.1, 0.2, 0.4, 0.5]}]}, "expected": "pass"},
            {"name": "region outside the image", "draft": "...", "contract": {"media": ["scan.jpg"],
             "findings": [{"rubric_code": "dimensioning", "region": [0.1, 0.2, 1.4, 0.5]}]}, "expected": "fail",
             "expected_reasons": ["REGION_OUT_OF_BOUNDS"]},
            {"name": "image without localisation", "draft": "...", "contract": {"media": ["scan.jpg"], "findings": []},
             "expected": "indeterminate", "expected_reasons": ["NO_LOCALISATION"]},
            {"name": "text submission needs none", "draft": "...", "contract": {"media": [], "findings": []}, "expected": "pass"},
        ],
        "adversarial": [
            {"name": "a region given as strings still has to be inside the square", "draft": "...",
             "contract": {"media": ["scan.jpg"], "findings": [{"rubric_code": "x", "region": ["0.1", "0.2", "0.3", "1.5"]}]},
             "expected": "fail", "expected_reasons": ["REGION_OUT_OF_BOUNDS"]},
            {"name": "a three-number region is not a box", "draft": "...",
             "contract": {"media": ["scan.jpg"], "findings": [{"rubric_code": "x", "region": [0.1, 0.2, 0.3]}]},
             "expected": "fail", "expected_reasons": ["REGION_OUT_OF_BOUNDS"]},
        ],
    },
}

EDUCATION_SOURCES: list[dict[str, Any]] = [
    {"id": "case", "title": "1EdTech Competencies and Academic Standards Exchange (CASE)", "kind": "standard", "edition": "1.0",
     "effective_date": "2017-07-27", "licence": "1EdTech specification licence", "jurisdiction": "global",
     "url": "https://www.imsglobal.org/sites/default/files/CASE/casev1p0/information_model/caseservicev1p0_infomodelv1p0.html"},
    {"id": "oneroster", "title": "1EdTech OneRoster", "kind": "standard", "edition": "1.2", "effective_date": "2021-11-10",
     "licence": "1EdTech specification licence", "jurisdiction": "global", "url": "https://www.imsglobal.org/spec/oneroster/v1p2"},
    {"id": "caliper", "title": "1EdTech Caliper Analytics", "kind": "standard", "edition": "1.2", "effective_date": "2020-09-16",
     "licence": "1EdTech specification licence", "jurisdiction": "global", "url": "https://www.imsglobal.org/spec/caliper/v1p2"},
    {"id": "cds-hooks", "title": "HL7 CDS Hooks", "kind": "standard", "edition": "2.0", "effective_date": "2022-12-01",
     "licence": "HL7 (CC0 for the specification text)", "jurisdiction": "global", "url": "https://cds-hooks.hl7.org/2.0/"},
    {"id": "black-wiliam-1998", "title": "Black & Wiliam, Inside the Black Box: Raising Standards Through Classroom Assessment",
     "kind": "literature", "edition": "Phi Delta Kappan 80(2)", "effective_date": "1998-10-01", "licence": "published article",
     "jurisdiction": "global", "url": ""},
    {"id": "hattie-timperley-2007", "title": "Hattie & Timperley, The Power of Feedback", "kind": "literature",
     "edition": "Review of Educational Research 77(1)", "effective_date": "2007-03-01", "licence": "published article",
     "jurisdiction": "global", "url": ""},
    {"id": "zw-data-protection-act", "title": "Zimbabwe Data Protection Act [Chapter 11:22]", "kind": "regulation",
     "edition": "Act 5 of 2021", "effective_date": "2021-12-03", "licence": "government gazette", "jurisdiction": "ZW", "url": ""},
]

ZA_SOURCES: list[dict[str, Any]] = [
    {"id": "za-popia", "title": "Protection of Personal Information Act", "kind": "regulation", "edition": "Act 4 of 2013",
     "effective_date": "2020-07-01", "licence": "government publication", "jurisdiction": "ZA",
     "url": "https://www.gov.za/documents/protection-personal-information-act"},
]

EDUCATION_WORKFLOW: dict[str, Any] = {"stages": [
    {"id": "intake", "trigger": "submission-received", "action": None, "inputs": ["submission", "rubric"], "outputs": ["submission"]},
    {"id": "pre-assess", "trigger": "stage:intake", "action": "education:draft-feedback", "effect": "reversible",
     "inputs": ["submission", "rubric"], "outputs": ["feedback-draft", "card"]},
    {"id": "review", "trigger": "card-feedback", "action": None, "inputs": ["feedback-draft", "card-feedback"], "outputs": ["feedback"]},
    {"id": "release", "trigger": "stage:review", "action": "education:release-feedback", "effect": "external",
     "inputs": ["feedback", "approval"], "outputs": ["release-receipt"]},
    {"id": "progress", "trigger": "stage:release", "action": "education:record-progress", "effect": "authoritative",
     "inputs": ["release-receipt"], "outputs": ["mastery-signal"]},
    {"id": "retrieval", "trigger": "schedule", "action": None, "inputs": ["mastery-signal"], "outputs": ["re-attempt"]},
]}

GEOMETRY_COLLECTIONS: list[dict[str, Any]] = [
    {"name": name, "version": 1, "key": ["id"], "vocabulary": "lumi.geometry/1",
     "description": description,
     "fields": {"id": {"type": "string"}, "principal": {"type": "string"},
                "classId": {"type": "string"}, "exerciseId": {"type": "string"},
                "content": {"type": "record"}, "pins": {"type": "record"}}}
    for name, description in (
        ("geometry-draft", "Revision-controlled learner construction and explanation."),
        ("geometry-submission", "Immutable construction snapshot and original draft revision."),
        ("geometry-annotation", "Separate teacher annotation tied to an immutable submission."),
    )
]

EDUCATION_COLLECTIONS: list[dict[str, Any]] = [
    {"name": "reviewer-appointment", "version": 1, "key": ["principal", "classId", "role"],
     "vocabulary": "pack-local owner-approved pilot appointment",
     "description": "Signed named reviewer appointment, separate from the person's OneRoster enrollment.",
     "fields": {"principal": {"type": "string"}, "schoolId": {"type": "string"},
                "classId": {"type": "string"}, "role": {"type": "string"},
                "document": {"type": "record"}}},
    {"name": "roster-user", "version": 1, "key": ["sourcedId", "classSourcedId"],
     "vocabulary": "oneroster@1.2 User + Enrollment",
     "description": "One person in one class: the OneRoster role vocabulary, so a school's SIS export lands unchanged.",
     "fields": {"sourcedId": {"type": "string"}, "role": {"type": "string"}, "givenName": {"type": "string"},
                "familyName": {"type": "string"}, "classSourcedId": {"type": "string"}, "status": {"type": "string"},
                "guardianSourcedIds": {"type": "set", "required": False},
                "enrollmentDocumentDigest": {"type": "string", "required": False},
                "enrollmentGeneration": {"type": "long", "required": False},
                "enrollmentAuthority": {"type": "string", "required": False},
                "enrollmentEffectiveFromUs": {"type": "long", "required": False},
                "enrollmentEffectiveUntilUs": {"type": "long", "required": False},
                "enrollmentPayloadDigest": {"type": "string", "required": False}}},
    {"name": "rubric", "version": 1, "key": ["identifier"], "vocabulary": "case@1.0 CFRubric",
     "description": "A CASE rubric: criteria (CFRubricCriterion with CFItemURI and weight) and levels (quality, score, feedback).",
     "fields": {"identifier": {"type": "string"}, "title": {"type": "string"}, "subject": {"type": "string"},
                "criteria": {"type": "set"}, "version": {"type": "long"}}},
    {"name": "submission", "version": 1, "key": ["submissionId"], "vocabulary": "pack-local",
     "description": "A learner's attempt: text or photographed work, bound to an exercise and a rubric.",
     "fields": {"submissionId": {"type": "string"}, "learnerSourcedId": {"type": "string"}, "exerciseId": {"type": "string"},
                "rubricIdentifier": {"type": "string"}, "media": {"type": "set"}, "submittedAt": {"type": "timestamp"},
                "draftDigest": {"type": "string", "required": False}}},
    {"name": "mastery-signal", "version": 1, "key": ["learnerSourcedId", "competencyUri", "attempt"],
     "vocabulary": "caliper@1.2 GradeEvent / Result",
     "description": "One attempt against one competency (a CASE CFItem URI), scored, with the evidence digest.",
     "fields": {"learnerSourcedId": {"type": "string"}, "competencyUri": {"type": "string"}, "attempt": {"type": "long"},
                "score": {"type": "decimal"}, "confidence": {"type": "decimal", "required": False},
                "eventTime": {"type": "timestamp"}, "evidenceDigest": {"type": "string"}}},
]

EDUCATION_COLLECTIONS += GEOMETRY_COLLECTIONS

# Teacher-authored material is school data under the signed collection contract;
# it never changes the publisher's built-in exercise file or claims its signature.
EDUCATION_COLLECTIONS += [
    {"name": name, "version": 1, "key": ["id"], "vocabulary": "lumi.education-teaching/1",
     "description": description,
     "fields": {"id": {"type": "string"}, "principal": {"type": "string"},
                "classId": {"type": "string"}, "exerciseId": {"type": "string"},
                "content": {"type": "record"}, "pins": {"type": "record"}}}
    for name, description in (
        ("teaching-lesson", "Revision-controlled teacher-authored objectives, practice, hints and source notes."),
        ("teaching-assignment", "Immutable lesson snapshot assigned to one enrolled class; never an automatic assessment."),
    )
]

EDUCATION_EXPERT_ROLES = ["subject-teacher", "curriculum-lead", "privacy-officer"]

EDUCATION_KIT = """# Education formative-feedback pack: the starting kit

This kit is the part of the pack a domain expert reads first. It is a starting point drawn from
published standards and practice, not yet validated by a teacher of technical drawing or mathematics;
the validation record below is empty on purpose until signed attestations arrive in `trust/attestations/`.

## Journey

Intake (a learner's text, photographed or scanned work, bound to an exercise and a rubric) -> advisory
pre-assessment on a declared lane (rubric-bound findings, localised on the image, misconception codes,
a hint ladder that never contains the answer) -> the teacher's card (accept, or override with a stated
reason) -> digest-bound release to the learner and guardian with a receipt -> a mastery signal recorded
against the competency -> a spaced re-attempt scheduled from the signals. The stages are typed in the
manifest's `workflow` section and bound to the schema's actions.

## Rulebook sources

Every source below is locked by edition in the manifest's `knowledge.sources`; the receipt pins the lock.

- 1EdTech CASE 1.0 (competency frameworks and rubrics: CFDocument, CFItem, CFRubric, CFRubricCriterion,
  CFRubricCriterionLevel).
- 1EdTech OneRoster 1.2 (users, enrollments, classes; the roles student/teacher/parent/guardian).
- 1EdTech Caliper Analytics 1.2 (AssessmentEvent, GradeEvent, FeedbackEvent; Attempt, Score, Result).
- HL7 CDS Hooks 2.0 for the card and feedback shape (summary, indicator, suggestions, overrideReasons,
  accepted/overridden).
- Formative assessment practice: feedback that names the next step and withholds the grade
  (Black & Wiliam 1998; Hattie & Timperley 2007).
- Zimbabwe Data Protection Act [Chapter 11:22] for learner and guardian personal information; the South
  African overlay adds POPIA.

## Approvers

- Release of feedback: one teacher (role `teacher`), approval valid 72 hours.
- Below calibrated confidence 0.70, or with no calibrated confidence: a second reviewer, a head of
  department (role `head-of-department`), two distinct people.
- The requester of a release may not be its approver.
- A jurisdiction or organization overlay may raise these thresholds; it may not lower them.

## Evidence

Every release carries the nine pins: the pack reference and digest, the activation id, the rulebook
reference and effective digest, the schema digest, the sources-lock digest, the verifier-profile digest
and the builder; plus each check with its capability, version and outcome, the approvers, the card
feedback (accepted or overridden with the reason) and the artifact digest. The learner and guardian
can read the receipt; an auditor can verify it against the signed records.

## Expert validation

Required roles (manifest `experts.required_roles`): a subject teacher, a curriculum lead and a privacy
officer, each attesting the rulebook as it is now. Not yet performed. Before a school pilot: a teacher
of technical drawing and a teacher of mathematics review the rubric criteria, the misconception codes and
the hint ladder against their own marking; the review is recorded as a signed attestation, not as prose.
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _index(pack_dir: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(pack_dir.rglob("*")):
        if path.is_file() and path.name not in UNINDEXED and "__pycache__" not in path.parts:
            files[str(path.relative_to(pack_dir)).replace("\\", "/")] = file_digest(path.read_bytes())
    return files


def write_rulebook(pack_dir: Path, *, authority: Signer, vertical: str, policy_id: str, version: str,
                   content: dict[str, Any], jurisdictions: tuple[str, ...], name: str = "rulebook.json") -> str:
    document = document_policy(authority, vertical=vertical, policy_id=policy_id, version=version, content=content,
                               jurisdictions=jurisdictions, effective_from_us=NOW_US - 1)
    payload = {
        "vertical": document.vertical, "policy_id": document.policy_id, "version": document.version,
        "content": document.content, "jurisdictions": list(document.jurisdictions),
        "effective_from_us": document.effective_from_us, "effective_until_us": document.effective_until_us,
        "issued_by": document.issued_by, "supersedes": document.supersedes,
        "signature": {"key_id": document.signature.key_id, "alg": document.signature.alg, "value": document.signature.value},
    }
    _write(pack_dir / "rulebook" / name, json.dumps(payload, sort_keys=True, indent=2))
    return document.digest()


def write_cases(pack_dir: Path, cases: Mapping[str, Mapping[str, list[dict[str, Any]]]]) -> None:
    for check_id, by_category in cases.items():
        for category, entries in by_category.items():
            _write(pack_dir / "conformance" / category / f"{check_id.replace(':', '.')}.json",
                   json.dumps({"cases": entries}, indent=2))


def finish_pack(pack_dir: Path, manifest_body: dict[str, Any], *, publisher: Signer) -> PackManifest:
    """Index, write the manifest, sign the files, attest the build."""
    body = {**manifest_body, "schema": PACK_SCHEMA, "platform_contract": PLATFORM_CONTRACT, "files": _index(pack_dir)}
    manifest = manifest_from_dict(body)
    _write(pack_dir / "pack.json", json.dumps(body, sort_keys=True, indent=2))
    sign_pack(pack_dir, manifest, publisher)
    write_provenance(pack_dir, manifest, builder_id=BUILDER_ID, build_type=BUILD_TYPE,
                     external_parameters={"source": "factory.packs.examples", "pack": manifest.reference}, signer=publisher)
    return manifest


def refinish_pack(pack_dir: Path, *, publisher: Signer) -> PackManifest:
    """Re-index and re-sign a pack whose files changed (an attestation was added, a case edited)."""
    body = json.loads((pack_dir / "pack.json").read_text(encoding="utf-8"))
    body.pop("files", None)
    return finish_pack(pack_dir, body, publisher=publisher)


def build_education_pack(target: Path, *, publisher: Signer, rulebook_authority: Signer,
                         rulebook_content: dict[str, Any] | None = None, version: str = "0.1.0",
                         collections: list[dict[str, Any]] | None = None,
                         cases: Mapping[str, Mapping[str, list[dict[str, Any]]]] | None = None) -> PackManifest:
    target.mkdir(parents=True, exist_ok=True)
    _write(target / "schema" / "schema.json", json.dumps(EDUCATION_SCHEMA, sort_keys=True, indent=2))
    digest = write_rulebook(target, authority=rulebook_authority, vertical="education", policy_id="formative-feedback",
                            version="1.0.0", content=rulebook_content or EDUCATION_RULEBOOK, jurisdictions=("ZW", "ZA"))
    write_cases(target, cases or EDUCATION_CASES)
    _write(target / "kit" / "README.md", EDUCATION_KIT)
    _write(target / "exercises" / "geometry.json", json.dumps({"schema": "lumi.geometry-exercises/1", "exercises": [
        {"id": "triangle", "version": "1", "title": "Right triangle construction",
         "prompt": "Construct horizontal and vertical sides of 30 mm and 20 mm. Label the vertices, explain why the angle is right, and compare the measured diagonal with your calculation.",
         "validation": "Seed exercise; teacher validation pending", "response_schema": "lumi.geometry/1"},
        {"id": "circle-tangent", "version": "1", "title": "Technical drawing: circle and tangent",
         "prompt": "Draw a circle with radius 10 mm. Construct a radius and a tangent at its endpoint. Label the contact point and explain the angle between the tangent and radius. Keep construction lines visible.",
         "validation": "Seed exercise; technical-drawing teacher validation pending", "response_schema": "lumi.geometry/1"},
        {"id": "pythagoras", "version": "1", "title": "Maths: show why the diagonal fits",
         "prompt": "Construct a right triangle with sides 30 mm and 40 mm. Predict its diagonal using Pythagoras and record each calculation step. Then measure the diagonal and explain any difference.",
         "validation": "Seed exercise; maths teacher validation pending", "response_schema": "lumi.geometry/1"}
    ]}, sort_keys=True))
    body: dict[str, Any] = {
        "id": EDUCATION_ID, "version": version, "kind": "base", "domain": "education",
        "title": "Education: teacher-governed formative feedback", "publisher": "lumiwright",
        "jurisdictions": ["ZW", "ZA"], "license": "proprietary",
        "roots": ["education/formative-feedback"], "capability": "education-feedback",
        "scopes": [
            {"name": "learner-identity", "data_class": "pii", "rationale": "feedback is addressed to a named learner in a class roster"},
            {"name": "submission-media", "data_class": "pii", "rationale": "photographed work identifies the learner; needed to localise findings"},
            {"name": "guardian-contact", "data_class": "pii", "rationale": "released feedback is visible to the guardian by the school's rule"},
        ],
        "dependencies": [], "vocabularies": ["oneroster@1.2", "case@1.0", "caliper@1.2", "cds-hooks@2.0"],
        "experts": {"required_roles": EDUCATION_EXPERT_ROLES},
        "workflow": EDUCATION_WORKFLOW,
        "rulebook": {"ref": "education/formative-feedback@1.0.0", "digest": digest, "path": "rulebook/rulebook.json"},
        "knowledge": {"sources": EDUCATION_SOURCES},
        "collections": collections if collections is not None else EDUCATION_COLLECTIONS,
        "cards": {"source_label": "Education formative-feedback pack"},
        "commercial": {"capabilities": ["education-feedback"]},
        "conformance": {"expected_decisions": {
            "education:draft-feedback": "ALLOWED_WITH_NOTICE",
            "education:release-feedback": "SECOND_REVIEW without calibrated confidence or below 0.70; APPROVAL_REQUIRED otherwise",
            "education:record-progress": "APPROVAL_REQUIRED"}},
    }
    return finish_pack(target, body, publisher=publisher)


def build_reference_contrast_pack(target: Path, *, domain: str, publisher: Signer,
                                  rulebook_authority: Signer) -> PackManifest:
    """Build either researched contrast pack. Both are data-only and use host verifier capabilities."""
    if domain == "health":
        pack_id, capability = "lumiwright.health.patient-education", "health-patient-education"
        title, content_type = "Health: clinician-governed patient education", "health:patient-education"
        principal, resource, role = "Clinician", "PatientEducation", "clinician"
        action, data_class = "health:release-patient-education", "phi"
        checks = {
            "health:source-fidelity": {"kind": "deterministic", "version": "1",
                "capability": "evidence.approved-source-citations@1", "params": {}},
            "health:no-diagnosis-or-prescription": {"kind": "deterministic", "version": "1",
                "capability": "text.prohibited-terms@1", "params": {
                    "patterns": ["\\byou (have|definitely have)\\b", "\\b(start|stop|change) your (medicine|medication|dose)\\b"],
                    "reason": "CLINICAL_ACTION_LANGUAGE"}},
        }
        cases = {
            "health:source-fidelity": {"golden": [
                {"name": "approved", "draft": "Discuss this with your clinician.",
                 "contract": {"approved_sources": ["who-education"], "citations": ["who-education"]}, "expected": "pass"},
                {"name": "unapproved", "draft": "Advice", "contract": {"approved_sources": ["who-education"],
                 "citations": ["blog"]}, "expected": "fail", "expected_reasons": ["SOURCE_FIDELITY_UNPROVEN"]}]},
            "health:no-diagnosis-or-prescription": {"golden": [
                {"name": "bounded", "draft": "This explains your care plan; ask your clinician before changing medication.",
                 "contract": {}, "expected": "pass"},
                {"name": "prohibited", "draft": "Stop your medication today.", "contract": {}, "expected": "fail",
                 "expected_reasons": ["CLINICAL_ACTION_LANGUAGE"]}]},
        }
        sources = [
            {"id": "fhir-r5", "title": "HL7 FHIR R5", "kind": "standard", "edition": "5.0.0",
             "effective_date": "2023-03-26", "licence": "HL7", "jurisdiction": "global", "url": "https://hl7.org/fhir/R5/"},
            {"id": "cds-hooks", "title": "CDS Hooks", "kind": "standard", "edition": "2.0",
             "effective_date": "2022-01-01", "licence": "HL7", "jurisdiction": "global", "url": "https://cds-hooks.hl7.org/2.0/"},
        ]
        expert_roles = ["licensed-clinician", "clinical-safety-officer"]
    elif domain == "critical-infrastructure":
        pack_id, capability = "lumiwright.critical-infrastructure.operational-procedure", "critical-infrastructure-procedure"
        title, content_type = "Critical infrastructure: controlled operational procedure", "critical-infrastructure:procedure"
        principal, resource, role = "AuthorizedOperator", "OperationalProcedure", "authorized-operator"
        action, data_class = "critical-infrastructure:release-procedure", "confidential"
        checks = {
            "ot:controlled-revision": {"kind": "deterministic", "version": "1",
                "capability": "operations.controlled-revision@1", "params": {}},
            "ot:command-allowlist": {"kind": "deterministic", "version": "1",
                "capability": "operations.command-allowlist@1", "params": {}},
        }
        cases = {
            "ot:controlled-revision": {"golden": [
                {"name": "controlled", "draft": "Operator checklist", "contract": {
                    "controlled_document_id": "SOP-17", "controlled_revision": "rev-6"}, "expected": "pass"},
                {"name": "uncontrolled", "draft": "Operator checklist", "contract": {}, "expected": "fail",
                 "expected_reasons": ["CONTROLLED_REVISION_MISSING"]}]},
            "ot:command-allowlist": {"golden": [
                {"name": "approved", "draft": "Execute approved isolation.", "contract": {
                    "requested_commands": ["isolate-feeder-2"], "approved_commands": ["isolate-feeder-2"]}, "expected": "pass"},
                {"name": "unapproved", "draft": "Execute shutdown.", "contract": {
                    "requested_commands": ["shutdown-grid"], "approved_commands": ["isolate-feeder-2"]}, "expected": "fail",
                 "expected_reasons": ["UNAPPROVED_OPERATIONAL_COMMAND"]}]},
        }
        sources = [
            {"id": "nist-800-82r3", "title": "NIST SP 800-82 Rev. 3", "kind": "guidance", "edition": "rev-3",
             "effective_date": "2023-09-01", "licence": "public-domain", "jurisdiction": "US",
             "url": "https://csrc.nist.gov/pubs/sp/800/82/r3/final"},
            {"id": "nist-csf-2", "title": "NIST Cybersecurity Framework 2.0", "kind": "guidance", "edition": "2.0",
             "effective_date": "2024-02-26", "licence": "public-domain", "jurisdiction": "US",
             "url": "https://www.nist.gov/cyberframework"},
        ]
        expert_roles = ["ot-safety-engineer", "control-system-security-lead"]
    else:
        raise ValueError("reference contrast domain must be 'health' or 'critical-infrastructure'")

    target.mkdir(parents=True, exist_ok=True)
    schema = {"schema": SCHEMA_ID, "namespace": domain,
              "entity_types": {principal: {"parents": [], "roles": [role], "attributes": {"id": {"type": "string"}}},
                               resource: {"parents": [], "attributes": {"id": {"type": "string"}}}},
              "actions": {action: {"effect": "external", "applies_to": {"principal_types": [principal],
                                                                           "resource_types": [resource]},
                                   "context": {"nonce": {"type": "string"}}}}}
    _write(target / "schema" / "schema.json", json.dumps(schema, sort_keys=True, indent=2))
    rulebook = {"schema": RULEBOOK_SCHEMA, "content_types": [content_type], "data_classes": [data_class],
                "retention_years": 7, "checks": checks, "rules": {action: {"required_checks": list(checks),
                    "requires_lineage": True, "approval": {"role_groups": [[role]], "minimum_approvers": 1},
                    "card": {"indicator": "warning", "summary": f"Approve {title.lower()} release?",
                             "override_reasons": [{"code": "unsafe", "display": "The draft is unsafe or unsupported"}]}}},
                "prohibited_language": []}
    digest = write_rulebook(target, authority=rulebook_authority, vertical=domain, policy_id="release", version="1.0.0",
                            content=rulebook, jurisdictions=("global",))
    write_cases(target, cases)
    _write(target / "kit" / "README.md", f"# {title}\n\n## Journey\n\nDraft, deterministic checks, expert review, release receipt.\n\n"
           f"## Rulebook sources\n\nThe signed source lock names the standards used to shape this starter.\n\n## Approvers\n\nA {role} approves release.\n\n"
           "## Evidence\n\nEvery decision and release carries all nine authority pins.\n\n## Expert validation\n\nNot reached. Required roles are declared; no attestation is implied.\n")
    body: dict[str, Any] = {"id": pack_id, "version": "0.1.0", "kind": "base", "domain": domain, "title": title,
        "publisher": "lumiwright", "jurisdictions": ["global"], "license": "proprietary", "roots": [content_type.replace(":", "/")],
        "capability": capability, "scopes": [{"name": "governed-content", "data_class": data_class,
        "rationale": "the governed release contains domain-sensitive operational or personal information"}], "dependencies": [],
        "vocabularies": [], "experts": {"required_roles": expert_roles},
        "workflow": {"stages": [{"id": "draft", "trigger": "request", "action": None, "inputs": [], "outputs": ["draft"]},
                                {"id": "release", "trigger": "stage:draft", "action": action,
                                 "inputs": ["draft", "approval"], "outputs": ["release-receipt"]}]},
        "rulebook": {"ref": f"{domain}/release@1.0.0", "digest": digest, "path": "rulebook/rulebook.json"},
        "knowledge": {"sources": sources}, "collections": [],
        "conformance": {"expected_decisions": {action: "APPROVAL_REQUIRED after deterministic checks pass"}}}
    return finish_pack(target, body, publisher=publisher)


ZA_OVERLAY: dict[str, Any] = {
    "schema": OVERLAY_SCHEMA,
    "base": "education/formative-feedback@1.0.0",
    "jurisdiction": "ZA",
    "rules": {"education:release-feedback": {"second_review": {"below_confidence": "0.80"},
                                             "approval": {"expires_after_hours": 48}}},
    "prohibited_language": ["report card"],
}

ZA_KIT = """# South African overlay for the Education formative-feedback pack

## Journey

Inherits the base journey. Nothing is added to the stages; the overlay changes who must look and when.

## Rulebook sources

- Protection of Personal Information Act 4 of 2013 (POPIA): learner and guardian personal information is
  processed under the school's lawful basis; the overlay does not decide consent, it tightens review.
- The base pack's sources apply unchanged.

## Approvers

- Second review below calibrated confidence 0.80 (base: 0.70).
- A release approval lives 48 hours (base: 72).

## Evidence

Inherits the base receipt; the rulebook digest on the receipt is the EFFECTIVE (merged) rulebook.

## Expert validation

Required: a privacy officer attesting the overlay against POPIA. Not yet performed.
"""


def build_za_overlay(target: Path, *, base: PackManifest, publisher: Signer, overlay_authority: Signer,
                     overlay_content: dict[str, Any] | None = None) -> PackManifest:
    target.mkdir(parents=True, exist_ok=True)
    digest = write_rulebook(target, authority=overlay_authority, vertical="education", policy_id="formative-feedback.za",
                            version="1.0.0", content=overlay_content or ZA_OVERLAY, jurisdictions=("ZA",), name="overlay.json")
    _write(target / "kit" / "README.md", ZA_KIT)
    body: dict[str, Any] = {
        "id": f"{EDUCATION_ID}.za", "version": "0.1.0", "kind": "overlay", "domain": "education",
        "title": "Education formative feedback: South Africa overlay", "publisher": "lumiwright", "jurisdictions": ["ZA"],
        "license": "proprietary", "roots": ["education/formative-feedback/za"], "capability": "education-feedback",
        "scopes": [], "dependencies": [base.reference], "vocabularies": [], "experts": {"required_roles": ["privacy-officer"]},
        "workflow": {"inherits": True},
        "rulebook": {"ref": "education/formative-feedback.za@1.0.0", "digest": digest, "path": "rulebook/overlay.json",
                     "base": "education/formative-feedback@1.0.0"},
        "knowledge": {"sources": ZA_SOURCES},
        "conformance": {"expected_decisions": {"education:release-feedback": "SECOND_REVIEW below 0.80; APPROVAL_REQUIRED otherwise"}},
    }
    return finish_pack(target, body, publisher=publisher)


def attest_pack(pack_dir: Path, *, publisher: Signer, expert: Signer, role: str, name: str, credential: str, issuer: str,
                reviewed_at: str, expires_at: str, findings: tuple[str, ...] = ()) -> PackManifest:
    """Write one expert attestation over the pack's rulebook as it is now, then re-index and re-sign the pack."""
    overlay = pack_dir / "rulebook" / "overlay.json"
    raw = json.loads((overlay if overlay.is_file() else pack_dir / "rulebook" / "rulebook.json").read_text(encoding="utf-8"))
    pack_id = str(json.loads((pack_dir / "pack.json").read_text(encoding="utf-8"))["id"])
    attestation = sign_attestation(expert, pack=pack_id, surface="rulebook", surface_digest=content_digest(raw["content"]),
                                   expert_name=name, expert_role=role, credential=credential, credential_issuer=issuer,
                                   reviewed_at=reviewed_at, expires_at=expires_at, findings=findings)
    write_attestation(pack_dir, attestation)
    return refinish_pack(pack_dir, publisher=publisher)


def build_minimal_pack(target: Path, *, domain: str, publisher: Signer, rulebook_authority: Signer,
                       pack_id: str | None = None) -> PackManifest:
    """The fourth pack: the least a domain needs to be governed. A reviewer role, a note, a release."""
    target.mkdir(parents=True, exist_ok=True)
    schema = {
        "schema": SCHEMA_ID, "namespace": domain,
        "entity_types": {"Reviewer": {"parents": [], "roles": ["reviewer"], "attributes": {"id": {"type": "string"}}},
                         "Note": {"parents": [], "attributes": {"id": {"type": "string"}}}},
        "actions": {f"{domain}:release-note": {"effect": "external",
                                               "applies_to": {"principal_types": ["Reviewer"], "resource_types": ["Note"]},
                                               "context": {"nonce": {"type": "string"}}}},
    }
    _write(target / "schema" / "schema.json", json.dumps(schema, sort_keys=True, indent=2))
    rulebook = {
        "schema": RULEBOOK_SCHEMA, "content_types": [f"{domain}:note"], "data_classes": ["internal"],
        "retention_years": 1,
        "checks": {"demo:present": {"kind": "deterministic", "version": "1", "capability": "text.non-empty@1", "params": {"reason": "EMPTY"}}},
        "rules": {f"{domain}:release-note": {
            "required_checks": ["demo:present"], "requires_lineage": True,
            "approval": {"role_groups": [["reviewer"]], "minimum_approvers": 1},
            "card": {"indicator": "info", "summary": "Release this note?",
                     "override_reasons": [{"code": "not-ready", "display": "Not ready"}]}}},
        "prohibited_language": [],
    }
    digest = write_rulebook(target, authority=rulebook_authority, vertical=domain, policy_id="release-note", version="1.0.0",
                            content=rulebook, jurisdictions=("global",))
    write_cases(target, {"demo:present": {"golden": [
        {"name": "present", "draft": "hello", "contract": {}, "expected": "pass"},
        {"name": "empty", "draft": "   ", "contract": {}, "expected": "fail", "expected_reasons": ["EMPTY"]}]}})
    _write(target / "kit" / "README.md", "# Demo kit\n\n## Journey\n\nx\n\n## Rulebook sources\n\nx\n\n## Approvers\n\nx\n\n"
                                          "## Evidence\n\nx\n\n## Expert validation\n\nnone yet\n")
    body: dict[str, Any] = {
        "id": pack_id or f"lumiwright.{domain}.notes", "version": "0.1.0", "kind": "base", "domain": domain,
        "title": f"{domain} notes", "publisher": "lumiwright", "jurisdictions": ["global"], "license": "proprietary",
        "roots": [f"{domain}/notes"], "capability": f"{domain}-notes", "scopes": [], "dependencies": [], "vocabularies": [],
        "experts": {"required_roles": []},
        "workflow": {"stages": [{"id": "draft", "trigger": "note-drafted", "action": None, "inputs": [], "outputs": ["note"]},
                                {"id": "release", "trigger": "stage:draft", "action": f"{domain}:release-note",
                                 "inputs": ["note"], "outputs": ["receipt"]}]},
        "rulebook": {"ref": f"{domain}/release-note@1.0.0", "digest": digest, "path": "rulebook/rulebook.json"},
        "knowledge": {"sources": [{"id": "house-style", "title": f"{domain} house style", "kind": "organization-policy",
                                   "edition": "2026-09", "effective_date": "2026-09-01", "licence": "internal",
                                   "jurisdiction": "global", "url": ""}]},
        "collections": [],
        "conformance": {"expected_decisions": {f"{domain}:release-note": "APPROVAL_REQUIRED"}},
    }
    return finish_pack(target, body, publisher=publisher)


__all__ = ["BUILDER_ID", "BUILD_TYPE", "EDUCATION_CASES", "EDUCATION_COLLECTIONS", "EDUCATION_EXPERT_ROLES", "EDUCATION_ID",
           "EDUCATION_KIT", "EDUCATION_RULEBOOK", "EDUCATION_SCHEMA", "EDUCATION_SOURCES", "EDUCATION_WORKFLOW", "NOW_US",
           "ZA_OVERLAY", "ZA_SOURCES", "attest_pack", "build_education_pack", "build_reference_contrast_pack",
           "build_minimal_pack", "build_za_overlay",
           "finish_pack", "refinish_pack", "write_cases", "write_rulebook"]
