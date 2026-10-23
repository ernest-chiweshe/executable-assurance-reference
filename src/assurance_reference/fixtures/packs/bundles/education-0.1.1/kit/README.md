# Education formative-feedback pack: the starting kit

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
