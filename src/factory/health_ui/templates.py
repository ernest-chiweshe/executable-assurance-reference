"""Document templates, and the synthetic material used to demonstrate them.

One engine, two templates. A consultation note and a psychiatric medico-legal
report differ in their sections and their sources, not in how the work is done,
which is the point: a third template is a declaration rather than a build.

All demonstration material here is INVENTED. It is written to be clinically and
procedurally realistic while corresponding to no real person, case, or record.
"""
from __future__ import annotations

from factory.health_ui.documents import (
    DOCUMENTARY,
    OBSERVATION,
    OPINION,
    PATIENT_REPORTED,
    SectionSpec,
    Template,
    WITNESS,
)

# ---------------------------------------------------------------------------
# Consultation note
# ---------------------------------------------------------------------------

CONSULTATION = Template(
    template_id="consultation-note",
    name="Consultation note",
    blurb="A structured note from a recorded consultation, every line traceable "
          "to what was said.",
    subject_word="patient",
    sections=(
        SectionSpec(
            "Subjective",
            "What the patient reported.",
            from_kinds=("transcript",),
            speaker="patient",
            evidence_class=PATIENT_REPORTED,
        ),
        SectionSpec(
            "Objective",
            "Examination and measured findings.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("examination", "examined", "blood pressure", "pulse",
                  "temperature", "reflexes", "straight leg", "auscultation",
                  "tenderness", "observations", "saturation", "weight"),
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "Assessment",
            "Clinical impression. Review this before signing.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("impression", "consistent with", "likely", "suggests",
                  "differential"),
            evidence_class=OPINION,
        ),
        SectionSpec(
            "Plan",
            "What was agreed and arranged.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("advise", "recommend", "refer", "review", "prescribe",
                  "arrange", "follow up", "book", "continue", "modified"),
            evidence_class=OBSERVATION,
        ),
    ),
)

# ---------------------------------------------------------------------------
# Psychiatric medico-legal report
# ---------------------------------------------------------------------------

MEDICO_LEGAL = Template(
    template_id="psychiatric-medico-legal",
    name="Psychiatric medico-legal report",
    blurb="An expert report for legal proceedings, with every paragraph marked "
          "as patient-reported, witness, documentary, observation or opinion.",
    subject_word="examinee",
    sections=(
        SectionSpec(
            "Instructions and purpose",
            "Who instructed the report and the questions to be answered.",
            from_kinds=("instruction",),
            evidence_class=DOCUMENTARY,
        ),
        SectionSpec(
            "Expert qualifications and declaration",
            "Your qualifications, duty to the court, and declaration. "
            "Clinician-authored.",
        ),
        SectionSpec(
            "Sources reviewed",
            "Every source this report is drawn from.",
            index=True,
        ),
        SectionSpec(
            "Relevant personal, medical and psychiatric history",
            "Background before the index event.",
            from_kinds=("medical",),
            evidence_class=DOCUMENTARY,
        ),
        SectionSpec(
            "Account of the incident and detention",
            "The examinee's own account.",
            from_kinds=("transcript",),
            speaker="patient",
            cues=("collect", "package", "delivery", "stopped", "officers",
                  "arrest", "arrested", "cell", "custody", "detained",
                  "detention", "remand", "charged", "released", "prison"),
            evidence_class=PATIENT_REPORTED,
        ),
        SectionSpec(
            "Corroborating witness and documentary evidence",
            "Independent material bearing on the account.",
            from_kinds=("witness", "record", "investigation"),
            evidence_class=WITNESS,
        ),
        SectionSpec(
            "Post-incident symptoms and functional consequences",
            "Symptoms and their effect on daily and working life.",
            from_kinds=("transcript", "employment"),
            cues=("nightmare", "flashback", "sleep", "startle", "avoid",
                  "anxious", "anxiety", "panic", "low", "depressed", "mood",
                  "concentrate", "irritable", "withdraw", "work", "shift",
                  "employment", "absence", "driving", "hypervigilant"),
            evidence_class=PATIENT_REPORTED,
        ),
        SectionSpec(
            # A claim turns on loss as well as diagnosis. Without this the
            # earnings evidence reached no section at all, which is how the
            # unplaced list found it.
            "Effect on work and earnings",
            "What the documentary record shows about lost work.",
            from_kinds=("employment",),
            evidence_class=DOCUMENTARY,
        ),
        SectionSpec(
            "Mental-state examination",
            "Your observations at interview. Clinician-authored.",
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "Psychometric findings",
            "Scores and instruments, where administered.",
            from_kinds=("medical",),
            cues=("pcl-5", "pcl5", "phq-9", "phq9", "gad-7", "gad7", "score",
                  "scale", "questionnaire"),
            evidence_class=DOCUMENTARY,
        ),
        SectionSpec(
            "Diagnosis and differential diagnosis",
            "Your diagnostic formulation. Clinician-authored.",
            evidence_class=OPINION,
        ),
        SectionSpec(
            "Causation and contributing factors",
            "Your reasoning on causation. Clinician-authored.",
            evidence_class=OPINION,
        ),
        SectionSpec(
            "Treatment needs and prognosis",
            "Recommended treatment and expected course. Clinician-authored.",
            evidence_class=OPINION,
        ),
        SectionSpec(
            "Expert opinion, limitations and unanswered questions",
            "Your opinion, what you could not assess, and what remains open. "
            "Clinician-authored.",
            evidence_class=OPINION,
        ),
    ),
)

# ---------------------------------------------------------------------------
# Documents written FROM the same consultation
# ---------------------------------------------------------------------------

PATIENT_LETTER = Template(
    template_id="patient-explainer",
    name="Patient explainer letter",
    blurb="Plain-language summary for the patient, in their own words back to "
          "them.",
    subject_word="patient",
    sections=(
        SectionSpec(
            # Named for what it actually contains. The lines below are the
            # patient's verbatim words, and a heading that implied the letter
            # had paraphrased them would misdescribe the page.
            "What you told me",
            "Your own words from the consultation, unchanged.",
            from_kinds=("transcript",),
            speaker="patient",
            evidence_class=PATIENT_REPORTED,
        ),
        SectionSpec(
            "What I found",
            "Examination findings explained plainly.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("examination", "examined", "blood pressure", "pulse",
                  "temperature", "reflexes", "straight leg", "tenderness",
                  "impression", "consistent with"),
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "What happens next",
            "The plan, as the patient needs to understand it.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("advise", "recommend", "refer", "review", "prescribe",
                  "arrange", "follow up", "book", "continue", "modified",
                  "come back", "see you"),
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "Anything you should watch for",
            "Safety-netting. Write this in your own words.",
        ),
    ),
)

REFERRAL = Template(
    template_id="referral-letter",
    name="Referral letter",
    blurb="A letter to a colleague, drawn from the same consultation.",
    subject_word="patient",
    sections=(
        SectionSpec(
            "Reason for referral",
            "Why you are referring. Write this in your own words.",
            evidence_class=OPINION,
        ),
        SectionSpec(
            "History",
            "What the patient reported.",
            from_kinds=("transcript",),
            speaker="patient",
            evidence_class=PATIENT_REPORTED,
        ),
        SectionSpec(
            "Examination and findings",
            "What you found.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("examination", "examined", "blood pressure", "pulse",
                  "temperature", "reflexes", "straight leg", "tenderness",
                  "saturation", "weight", "chest"),
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "Management so far",
            "What has already been arranged.",
            from_kinds=("transcript",),
            speaker="clinician",
            cues=("advise", "recommend", "prescribe", "arrange", "continue",
                  "modified", "refer", "review"),
            evidence_class=OBSERVATION,
        ),
        SectionSpec(
            "What I am asking for",
            "The specific question for your colleague. Your words.",
            evidence_class=OPINION,
        ),
    ),
)


TEMPLATES = {t.template_id: t for t in (
    CONSULTATION, PATIENT_LETTER, REFERRAL, MEDICO_LEGAL,
)}


# ---------------------------------------------------------------------------
# Synthetic material
# ---------------------------------------------------------------------------

CONSULT_TRANSCRIPT = """Clinician: Good morning, what's brought you in today?
Patient: I've had this ache in my lower back for about three weeks now.
Patient: It's worse in the mornings and it hurts when I bend forward.
Clinician: Any numbness or weakness going down your legs?
Patient: No numbness, but I'm tired all the time and my sleep is poor because of the pain.
Clinician: Have you started any new activity recently?
Patient: I started a new job in a warehouse about a month ago, lots of lifting.
Clinician: On examination there is tenderness over the lumbar paraspinal muscles.
Clinician: Straight leg raise is negative bilaterally and reflexes are normal.
Clinician: Blood pressure is 128 over 78 and temperature is normal.
Clinician: My impression is this is consistent with mechanical low back pain related to the lifting.
Clinician: I advise regular paracetamol and a short course of gentle mobilisation.
Clinician: I'll refer you to physiotherapy and I'd like to review you in four weeks.
Patient: Should I stay off work?
Clinician: I recommend modified duties rather than complete rest, and we'll review that at follow up."""


ML_INSTRUCTION = """Ferrand & Osei Solicitors, 14 Bridgegate, instructing on behalf of Mr K. Adeyemi.

We act for Mr Adeyemi in a claim for wrongful arrest and false imprisonment against the Chief Constable. We instruct you to prepare a psychiatric report addressing the following questions.

1. Does Mr Adeyemi suffer from a recognised psychiatric injury, and if so what is the diagnosis?

2. If a psychiatric injury is present, was it caused or materially contributed to by the arrest and detention on 3 March 2026?

3. What treatment does he require, over what period, and at what cost?

4. What is the prognosis, and to what extent is any impairment likely to be permanent?

5. To what extent do any pre-existing factors or subsequent events contribute to his present condition?

Please note your duty is to the court. Dated 11 June 2026."""


ML_INTERVIEW = """Psychiatrist: Thank you for coming in. Can you tell me in your own words what happened?
Patient: I drive for a delivery app. On 3 March 2026 I got a job like any other, collect a package from an address and take it across town.
Patient: I never open the packages, that's the rule, you just collect and deliver.
Patient: When I got to the drop-off there were officers waiting and they stopped the car straight away.
Patient: They said the package had drugs in it. I kept telling them I only collected it, I didn't know what was inside.
Patient: I was arrested at the roadside in front of people I knew. That's the part I still see.
Patient: I was held in a cell overnight and then remanded. I was in prison for eleven weeks before it was dropped.
Patient: The investigation found the sender's records and the app logs showing I never opened it, and the charges were dropped on 21 May 2026.
Psychiatrist: How have you been since your release?
Patient: I get nightmares about the cell most nights. I wake up soaked and then I can't get back to sleep.
Patient: I get flashbacks when I see a police car, my chest goes tight and I have to pull over.
Patient: I avoid that whole part of town now. I won't take jobs that go near there.
Patient: I'm irritable with my wife and I've withdrawn from my friends because of the shame of it.
Patient: I can't concentrate. I used to do twelve hour shifts and now I manage about four before I have to stop.
Patient: I stopped driving for the app for two months entirely because I was too anxious to take a package from anyone.
Psychiatrist: Had you any mental health difficulties before this?
Patient: Never. I've never seen a psychiatrist in my life before this."""


ML_WITNESS = """Witness statement of Mrs A. Adeyemi, spouse, dated 2 July 2026.

Before 3 March 2026 my husband was an outgoing man who worked long hours without complaint and was close to his brothers.

Since his release he wakes most nights shouting. I have found him sitting on the kitchen floor at three in the morning on several occasions.

He will not drive past the area where he was arrested. On 14 June 2026 he turned the car around rather than pass it and would not explain why until later that evening.

He has stopped attending family gatherings. He says he cannot face people asking about the case."""


ML_RECORDS = """Custody record extract, Central Police Station.

Detained person booked into custody at 19:42 on 3 March 2026. Released into court custody on 4 March 2026.

Crown Court remand record: defendant remanded 4 March 2026. Charges discontinued and defendant released on 21 May 2026.

Total period in custody: seventy-nine days."""


ML_MEDICAL = """GP and psychiatric records summary.

Records reviewed from 2019 to present. No prior psychiatric history, no prior referral to mental health services, and no psychotropic prescribing before June 2026.

First presentation to GP on 2 June 2026 reporting nightmares, poor sleep and intrusive memories of arrest. Sertraline 50mg commenced 9 June 2026.

PCL-5 administered 20 June 2026, score 58, consistent with severe post-traumatic stress symptoms.

PHQ-9 administered 20 June 2026, score 17, consistent with moderately severe depressive symptoms."""


ML_EMPLOYMENT = """Employment and functional evidence.

Platform earnings records show average weekly earnings of GBP 640 in the six months to February 2026.

No earnings recorded between 3 March 2026 and 28 May 2026 during the period in custody.

Earnings from June 2026 onward average GBP 210 per week, reflecting reduced hours.

Employer reference letter dated 30 June 2026 notes he declined night shifts he had previously accepted."""


ML_INVESTIGATION = """Investigation findings, disclosed in proceedings.

Analysis of the delivery platform's records confirmed the collection job was assigned automatically and that the package was sealed at collection.

Sender was identified and charged separately. Documentation confirms no contact between the sender and Mr Adeyemi beyond the automated assignment.

The reviewing officer recorded on 19 May 2026 that there was no evidence Mr Adeyemi knew the contents of the package."""


#: Sources pre-loaded for the medico-legal demonstration.
ML_SOURCES = (
    ("instruction", "Letter of instruction", "Ferrand & Osei Solicitors",
     "11 June 2026", ML_INSTRUCTION),
    ("transcript", "Psychiatric interview", "Examining psychiatrist",
     "9 July 2026", ML_INTERVIEW),
    ("witness", "Witness statement — spouse", "Mrs A. Adeyemi",
     "2 July 2026", ML_WITNESS),
    ("record", "Custody and remand records", "Central Police Station",
     "4 March 2026", ML_RECORDS),
    ("medical", "GP and psychiatric records", "Primary care record",
     "20 June 2026", ML_MEDICAL),
    ("employment", "Employment and earnings evidence", "Platform records",
     "30 June 2026", ML_EMPLOYMENT),
    ("investigation", "Investigation findings", "Disclosed in proceedings",
     "19 May 2026", ML_INVESTIGATION),
)


# The expert's own sections, written for the worked sample so the case can be
# walked from the conversation to a finished court report. These are PART OF
# THE SAMPLE, in the same sense as the invented witness statement — the system
# does not write expert opinion, and a real case starts with these empty and
# cannot be signed until the expert fills them. The document says so on its
# face; see `Document.sample_note`.
ML_WORKED_OPINION: tuple[tuple[str, str], ...] = (
    (
        "Expert qualifications and declaration",
        "I am a consultant psychiatrist, MRCPsych, on the GMC specialist "
        "register for general adult psychiatry, and I have prepared reports "
        "for the civil courts since 2014. I understand that my duty is to the "
        "court and that it overrides any obligation to the party instructing "
        "me. I have complied with that duty and confirm that the opinions "
        "below are my own and within my expertise.",
    ),
    (
        "Mental-state examination",
        "On examination Mr Adeyemi was alert and fully oriented. He was "
        "guarded at the outset and became tearful when describing the arrest "
        "at the roadside, recovering his composure without prompting. Speech "
        "was normal in rate and form. Mood was subjectively low and "
        "objectively depressed with reactive affect. There was no evidence of "
        "psychotic phenomena, no thought disorder, and no active suicidal "
        "ideation, plan or intent. Cognition was grossly intact. Insight was "
        "good; he attributes his symptoms to the detention and is willing to "
        "engage in treatment.",
    ),
    (
        "Diagnosis and differential diagnosis",
        "In my opinion Mr Adeyemi meets the diagnostic criteria for "
        "post-traumatic stress disorder (ICD-11 6B40), with a comorbid "
        "moderate depressive episode (ICD-11 6A71.1). The intrusion symptoms "
        "(nightmares, flashbacks on seeing a police vehicle), the avoidance "
        "(of the area of the arrest and of collection work), and the "
        "persistent sense of current threat are each present and have lasted "
        "well beyond one month. I considered an adjustment disorder and "
        "rejected it: the symptom picture is too specific and too severe, and "
        "the PCL-5 score of 58 is consistent with severe post-traumatic "
        "symptoms rather than an adjustment reaction.",
    ),
    (
        "Causation and contributing factors",
        "In my opinion the arrest on 3 March 2026 and the ensuing seventy-nine "
        "days in custody are the material cause of both conditions. The "
        "records disclose no psychiatric history, no prior referral to mental "
        "health services and no psychotropic prescribing before June 2026, so "
        "there is no pre-existing vulnerability of which I am aware. I am not "
        "aware of any intervening traumatic event. The public nature of the "
        "arrest, in front of people known to him, and the shame he describes "
        "in consequence, are in my opinion aggravating features rather than "
        "separate causes. Had the detention not occurred, I do not consider "
        "that these conditions would have arisen when they did.",
    ),
    (
        "Treatment needs and prognosis",
        "Mr Adeyemi requires trauma-focused cognitive behavioural therapy, in "
        "the order of sixteen sessions with a therapist experienced in "
        "post-traumatic presentations, and continuation of sertraline under "
        "review for at least twelve months. At present rates this equates to "
        "approximately £2,400 for the psychological treatment. With that "
        "treatment I consider the prognosis good and would expect substantial "
        "recovery within twelve to eighteen months. Without it I would expect "
        "the avoidance to entrench and his working capacity to remain "
        "impaired. I do not consider that any impairment is likely to be "
        "permanent, although a residual sensitivity to police contact may "
        "persist.",
    ),
    (
        "Expert opinion, limitations and unanswered questions",
        "In summary: Mr Adeyemi suffers from post-traumatic stress disorder "
        "with a comorbid moderate depressive episode; the detention is the "
        "material cause; treatment is available and the prognosis with it is "
        "good. My opinion is subject to the following limitations. I have not "
        "seen the custody CCTV and my comments on the conditions of detention "
        "rest on his account and the custody record alone. I have not been "
        "provided with records from any employer other than the delivery "
        "platform. I have examined Mr Adeyemi on one occasion. Should further "
        "material become available I reserve the right to revise this "
        "opinion.",
    ),
)
