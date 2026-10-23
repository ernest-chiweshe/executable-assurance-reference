"""Working out who said what, so the clinician does not have to say so.

A doctor cannot stop an examination to tell a computer whose turn it is. Asking
them to is the fastest way to make a consultation feel like data entry, which
is the exact thing this product exists to remove. So attribution is inferred
and then offered for correction, rather than demanded up front.

Two signals, deliberately separate:

* **Voice**, measured in the browser. Two people in a room have two pitches,
  and turns cluster into two groups without knowing anything about language.
  That runs where the microphone is and never reaches this process.

* **Language**, decided here. Clinical speech is strongly asymmetric. "On
  examination there is tenderness" is not something a patient says, and "it
  hurts when I bend" is not something a clinician says about themselves. This
  module scores that asymmetry.

Language is the arbiter when the two disagree, because pitch separates two
voices but cannot say which is the doctor, while a sentence about performing an
examination can. Where language is silent the voice grouping stands.

Neither signal is trusted to be right. Every turn stays correctable in one
click, and the note redraws from the correction — the design assumes it will
get some turns wrong and makes that cheap, rather than pretending it will not.
"""
from __future__ import annotations

import re

CLINICIAN = "clinician"
PATIENT = "patient"

# Things only the person conducting the consultation says. Weighted higher
# than the patient cues because they are less ambiguous: a patient may narrate
# an examination they were given, but they do not perform one.
_CLINICIAN_PHRASES = (
    ("on examination", 4), ("examination reveals", 4), ("i examined", 4),
    ("my impression", 4), ("the impression is", 4), ("differential", 3),
    ("i advise", 4), ("i recommend", 4), ("i'd like to review", 4),
    ("i will review", 3), ("i'll review", 3), ("i'll refer", 4),
    ("i am referring", 4), ("i'm referring", 4), ("i'll arrange", 4),
    ("i will arrange", 4), ("i'll start", 3), ("i'm giving you", 4),
    ("i'd like to", 3), ("we'll", 2), ("let's", 2),
    ("blood pressure is", 4), ("pulse", 2), ("saturation", 3),
    ("temperature is", 3), ("reflexes", 3), ("tenderness", 3),
    ("palpation", 3), ("auscultation", 3), ("percussion", 3),
    ("radiograph", 3), ("the scan shows", 3), ("test is positive", 3),
    ("consistent with", 3), ("prognosis", 3), ("diagnosis", 3),
    ("prescribe", 3), ("milligrams", 2), ("dose", 2),
    ("what's brought you in", 4), ("what brings you in", 4),
    ("tell me about", 3), ("tell me more", 3), ("how have you been", 3),
    ("have you tried", 3), ("any numbness", 3), ("any swelling", 3),
    ("do you have any", 2), ("are you taking", 3), ("had you any", 3),
    ("thank you for coming", 3), ("come back if", 3), ("follow up", 2),
    # Directing the other person, and announcing what is about to be done.
    ("tell me", 3), ("show me", 3), ("let me", 3), ("i'll ", 2), ("i will ", 2),
    ("i'm going to", 3), ("i am going to", 3), ("today i", 3),
    ("antibiotic", 3), ("treatment", 2), ("referral", 3), ("clinic", 2),
    ("no spreading", 3), ("would not help", 2),
)

# Things only the person being seen says. First-person symptom reporting.
_PATIENT_PHRASES = (
    ("i've had", 4), ("i have had", 4), ("it hurts", 4), ("it aches", 4),
    ("the pain", 3), ("my pain", 4), ("it wakes me", 4), ("i can't sleep", 4),
    ("i wake", 3), ("i've been", 3), ("i feel", 3), ("i felt", 3),
    ("i get", 2), ("i stopped", 3), ("i started", 2), ("i take", 2),
    ("i'm tired", 3), ("i can't", 3), ("i couldn't", 3), ("i struggle", 3),
    ("my shoulder", 3), ("my back", 3), ("my chest", 3), ("my wife", 3),
    ("my husband", 3), ("my job", 3), ("my sleep", 3), ("my leg", 3),
    ("should i", 4), ("do i need", 4), ("will it", 3), ("what does that mean", 4),
    ("it started", 3), ("it comes on", 3), ("it settles", 3),
    ("worse when", 2), ("kept me awake", 4), ("never had", 3),
    # Reporting a symptom as something one HAS.
    ("i've got", 4), ("i got", 3), ("i had", 2),
    ("what does that mean", 6), ("am i", 4),
)

# The person conducting a consultation asks the questions. The exception is the
# patient asking about THEMSELVES — "should I stay off work?", "do I need
# antibiotics?" — so a question carrying a first-person subject earns no
# clinician credit and is left to the phrase cues. That one rule replaces
# several phrases that would otherwise each have to be listed.
_QUESTION = re.compile(r"\?\s*$")
_FIRST_PERSON = re.compile(r"\b(i|i'm|i've|i'd|i'll|me|my|mine)\b",
                           re.IGNORECASE)


def score(text: str) -> int:
    """How strongly a line reads as the clinician (positive) or patient (negative).

    Zero means the language does not say. That is a real answer and must not be
    rounded into a guess: it is the case where the voice grouping should decide.
    """

    low = " " + " ".join(text.lower().split()) + " "
    total = 0
    for phrase, weight in _CLINICIAN_PHRASES:
        if phrase in low:
            total += weight
    for phrase, weight in _PATIENT_PHRASES:
        if phrase in low:
            total -= weight

    if _QUESTION.search(text) and not _FIRST_PERSON.search(text):
        total += 3
    return total


def guess(text: str) -> str | None:
    """The speaker the language implies, or None when it implies nothing."""

    value = score(text)
    if value >= 2:
        return CLINICIAN
    if value <= -2:
        return PATIENT
    return None


#: Below this, the language evidence separating the two voices is too thin to
#: act on quietly. Two groups whose scores are this close have not been told
#: apart by what was said; they have been told apart by a coin.
CONFIDENT = 6


def confidence(lines: list[str], voice_groups: list[int] | None = None) -> int:
    """How firmly the language separates the two voices. 0 means it does not.

    Reported so the interface can ASK once — "which of these is you?" — rather
    than assert a coin-flip and leave a clinician to discover it in the note.
    """

    if not (voice_groups and len(voice_groups) == len(lines)):
        return 0
    totals: dict[int, int] = {}
    for group, text in zip(voice_groups, lines):
        totals[group] = totals.get(group, 0) + score(text)
    if len(totals) < 2:
        return 0
    ranked = sorted(totals.values(), reverse=True)
    return ranked[0] - ranked[1]


def attribute(lines: list[str], voice_groups: list[int] | None = None,
              ) -> list[str]:
    """Assign a speaker to every line.

    `voice_groups` is the browser's acoustic clustering: one group number per
    line, or None when there was no microphone (a pasted transcript). The two
    signals are combined per group rather than per line, because a single
    confident sentence tells you which voice the whole group belongs to and a
    per-line decision would let one ambiguous sentence flip mid-conversation.
    """

    if not lines:
        return []

    if voice_groups and len(voice_groups) == len(lines):
        # Sum the language evidence within each acoustic group. The group with
        # the higher total is the clinician; one clear sentence anywhere in a
        # group settles every line in it.
        totals: dict[int, int] = {}
        for group, text in zip(voice_groups, lines):
            totals[group] = totals.get(group, 0) + score(text)
        if len(totals) >= 2:
            ranked = sorted(totals, key=lambda g: totals[g], reverse=True)
            role = {ranked[0]: CLINICIAN}
            for other in ranked[1:]:
                role[other] = PATIENT
            return [role[g] for g in voice_groups]

    # No usable voice grouping: decide line by line, and let a line the
    # language cannot place inherit the previous speaker, because consecutive
    # sentences are usually the same person still talking.
    out: list[str] = []
    previous = CLINICIAN            # a consultation is opened by the clinician
    for text in lines:
        who = guess(text) or previous
        out.append(who)
        previous = who
    return out
