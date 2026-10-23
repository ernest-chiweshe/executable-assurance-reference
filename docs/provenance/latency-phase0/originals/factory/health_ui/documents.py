"""Clinical document workspace: templates, evidence, traceable drafting.

The unit of work is a DOCUMENT a clinician has to produce, not a note format.
A consultation note and a medico-legal report are the same machine with
different templates, because the doctor's job is "produce this document from
this material", and the material differs far more than the process does.

Three things carry the clinical weight:

* **Evidence class is visible per paragraph.** A reader must be able to tell
  patient-reported material from witness evidence, documentary fact, clinician
  observation and expert opinion. In a report that goes to court, conflating
  them is the failure that discredits the whole document.

* **A citation means the words came from that source.** When a clinician
  rewrites a paragraph it becomes CLINICIAN-AUTHORED and its extracted
  citations are dropped, because keeping them would assert that a source says
  something it does not. That is false traceability and it is worse than no
  traceability at all.

* **Signing freezes a document the clinician has already read.** The draft is
  fully renderable and exportable before signature; what signing changes is
  that the exact bytes become fixed and attributed.

NOT IN SCOPE: no diagnosis, no prescribing, no treatment decision, and no
opinion of its own. Expert opinion paragraphs are always clinician-authored.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

#: How a statement is known. Rendered on every paragraph.
PATIENT_REPORTED = "patient-reported"
WITNESS = "witness-evidence"
DOCUMENTARY = "documentary-fact"
OBSERVATION = "clinician-observation"
OPINION = "expert-opinion"

EVIDENCE_CLASSES = (
    PATIENT_REPORTED, WITNESS, DOCUMENTARY, OBSERVATION, OPINION,
)

EVIDENCE_LABEL = {
    PATIENT_REPORTED: "Patient-reported",
    WITNESS: "Witness evidence",
    DOCUMENTARY: "Documentary fact",
    OBSERVATION: "Clinician observation",
    OPINION: "Expert opinion",
}

#: Source kinds a clinician can add to a case.
SOURCE_KINDS = {
    "transcript": "Interview transcript",
    "witness": "Witness statement",
    "record": "Official record",
    "medical": "Medical / psychiatric record",
    "employment": "Employment / functional evidence",
    "investigation": "Investigation finding",
    "instruction": "Letter of instruction",
    "joint-minute": "Expert joint minute",
    "sketch": "Clinician sketch",
    "other": "Other supporting document",
}

#: Which evidence class a source kind yields by default.
_KIND_EVIDENCE = {
    "transcript": PATIENT_REPORTED,
    "witness": WITNESS,
    "record": DOCUMENTARY,
    "medical": DOCUMENTARY,
    "employment": DOCUMENTARY,
    "investigation": DOCUMENTARY,
    "instruction": DOCUMENTARY,
    "joint-minute": DOCUMENTARY,
    "sketch": OBSERVATION,
    "other": DOCUMENTARY,
}


@dataclass(frozen=True)
class SketchAsset:
    """An immutable, validated image captured by the clinician.

    PNG bytes are base64-encoded only because the current durable store is
    JSON.  ``digest`` binds the exact bytes into any document that cites the
    sketch; width and height come from the PNG header, never from the client.
    """

    png_base64: str
    digest: str
    width: int
    height: int


@dataclass
class Sketch:
    """A saved canvas version, private until deliberately promoted."""

    sketch_id: str
    title: str
    caption: str
    author: str
    created_utc: str
    asset: SketchAsset
    included_source_id: str = ""


@dataclass
class Fragment:
    """A citable piece of a source: a transcript turn or a document paragraph."""

    locator: int
    speaker: str | None
    text: str
    #: Which acoustic voice said this, when the microphone could tell them
    #: apart. Correcting a role applies to the whole VOICE rather than the one
    #: turn, because a clinician who says "that is the patient, not me" is
    #: telling you about a person, not about a sentence.
    voice: int | None = None
    #: Human locator from the original asset (for example ``p. 12``). The
    #: integer remains the stable machine locator used by citations.
    locator_label: str = ""
    #: Approximate offset reported by the browser speech-recognition event.
    #: ``None`` for pasted text and documents.
    started_ms: int | None = None

    @property
    def label(self) -> str:
        if self.locator_label:
            return self.locator_label
        return SPEAKER_LABEL.get(self.speaker or "", f"¶{self.locator + 1}")


@dataclass(frozen=True)
class CaseAsset:
    """Immutable uploaded evidence and the status of local extraction."""

    asset_id: str
    filename: str
    media_type: str
    size_bytes: int
    digest: str
    extraction_status: str
    extraction_method: str
    page_count: int
    missing_pages: tuple[int, ...] = ()


@dataclass(frozen=True)
class RecordingProvenance:
    """How a transcript was derived from one exact recording."""

    duration_ms: int
    transcript_digest: str
    captured_utc: str
    transcription_method: str
    browser_language: str
    transcription_status: str = "complete"
    transcription_error: str = ""


@dataclass(frozen=True)
class PendingRecording:
    """Durable audio whose transcript is incomplete or needs another attempt."""

    asset: CaseAsset
    duration_ms: int
    captured_utc: str
    transcription_method: str
    browser_language: str
    transcription_status: str = "uploaded"
    transcription_error: str = ""


@dataclass
class WorkingDraft:
    """Server-side recovery text that has not entered the clinical record."""

    text: str
    revision: int
    updated_utc: str


@dataclass(frozen=True)
class ModelUseReceipt:
    """One governed Factory run, retained after a clinician adopts its text."""

    run_id: str
    lane: str
    model: str
    billing: str
    cost_usd: float
    call_count: int
    evidence_digest: str
    document_digest: str
    output_digest: str
    gate_reason: str
    token_accounting: str = "not available from Factory run receipt"
    adopted_suggestion_ids: tuple[str, ...] = ()
    reviewed_by: str = ""
    reviewed_utc: str = ""


@dataclass
class ModelSuggestion:
    suggestion_id: str
    doc_id: str
    operation: str
    section: str
    text: str
    evidence: tuple[Citation, ...]
    exact_quotes: tuple[str, ...]
    status: str
    receipt: ModelUseReceipt


@dataclass(frozen=True)
class RubricCriterionFeedback:
    """One clinician judgment against one criterion of an exact rubric version."""

    criterion_id: str
    outcome: str
    comment: str


@dataclass(frozen=True)
class ClinicianValidation:
    """Human validation of one exact draft under one exact rubric version."""

    validation_id: str
    rubric_id: str
    rubric_version: str
    document_digest: str
    decision: str
    limitations_acknowledged: bool
    feedback: tuple[RubricCriterionFeedback, ...]
    reviewed_by: str
    reviewed_utc: str


@dataclass
class Source:
    source_id: str
    kind: str
    title: str
    author: str
    dated: str
    fragments: list[Fragment] = field(default_factory=list)
    sketch: SketchAsset | None = None
    case_asset: CaseAsset | None = None
    recording: RecordingProvenance | None = None

    @property
    def kind_label(self) -> str:
        return SOURCE_KINDS.get(self.kind, "Document")

    @property
    def evidence_class(self) -> str:
        return _KIND_EVIDENCE.get(self.kind, DOCUMENTARY)


_SPEAKERS = {
    "doctor": "clinician", "dr": "clinician", "clinician": "clinician",
    "psychiatrist": "clinician", "gp": "clinician", "examiner": "clinician",
    "patient": "patient", "pt": "patient", "client": "patient",
    # A third person in the room is common — a carer, an interpreter, a nurse,
    # a family member. Their words are neither the clinician's findings nor
    # the patient's own account, and a note that silently files them as either
    # is wrong in a way nobody would notice.
    "other": "other", "someone else": "other",
    "carer": "other", "interpreter": "other",
    "nurse": "other", "relative": "other", "family": "other",
    "parent": "other", "partner": "other", "support": "other",
}

#: The roles a turn can carry, and how each is written in the transcript.
SPEAKER_LABEL = {
    "clinician": "Clinician",
    "patient": "Patient",
    "other": "Someone else",
}


CLINICIAN_SPEAKER = "clinician"
PATIENT_SPEAKER = "patient"


def attribute_transcript(text: str, voices: list[int] | None = None) -> str:
    """Put a speaker in front of every line that has not got one.

    A doctor cannot stop an examination to say whose turn it is, so the
    recorder does not ask. Lines arrive bare and are attributed here from what
    was said and, when the microphone heard two voices, from which voice said
    it. Lines that already carry a speaker are left exactly alone: an explicit
    label is a decision, and inference must not overrule a decision.
    """

    from factory.health_ui import speakers

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return text

    labelled: list[str | None] = []
    bare: list[str] = []
    for line in lines:
        match = re.match(r"^([A-Za-z .]{1,24})\s*:\s*(.+)$", line)
        who = match.group(1).strip().lower().rstrip(".") if match else None
        if who in _SPEAKERS:
            labelled.append(line)
            bare.append(match.group(2).strip())      # type: ignore[union-attr]
        else:
            labelled.append(None)
            bare.append(line)

    if all(entry is not None for entry in labelled):
        return text

    # The voice grouping describes the same lines in the same order, so it is
    # only usable when it is the same length. A mismatch means something is out
    # of step and guessing from it would be worse than not using it.
    groups = voices if voices and len(voices) == len(bare) else None
    guessed = speakers.attribute(bare, groups)

    out: list[str] = []
    for original, said, who in zip(labelled, bare, guessed):
        if original is not None:
            out.append(original)
        else:
            out.append(f"{SPEAKER_LABEL.get(who, 'Patient')}: {said}")
    return "\n".join(out)


def speaker_confidence(session: "Session") -> int:
    """How firmly the recording's two voices were told apart by what was said.

    Zero when there is nothing to be confident about — no recording, one voice,
    or a transcript that arrived already labelled by a person.
    """

    from factory.health_ui import speakers

    source = next((s for s in session.sources if s.kind == "transcript"), None)
    if source is None:
        return 0
    voices = [f.voice for f in source.fragments]
    if any(v is None for v in voices) or len(set(voices)) < 2:
        return 0
    return speakers.confidence([f.text for f in source.fragments],
                               [v for v in voices if v is not None])


def make_source(
    source_id: str, kind: str, title: str, author: str, dated: str, body: str,
    voices: list[int] | None = None,
) -> Source:
    """Split a source into citable fragments.

    Transcripts split by attributed turn; everything else by paragraph. A line
    that cannot be attributed is appended to the previous fragment rather than
    dropped, because a lost line is lost evidence.
    """

    fragments: list[Fragment] = []
    if kind == "transcript":
        # Attribution happens HERE rather than at each call site. A transcript
        # arriving without speaker labels — from the recorder, from a paste,
        # from a sample — used to have its opening lines silently dropped,
        # because a line with nobody to attach to had nowhere to go. Doing it
        # once, at the only place transcripts become fragments, means a caller
        # added later cannot reintroduce that.
        body = attribute_transcript(body, voices)
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^([A-Za-z .]{1,24})\s*:\s*(.+)$", line)
            if match:
                who = match.group(1).strip().lower().rstrip(".")
                if who in _SPEAKERS:
                    fragments.append(Fragment(len(fragments), _SPEAKERS[who],
                                              match.group(2).strip()))
                    continue
            if fragments:
                prev = fragments[-1]
                fragments[-1] = Fragment(prev.locator, prev.speaker,
                                         f"{prev.text} {line}")
    else:
        for block in re.split(r"\n\s*\n", body):
            block = " ".join(block.split())
            if block:
                fragments.append(Fragment(len(fragments), None, block))
    # Stamp which voice said each turn, so a later correction can be applied to
    # the PERSON rather than to the one sentence that happened to be wrong.
    if voices and len(voices) == len(fragments):
        for fragment, group in zip(fragments, voices):
            fragment.voice = group
    return Source(source_id, kind, title, author, dated, fragments)


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------

EXTRACTED = "extracted"
CLINICIAN = "clinician-authored"


#: Cites a source as a whole rather than a piece inside it — used by the
#: evidence index, where the source's own identity is the claim.
WHOLE_SOURCE = -1


@dataclass
class Citation:
    source_id: str
    locator: int


@dataclass
class Paragraph:
    text: str
    evidence_class: str
    citations: list[Citation] = field(default_factory=list)
    origin: str = EXTRACTED

    def rewrite(self, text: str) -> None:
        """A clinician's words are the clinician's, not the source's.

        Dropping the citations is the whole point: retaining them would make
        the document assert that a transcript or a witness said something it
        never said. In a report relied on in court that is the difference
        between evidence and fabrication.
        """

        self.text = text
        self.origin = CLINICIAN
        self.citations = []

    @property
    def is_traceable(self) -> bool:
        return bool(self.citations) or self.origin == CLINICIAN


@dataclass
class DocSection:
    name: str
    guidance: str = ""
    paragraphs: list[Paragraph] = field(default_factory=list)
    #: True when this section is the evidence index, so an exporter does not
    #: print the list of sources a second time.
    index: bool = False
    #: Lines from the material that belong here but did not make the note.
    #: Kept with the document and offered to the clinician; never discarded,
    #: never exported unless the clinician pulls one in.
    offered: list[Paragraph] = field(default_factory=list)


DRAFT = "draft"
SIGNED = "signed"

#: Finalisation through the door (docs/ARCHITECTURE-OF-RECORD/09-clinical-finalisation.md). PENDING and UNKNOWN
#: freeze the document; only COMMITTED, from the target's receipt, makes it SIGNED; FAILED releases it again.
FINALISATION_PENDING = "pending"
FINALISATION_COMMITTED = "committed"
FINALISATION_FAILED = "failed"
FINALISATION_UNKNOWN = "unknown"
FINALISATION_STATES = (FINALISATION_PENDING, FINALISATION_COMMITTED, FINALISATION_FAILED, FINALISATION_UNKNOWN)


@dataclass
class Finalisation:
    """One attempt to finalise exactly one version of a document through the door, and how it settled."""

    state: str
    document_digest: str              # the frozen version this attempt finalises
    artifact_address: str             # the retained final render, content-addressed per tenant
    artifact_sha256: str
    signer: str                       # the verified clinician's name, exactly as rendered
    signed_utc: str                   # the signing time, exactly as rendered
    nonce: str                        # the permit nonce the target's receipts are keyed by
    started_us: int                   # when the attempt began, on the authority clock, to bound its recovery
    detail: str = ""


class RecordIntegrityError(ValueError):
    """A signed record no longer matches the content frozen at signing."""


@dataclass
class Document:
    doc_id: str
    template_id: str
    template_name: str
    title: str
    case_ref: str
    subject_ref: str
    created_utc: str
    sections: list[DocSection]
    sources: list[Source] = field(default_factory=list)
    status: str = DRAFT
    signed_by: str | None = None
    signed_utc: str | None = None
    frozen_digest: str | None = None
    # Added without changing the historical content digest contract. New
    # signatures bind every field that can reach an export; older records with
    # no manifest digest continue to validate against frozen_digest.
    frozen_export_digest: str | None = None
    frozen_export_digest_version: int | None = None
    versions: list[dict[str, str]] = field(default_factory=list)
    #: Set only on a worked sample. It says, on the document itself, that the
    #: expert's own sections came with the sample rather than being written by
    #: the system — the single misunderstanding this product must never allow.
    sample_note: str = ""
    #: Lines from the material that reached NO section. Routing is done by cue
    #: words and a cue list always has gaps; the day a prescribing instruction
    #: matches nothing, it must appear here rather than disappear.
    unplaced: list[Paragraph] = field(default_factory=list)
    model_receipts: list[ModelUseReceipt] = field(default_factory=list)
    validations: list[ClinicianValidation] = field(default_factory=list)
    finalisation: Finalisation | None = None

    @property
    def is_frozen(self) -> bool:
        """Signed, or being finalised: in both cases the document cannot change under its reviewer."""
        return self.status == SIGNED or (
            self.finalisation is not None
            and self.finalisation.state in (FINALISATION_PENDING, FINALISATION_UNKNOWN))

    def digest(self) -> str:
        paragraphs = "|".join(
            f"{s.name}#{p.origin}#{p.evidence_class}#{p.text}#"
            + ",".join(f"{c.source_id}:{c.locator}" for c in p.citations)
            for s in self.sections for p in s.paragraphs
        )
        # A promoted image is part of the signed record.  Hashing only its
        # caption would allow the cited pixels to change without invalidating
        # the signature.
        assets = json.dumps([
            {
                "source_id": source.source_id,
                "digest": source.sketch.digest,
                "title": source.title,
                "author": source.author,
                "dated": source.dated,
                "caption": source.fragments[0].text if source.fragments else "",
            }
            for source in self.sources if source.sketch is not None
        ], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        # Preserve every pre-HV-2 digest byte-for-byte when no sketch is in the
        # document. Existing signed records must not become invalid merely
        # because the application learned a new source type.
        receipt_manifest = json.dumps(
            [asdict(receipt) for receipt in self.model_receipts],
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        material = paragraphs if assets == "[]" else f"{paragraphs}||assets:{assets}"
        if receipt_manifest != "[]":
            material += f"||model_receipts:{receipt_manifest}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def export_digest(self, version: int = 3) -> str:
        """Bind the complete signed/exported record without changing digest v1."""

        if version not in {2, 3}:
            raise ValueError("unsupported export digest version")
        manifest = {
            "manifest_version": version,
            "doc_id": self.doc_id,
            "template_id": self.template_id,
            "template_name": self.template_name,
            "title": self.title,
            "case_ref": self.case_ref,
            "subject_ref": self.subject_ref,
            "created_utc": self.created_utc,
            "sections": [asdict(section) for section in self.sections],
            "sources": [asdict(source) for source in self.sources],
            "status": self.status,
            "signed_by": self.signed_by,
            "signed_utc": self.signed_utc,
            "sample_note": self.sample_note,
            "unplaced": [asdict(paragraph) for paragraph in self.unplaced],
        }
        if self.model_receipts:
            manifest["model_receipts"] = [asdict(item) for item in self.model_receipts]
        if self.validations:
            manifest["clinician_validations"] = [
                asdict(item) for item in self.validations
            ]
        if version >= 3:
            # This value is printed as the signed record's content digest. It
            # must therefore be bound by the separate export manifest too;
            # otherwise a valid-looking replacement could be displayed while
            # the record digest stayed unchanged.
            manifest["content_digest"] = self.frozen_digest
        canonical = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def require_intact(self) -> None:
        """Refuse use of a signed record whose frozen content has changed."""

        if self.status != SIGNED:
            return
        if self.frozen_export_digest:
            version = self.frozen_export_digest_version or 2
            intact = self.export_digest(version) == self.frozen_export_digest
        else:
            intact = bool(self.frozen_digest and self.digest() == self.frozen_digest)
        if not intact:
            raise RecordIntegrityError(
                "the signed document no longer matches its frozen digest"
            )

    def source(self, source_id: str) -> Source | None:
        return next((s for s in self.sources if s.source_id == source_id), None)

    def untraceable(self) -> list[str]:
        return [
            p.text for s in self.sections for p in s.paragraphs
            if not p.is_traceable
        ]

    def snapshot(self, note: str) -> None:
        self.versions.append(
            {"utc": _now(), "digest": self.digest()[:16], "note": note}
        )


# ---------------------------------------------------------------------------
# Session: one conversation, many documents
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """One consultation, and everything written from it.

    The doctor records once. The transcript stays reachable for as long as the
    session exists, and every document — note, patient letter, referral,
    medico-legal report — is generated from this same material rather than
    from a fresh upload. That is the whole time-saving: the conversation
    happens once and the paperwork follows from it.
    """

    session_id: str
    clinician: str
    title: str
    subject_ref: str
    created_utc: str
    #: Stable tenant-scoped ownership. Display names are authorship labels and
    #: can collide; they are never an authorization key once this is present.
    owner_id: str = ""
    workspace_id: str = ""
    sources: list[Source] = field(default_factory=list)
    sketches: list[Sketch] = field(default_factory=list)
    documents: list[Document] = field(default_factory=list)
    #: In-progress browser text, durably autosaved but visibly distinct from
    #: the clinical record until the clinician chooses the explicit action.
    working_drafts: dict[str, WorkingDraft] = field(default_factory=dict)
    model_suggestions: list[ModelSuggestion] = field(default_factory=list)
    #: Audio is preserved before transcription is accepted. This makes a
    #: browser/provider failure recoverable without calling an empty transcript
    #: complete or asking the clinician to repeat the consultation.
    pending_recording: PendingRecording | None = None
    #: Name of a bundled synthetic sample recording, when there is one. Live
    #: recordings are represented by the transcript Source.case_asset and its
    #: RecordingProvenance receipt instead of this public sample-asset name.
    audio: str = ""
    #: A demonstration case. It is READ-ONLY: it cannot be edited, signed,
    #: added to or deleted, so a rehearsal cannot damage the thing being
    #: rehearsed and the next person to open it sees exactly what the last
    #: person saw.
    read_only: bool = False
    #: The stored revision this copy was read at. A save succeeds only while it is still the stored revision, so a
    #: request working from an older read can never overwrite a newer write, a signature included (source review 3027).
    revision: int = 0

    @property
    def transcript(self) -> Source | None:
        return next((s for s in self.sources if s.kind == "transcript"), None)

    @property
    def has_recording(self) -> bool:
        # Historical API name: this means the consultation has reached either
        # a durable audio-pending state or a transcript, including pasted text.
        return self.pending_recording is not None or self.transcript is not None

    def document(self, doc_id: str) -> Document | None:
        return next((d for d in self.documents if d.doc_id == doc_id), None)

    def source(self, source_id: str) -> Source | None:
        return next((s for s in self.sources if s.source_id == source_id), None)


# ---------------------------------------------------------------------------
# Template engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SectionSpec:
    """One section, and how it draws from the case material."""

    name: str
    guidance: str = ""
    #: Source kinds this section draws from. Empty = clinician writes it.
    from_kinds: tuple[str, ...] = ()
    #: Cue words that route a fragment here. Empty = take everything.
    cues: tuple[str, ...] = ()
    #: Force this evidence class regardless of source kind.
    evidence_class: str | None = None
    #: Speaker filter for transcripts.
    speaker: str | None = None
    #: This section IS the evidence index: one line per source reviewed.
    index: bool = False
    #: The clinician must write here before the document can be signed, EVEN
    #: IF sources fill it. A section with no `from_kinds` already requires
    #: them by construction; this flag exists for the case that inference
    #: cannot see — a section drawn from the material that still needs the
    #: clinician's own judgement on top of it.
    requires_clinician: bool = False


@dataclass(frozen=True)
class Template:
    template_id: str
    name: str
    blurb: str
    subject_word: str          # "patient" | "examinee"
    sections: tuple[SectionSpec, ...]


# Words that make a line of conversation worth putting in a clinical document.
# Deliberately about CLINICAL SHAPE, not diagnosis: duration, frequency,
# severity, negation, medication, function. A line carrying none of these is
# usually the conversation working rather than the consultation's content.
_CLINICAL_CUES = (
    "pain", "ache", "sore", "sleep", "wake", "night", "morning", "week",
    "month", "year", "day", "hour", "since", "before", "after", "worse",
    "better", "eased", "improved", "severe", "mild", "constant",
    "comes and goes", "no ", "not ", "never", "stopped", "started",
    "taking", "tablet", "mg", "dose", "prescribed", "medication", "ibuprofen",
    "paracetamol", "work", "walk", "lift", "drive", "stairs", "unable",
    "can't", "cannot", "struggle", "numb", "tingling", "weakness", "swelling",
    "fever", "weight", "appetite", "mood", "anxious", "low", "history",
    "allergic", "surgery", "injury", "fell", "accident", "referred",
)

# Bare conversational moves. A note made of these is a transcript.
_FILLER = (
    "yes", "yeah", "no", "ok", "okay", "mm", "mhm", "right", "sure", "i see",
    "thank you", "thanks", "of course", "please", "hello", "good morning",
    "good afternoon", "that's fine", "sorry",
)

#: How many lines a drafted section may carry before the rest are offered
#: rather than printed. A real fifteen-minute consultation is well over a
#: hundred turns; a section holding all of them is the transcript again.
SECTION_LIMIT = 8


def _salience(text: str) -> int:
    """How much clinical content a line carries. Higher is kept sooner."""

    stripped = text.strip().rstrip(".!?").lower()
    if stripped in _FILLER or len(stripped) < 12:
        # Below zero, not at zero. A bare "Yes." must rank under a substantive
        # line that simply carries no cue word, or the list the clinician is
        # offered opens with the least useful thing they said.
        return -1
    low = text.lower()
    score = sum(1 for cue in _CLINICAL_CUES if cue in low)
    if any(ch.isdigit() for ch in text):
        score += 1                      # a number is usually a fact
    return score


def _shortlist(paragraphs: list[Paragraph]) -> tuple[list[Paragraph],
                                                     list[Paragraph]]:
    """Split a section's candidates into what it prints and what it offers.

    Nothing is discarded. The remainder stays with the document and the
    clinician can pull any line in with one click, because a scribe that
    silently drops what the patient said is worse than one that says too much.
    Order is preserved in both lists: a note that reorders the consultation is
    harder to check against the recording.
    """

    if len(paragraphs) <= SECTION_LIMIT:
        return paragraphs, []

    seen: set[str] = set()
    ranked: list[tuple[int, int, Paragraph]] = []
    for position, para in enumerate(paragraphs):
        key = " ".join(para.text.lower().split())[:80]
        if key in seen:
            continue                    # a repeated line adds nothing twice
        seen.add(key)
        ranked.append((_salience(para.text), position, para))

    ranked.sort(key=lambda row: (-row[0], row[1]))
    keep = {row[1] for row in ranked[:SECTION_LIMIT] if row[0] > 0}
    kept = [p for i, p in enumerate(paragraphs) if i in keep]
    # What is offered is the DISTINCT remainder. Repeating a line the doctor
    # already declined, or listing twenty acknowledgements, would bury the one
    # line they might actually want — and the full recording is one tab away
    # either way, which is where completeness is guaranteed.
    rest = [para for _, position, para in ranked if position not in keep]
    return kept, rest


def _matches(fragment: Fragment, spec: SectionSpec) -> bool:
    if spec.speaker and fragment.speaker != spec.speaker:
        return False
    if not spec.cues:
        return True
    low = fragment.text.lower()
    return any(cue in low for cue in spec.cues)


def build_document(
    template: Template, title: str, case_ref: str, subject_ref: str,
    sources: list[Source],
) -> Document:
    """Draft a document from the case material.

    Every paragraph is lifted from a source and cited. Sections a template
    marks as clinician-written are left empty on purpose: the system must not
    author expert opinion.
    """

    sections: list[DocSection] = []
    for spec in template.sections:
        section = DocSection(spec.name, spec.guidance, index=spec.index)
        if spec.index:
            # The index cites the source as a whole, so each line carries the
            # source's own identity rather than a fragment inside it.
            for source in sources:
                line = f"[{source.kind_label}] {source.title}"
                if source.author:
                    line += f" — {source.author}"
                if source.dated:
                    line += f", {source.dated}"
                section.paragraphs.append(Paragraph(
                    text=line,
                    evidence_class=DOCUMENTARY,
                    citations=[Citation(source.source_id, WHOLE_SOURCE)],
                ))
        elif spec.from_kinds:
            for source in sources:
                if source.kind not in spec.from_kinds:
                    continue
                for fragment in source.fragments:
                    if not _matches(fragment, spec):
                        continue
                    section.paragraphs.append(
                        Paragraph(
                            text=fragment.text,
                            evidence_class=spec.evidence_class
                            or source.evidence_class,
                            citations=[Citation(source.source_id,
                                                fragment.locator)],
                        )
                    )
            # Selection is for CONVERSATION only. A transcript is verbose by
            # nature and a note that reprints it has saved nobody anything. A
            # witness statement, a custody record or an investigation finding
            # is already curated, and a report that showed eight of its
            # thirteen pieces of corroborating evidence would be a worse
            # document than a long one — in a report a court relies on, that
            # is the difference between concise and incomplete.
            if set(spec.from_kinds) == {"transcript"}:
                section.paragraphs, section.offered = _shortlist(
                    section.paragraphs)
        sections.append(section)

    doc = Document(
        doc_id=uuid.uuid4().hex[:12],
        template_id=template.template_id,
        template_name=template.name,
        title=title,
        case_ref=case_ref,
        subject_ref=subject_ref,
        created_utc=_now(),
        sections=sections,
        sources=list(sources),
    )
    doc.unplaced = _unplaced(template, sections, sources)
    doc.snapshot("draft created")
    return doc


def _unplaced(template: Template, sections: list[DocSection],
              sources: list[Source]) -> list[Paragraph]:
    """Lines the template drew on but routed nowhere.

    Sections are filled by cue words, and a cue list is a guess about language.
    The failure that matters is not an imperfect guess — it is an imperfect
    guess that is invisible: a prescribing instruction phrased in a way no cue
    anticipated would simply not appear in the note, and nothing would say so.
    Anything a section COULD have taken and none did is collected here, so the
    clinician decides rather than the vocabulary.
    """

    drawn_from = {kind for spec in template.sections for kind in spec.from_kinds}
    if not drawn_from:
        return []
    accounted = {
        para.text for section in sections
        for para in (*section.paragraphs, *section.offered)
    }
    missed: list[Paragraph] = []
    seen: set[str] = set()
    for source in sources:
        if source.kind not in drawn_from:
            continue
        for fragment in source.fragments:
            if fragment.text in accounted or fragment.text in seen:
                continue
            # A question the clinician asked is a prompt, not content: whatever
            # it was asking for is in the answer that follows. Listing every
            # question here would bury the lines that genuinely went nowhere.
            if fragment.speaker == "clinician" and fragment.text.endswith("?"):
                continue
            seen.add(fragment.text)
            missed.append(Paragraph(
                text=fragment.text,
                evidence_class=source.evidence_class,
                citations=[Citation(source.source_id, fragment.locator)],
            ))
    return missed


# ---------------------------------------------------------------------------
# Case analysis: index, chronology, gaps
# ---------------------------------------------------------------------------

def evidence_index(doc: Document) -> list[dict[str, str]]:
    return [
        {"source_id": s.source_id, "kind": s.kind_label, "title": s.title,
         "author": s.author, "dated": s.dated,
         "fragments": str(len(s.fragments))}
        for s in doc.sources
    ]


_DATE = re.compile(
    r"\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)


def chronology(doc: Document) -> list[dict[str, str]]:
    """Every date mentioned in the material, with the line that mentions it.

    Deliberately not called a chronology OF EVENTS. This is date extraction,
    not comprehension: a line reading "before 3 March he was well" mentions the
    date without being an event on it. Presenting that to a psychiatrist as an
    established sequence would be a claim the code cannot support, so the
    interface names it for what it is and shows the source line beside it.

    The letter of instruction is excluded. It poses the solicitor's questions
    and quotes dates back at the expert; it is not evidence of anything
    happening.
    """

    events: list[dict[str, str]] = []
    for source in doc.sources:
        if source.kind == "instruction":
            continue
        for fragment in source.fragments:
            for found in _DATE.findall(fragment.text):
                events.append({
                    "date": found,
                    "event": fragment.text[:180],
                    "source": source.title,
                    "source_id": source.source_id,
                    "locator": str(fragment.locator),
                })
    def key(event: dict[str, str]) -> tuple[int, str]:
        raw = event["date"]
        if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
            return (0, raw)
        months = ["january", "february", "march", "april", "may", "june",
                  "july", "august", "september", "october", "november",
                  "december"]
        parts = raw.split()
        if len(parts) == 3 and parts[1].lower() in months:
            return (0, f"{parts[2]}-{months.index(parts[1].lower())+1:02d}-"
                       f"{int(parts[0]):02d}")
        return (1, raw)
    return sorted(events, key=key)


MEDICO_LEGAL_TEMPLATE = "psychiatric-medico-legal"


def requires_rubric_validation(doc: "Document") -> bool:
    """Whether signing this document needs a current clinician rubric validation: the medico-legal profile."""
    return doc.template_id == MEDICO_LEGAL_TEMPLATE


def current_validation(doc: "Document") -> "ClinicianValidation | None":
    """The clinician validation of exactly this version of the document, if one was recorded."""
    digest = doc.digest()
    return next((item for item in reversed(doc.validations) if item.document_digest == digest), None)


def unwritten_sections(doc: "Document", template: "Template") -> list[str]:
    """Sections the template leaves to the clinician, still empty.

    A section with no source kinds is one the material cannot supply — an
    opinion, a conclusion, a recommendation. Signing a report whose opinion is
    blank is the one failure a court would notice first, so signing is refused
    rather than merely flagged.
    """

    written_by_clinician = {
        section.name for section in doc.sections
        if any(p.origin == CLINICIAN for p in section.paragraphs)
    }
    empty = {s.name for s in doc.sections if not s.paragraphs}
    outstanding: list[str] = []
    for spec in template.sections:
        if spec.index:
            continue
        if spec.requires_clinician:
            # Declared: sources may have filled it, but the clinician has not.
            if spec.name not in written_by_clinician:
                outstanding.append(spec.name)
        elif not spec.from_kinds and spec.name in empty:
            # Inferred: nothing can fill this but the clinician, and nothing has.
            outstanding.append(spec.name)
    return outstanding


def gaps_and_contradictions(doc: Document, template: Template) -> list[str]:
    """What the clinician should chase before signing.

    Stated as questions rather than conclusions: this flags absence, it does
    not decide anything.
    """

    found: list[str] = []
    kinds = {s.kind for s in doc.sources}
    expected = {k for spec in template.sections for k in spec.from_kinds}
    for kind in sorted(expected - kinds):
        found.append(
            f"No {SOURCE_KINDS.get(kind, kind).lower()} has been added; "
            f"sections drawing on it will be empty."
        )
    for section in doc.sections:
        spec = next((s for s in template.sections if s.name == section.name),
                    None)
        if spec and spec.from_kinds and not section.paragraphs:
            found.append(
                f"'{section.name}' is empty — no material matched it."
            )
        if spec and not spec.from_kinds and not section.paragraphs:
            found.append(
                f"'{section.name}' must be written by the clinician and is "
                f"still empty."
            )
    if not any(s.kind == "instruction" for s in doc.sources):
        found.append(
            "No letter of instruction has been added, so the questions to be "
            "answered are not on record."
        )
    undated = [s.title for s in doc.sources if not s.dated.strip()]
    for title in undated:
        found.append(f"Source '{title}' has no date recorded.")
    return found
