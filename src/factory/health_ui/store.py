"""Persistence and ownership for the clinician workspace.

A doctor's sessions must survive a restart, and must belong to them. Both are
enforced here rather than left to the request layer:

* every session records the clinician who created it, and lookups take the
  clinician so one doctor cannot read or alter another's work;
* state is written to disk on every mutation, because a scribe that loses a
  consultation when a process restarts is worse than no scribe.

File-backed JSON is deliberate at this stage: it is inspectable, needs no
service, and the seam is narrow enough to swap for Postgres without touching
the workspace above it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import AbstractSet, Any, Protocol, cast

from factory.health_ui import documents as doc_mod
from factory.health_ui import audio as audio_mod
from factory.health_ui import sketches as sketch_mod
from factory.health_ui import templates as tpl_mod


class StoreDegraded(RuntimeError):
    """Durable state failed integrity checks and must remain untouched."""


class StoreRecoveryRequired(RuntimeError):
    """Attributable damaged entries are isolated, but writes await confirmation."""


class StaleSession(RuntimeError):
    """The consultation changed after this copy was read; nothing was written. Reload and try again."""


class SessionStore(Protocol):
    """Durable consultation authority used by the HTTP application."""

    @property
    def degraded(self) -> bool: ...

    @property
    def recovery_required(self) -> bool: ...

    def save(self, session: doc_mod.Session) -> None: ...

    def get(self, session_id: str, owner_id: str) -> doc_mod.Session | None: ...

    def list_for(self, owner_id: str) -> list[doc_mod.Session]: ...

    def delete(self, session_id: str, owner_id: str) -> bool: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mapping(
    raw: Any,
    *,
    required: set[str],
    optional: AbstractSet[str] = frozenset(),
    where: str,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(k, str) for k in raw):
        raise TypeError(f"{where} must be an object")
    value = cast(dict[str, Any], raw)
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        raise ValueError(
            f"{where} has missing {sorted(missing)} or unknown {sorted(unknown)} fields"
        )
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError(f"{where} must be a list")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{where} must be text")
    return value


def _optional_string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _string(value, where)


def _integer(value: Any, where: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{where} must be an integer")
    return value


def _optional_integer(value: Any, where: str) -> int | None:
    if value is None:
        return None
    return _integer(value, where)


def _boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{where} must be a boolean")
    return value


def _sha256(value: Any, where: str) -> str:
    digest = _string(value, where)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError(f"{where} must be a lowercase SHA-256 digest")
    return digest


def _unique(values: list[str], where: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{where} contains duplicate identifiers")


def _encode(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    return value


def _fragment(raw: dict[str, Any]) -> doc_mod.Fragment:
    raw = _mapping(
        raw,
        required={"locator", "speaker", "text"},
        optional={"voice", "locator_label", "started_ms"},
        where="fragment",
    )
    return doc_mod.Fragment(
        _integer(raw["locator"], "fragment.locator"),
        _optional_string(raw["speaker"], "fragment.speaker"),
        _string(raw["text"], "fragment.text"),
        _optional_integer(raw.get("voice"), "fragment.voice"),
        _string(raw.get("locator_label", ""), "fragment.locator_label"),
        _optional_integer(raw.get("started_ms"), "fragment.started_ms"),
    )


def _asset(raw: dict[str, Any]) -> doc_mod.SketchAsset:
    raw = _mapping(
        raw,
        required={"png_base64", "digest", "width", "height"},
        where="sketch asset",
    )
    asset = doc_mod.SketchAsset(
        png_base64=_string(raw["png_base64"], "sketch asset.png_base64"),
        digest=_string(raw["digest"], "sketch asset.digest"),
        width=_integer(raw["width"], "sketch asset.width"),
        height=_integer(raw["height"], "sketch asset.height"),
    )
    sketch_mod.asset_bytes(asset)
    return asset


def _case_asset(raw: dict[str, Any]) -> doc_mod.CaseAsset:
    raw = _mapping(
        raw,
        required={
            "asset_id", "filename", "media_type", "size_bytes", "digest",
            "extraction_status", "extraction_method", "page_count",
            "missing_pages",
        },
        where="case asset",
    )
    asset_id = _string(raw["asset_id"], "case asset.asset_id")
    if not re.fullmatch(r"asset-[0-9a-f]{20}", asset_id):
        raise ValueError("case asset.asset_id is invalid")
    missing_pages = [
        _integer(item, "case asset.missing_pages[]")
        for item in _list(raw["missing_pages"], "case asset.missing_pages")
    ]
    if any(page <= 0 for page in missing_pages):
        raise ValueError("case asset missing pages must be positive")
    return doc_mod.CaseAsset(
        asset_id=asset_id,
        filename=_string(raw["filename"], "case asset.filename"),
        media_type=_string(raw["media_type"], "case asset.media_type"),
        size_bytes=_integer(raw["size_bytes"], "case asset.size_bytes"),
        digest=_sha256(raw["digest"], "case asset.digest"),
        extraction_status=_string(
            raw["extraction_status"], "case asset.extraction_status"
        ),
        extraction_method=_string(
            raw["extraction_method"], "case asset.extraction_method"
        ),
        page_count=_integer(raw["page_count"], "case asset.page_count"),
        missing_pages=tuple(missing_pages),
    )


def _recording(raw: dict[str, Any]) -> doc_mod.RecordingProvenance:
    raw = _mapping(
        raw,
        required={
            "duration_ms", "transcript_digest", "captured_utc",
            "transcription_method", "browser_language",
        },
        optional={"transcription_status", "transcription_error"},
        where="recording provenance",
    )
    duration = _integer(raw["duration_ms"], "recording.duration_ms")
    if duration <= 0:
        raise ValueError("recording duration must be positive")
    status = _string(
        raw.get("transcription_status", "complete"),
        "recording.transcription_status",
    )
    error = _string(raw.get("transcription_error", ""), "recording.transcription_error")
    if status != "complete" or error:
        raise ValueError("accepted recording transcript is not complete")
    return doc_mod.RecordingProvenance(
        duration_ms=duration,
        transcript_digest=_sha256(
            raw["transcript_digest"], "recording.transcript_digest"
        ),
        captured_utc=_string(raw["captured_utc"], "recording.captured_utc"),
        transcription_method=_string(
            raw["transcription_method"], "recording.transcription_method"
        ),
        browser_language=_string(
            raw["browser_language"], "recording.browser_language"
        ),
        transcription_status=status,
        transcription_error=error,
    )


def _pending_recording(raw: dict[str, Any]) -> doc_mod.PendingRecording:
    raw = _mapping(
        raw,
        required={
            "asset", "duration_ms", "captured_utc", "transcription_method",
            "browser_language", "transcription_status", "transcription_error",
        },
        where="pending recording",
    )
    asset = _case_asset(raw["asset"])
    duration = _integer(raw["duration_ms"], "pending recording.duration_ms")
    status = _string(
        raw["transcription_status"], "pending recording.transcription_status"
    )
    error = _string(raw["transcription_error"], "pending recording.transcription_error")
    if duration <= 0 or not asset.media_type.startswith("audio/"):
        raise ValueError("pending recording is not valid audio")
    if status not in {"uploaded", "transcription-failed"}:
        raise ValueError("pending recording has an unknown transcription status")
    if (status == "uploaded" and error) or (status == "transcription-failed" and not error):
        raise ValueError("pending recording status and error disagree")
    return doc_mod.PendingRecording(
        asset=asset,
        duration_ms=duration,
        captured_utc=_string(raw["captured_utc"], "pending recording.captured_utc"),
        transcription_method=_string(
            raw["transcription_method"], "pending recording.transcription_method"
        ),
        browser_language=_string(
            raw["browser_language"], "pending recording.browser_language"
        ),
        transcription_status=status,
        transcription_error=error,
    )


def _working_draft(raw: dict[str, Any]) -> doc_mod.WorkingDraft:
    raw = _mapping(
        raw,
        required={"text", "revision", "updated_utc"},
        where="working draft",
    )
    revision = _integer(raw["revision"], "working draft.revision")
    if revision < 1:
        raise ValueError("working draft revision must be positive")
    return doc_mod.WorkingDraft(
        text=_string(raw["text"], "working draft.text"),
        revision=revision,
        updated_utc=_string(raw["updated_utc"], "working draft.updated_utc"),
    )


def _working_drafts(raw: Any) -> dict[str, doc_mod.WorkingDraft]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise TypeError("session.working_drafts must be an object")
    if set(raw) - {"transcript"}:
        raise ValueError("session.working_drafts contains an unknown draft kind")
    return {key: _working_draft(value) for key, value in raw.items()}


def _model_receipt(raw: dict[str, Any]) -> doc_mod.ModelUseReceipt:
    raw = _mapping(
        raw,
        required={
            "run_id", "lane", "model", "billing", "cost_usd",
            "call_count", "evidence_digest", "document_digest", "output_digest",
            "gate_reason", "reviewed_by", "reviewed_utc",
        },
        optional={"token_accounting", "adopted_suggestion_ids"},
        where="model use receipt",
    )
    cost = raw["cost_usd"]
    if isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0:
        raise ValueError("model use receipt cost is invalid")
    calls = _integer(raw["call_count"], "model use receipt.call_count")
    if calls not in {0, 1}:
        raise ValueError("model use receipt call count is invalid")
    return doc_mod.ModelUseReceipt(
        run_id=_string(raw["run_id"], "model use receipt.run_id"),
        lane=_string(raw["lane"], "model use receipt.lane"),
        model=_string(raw["model"], "model use receipt.model"),
        billing=_string(raw["billing"], "model use receipt.billing"),
        cost_usd=float(cost),
        call_count=calls,
        evidence_digest=_sha256(raw["evidence_digest"], "model use receipt.evidence_digest"),
        document_digest=_sha256(raw["document_digest"], "model use receipt.document_digest"),
        output_digest=_sha256(raw["output_digest"], "model use receipt.output_digest"),
        gate_reason=_string(raw["gate_reason"], "model use receipt.gate_reason"),
        token_accounting=_string(
            raw.get("token_accounting", "not available from Factory run receipt"),
            "model use receipt.token_accounting",
        ),
        adopted_suggestion_ids=tuple(
            _string(item, "model use receipt.adopted_suggestion_id")
            for item in _list(
                raw.get("adopted_suggestion_ids", []),
                "model use receipt.adopted_suggestion_ids",
            )
        ),
        reviewed_by=_string(raw["reviewed_by"], "model use receipt.reviewed_by"),
        reviewed_utc=_string(raw["reviewed_utc"], "model use receipt.reviewed_utc"),
    )


def _model_suggestion(raw: dict[str, Any]) -> doc_mod.ModelSuggestion:
    raw = _mapping(
        raw,
        required={
            "suggestion_id", "doc_id", "operation", "section", "text",
            "evidence", "exact_quotes", "status", "receipt",
        },
        where="model suggestion",
    )
    evidence = tuple(
        _citation(item) for item in _list(raw["evidence"], "model suggestion.evidence")
    )
    quotes = tuple(
        _string(item, "model suggestion.exact_quote")
        for item in _list(raw["exact_quotes"], "model suggestion.exact_quotes")
    )
    if not evidence or len(evidence) != len(quotes):
        raise ValueError("model suggestion evidence and quotes do not match")
    operation = _string(raw["operation"], "model suggestion.operation")
    status = _string(raw["status"], "model suggestion.status")
    if operation not in {"critique", "draft", "redraft"}:
        raise ValueError("model suggestion operation is invalid")
    if status not in {"pending", "adopted", "rejected"}:
        raise ValueError("model suggestion status is invalid")
    return doc_mod.ModelSuggestion(
        suggestion_id=_string(raw["suggestion_id"], "model suggestion.suggestion_id"),
        doc_id=_string(raw["doc_id"], "model suggestion.doc_id"),
        operation=operation,
        section=_string(raw["section"], "model suggestion.section"),
        text=_string(raw["text"], "model suggestion.text"),
        evidence=evidence,
        exact_quotes=quotes,
        status=status,
        receipt=_model_receipt(raw["receipt"]),
    )


def _rubric_feedback(raw: dict[str, Any]) -> doc_mod.RubricCriterionFeedback:
    raw = _mapping(
        raw,
        required={"criterion_id", "outcome", "comment"},
        where="rubric criterion feedback",
    )
    outcome = _string(raw["outcome"], "rubric feedback.outcome")
    if outcome not in {"meets", "needs-change", "not-applicable"}:
        raise ValueError("rubric feedback outcome is invalid")
    return doc_mod.RubricCriterionFeedback(
        criterion_id=_string(raw["criterion_id"], "rubric feedback.criterion_id"),
        outcome=outcome,
        comment=_string(raw["comment"], "rubric feedback.comment"),
    )


def _finalisation(raw: Any, *, status: str, signed_by: str | None,
                  signed_utc: str | None) -> doc_mod.Finalisation | None:
    """A finalisation record, consistent with the document status it accompanies, or refused."""
    if raw is None:
        return None
    raw = _mapping(raw, required={"state", "document_digest", "artifact_address", "artifact_sha256", "signer",
                                  "signed_utc", "nonce", "started_us", "detail"}, where="document.finalisation")
    record = doc_mod.Finalisation(
        state=_string(raw["state"], "document.finalisation.state"),
        document_digest=_sha256(raw["document_digest"], "document.finalisation.document_digest"),
        artifact_address=_sha256(raw["artifact_address"], "document.finalisation.artifact_address"),
        artifact_sha256=_sha256(raw["artifact_sha256"], "document.finalisation.artifact_sha256"),
        signer=_string(raw["signer"], "document.finalisation.signer"),
        signed_utc=_string(raw["signed_utc"], "document.finalisation.signed_utc"),
        nonce=_string(raw["nonce"], "document.finalisation.nonce"),
        started_us=_integer(raw["started_us"], "document.finalisation.started_us"),
        detail=_string(raw["detail"], "document.finalisation.detail"),
    )
    if record.state not in doc_mod.FINALISATION_STATES or not record.nonce or not record.signer:
        raise ValueError("document.finalisation is incomplete or has an unknown state")
    committed = record.state == doc_mod.FINALISATION_COMMITTED
    if committed != (status == doc_mod.SIGNED):
        raise ValueError("only a committed finalisation accompanies a signed document")
    if committed and (signed_by != record.signer or signed_utc != record.signed_utc):
        raise ValueError("a signed document must carry exactly the signer and time its finalisation rendered")
    return record


def _clinician_validation(raw: dict[str, Any]) -> doc_mod.ClinicianValidation:
    raw = _mapping(
        raw,
        required={
            "validation_id", "rubric_id", "rubric_version", "document_digest",
            "decision", "limitations_acknowledged", "feedback", "reviewed_by",
            "reviewed_utc",
        },
        where="clinician validation",
    )
    decision = _string(raw["decision"], "clinician validation.decision")
    if decision not in {"ready-to-sign", "changes-required"}:
        raise ValueError("clinician validation decision is invalid")
    feedback = [
        _rubric_feedback(item)
        for item in _list(raw["feedback"], "clinician validation.feedback")
    ]
    _unique(
        [item.criterion_id for item in feedback],
        "clinician validation criterion feedback",
    )
    return doc_mod.ClinicianValidation(
        validation_id=_string(raw["validation_id"], "clinician validation.validation_id"),
        rubric_id=_string(raw["rubric_id"], "clinician validation.rubric_id"),
        rubric_version=_string(
            raw["rubric_version"], "clinician validation.rubric_version"
        ),
        document_digest=_sha256(
            raw["document_digest"], "clinician validation.document_digest"
        ),
        decision=decision,
        limitations_acknowledged=_boolean(
            raw["limitations_acknowledged"],
            "clinician validation.limitations_acknowledged",
        ),
        feedback=tuple(feedback),
        reviewed_by=_string(raw["reviewed_by"], "clinician validation.reviewed_by"),
        reviewed_utc=_string(raw["reviewed_utc"], "clinician validation.reviewed_utc"),
    )


def _sketch(raw: dict[str, Any]) -> doc_mod.Sketch:
    raw = _mapping(
        raw,
        required={"sketch_id", "title", "caption", "author", "created_utc", "asset"},
        optional={"included_source_id"},
        where="sketch",
    )
    return doc_mod.Sketch(
        sketch_id=_string(raw["sketch_id"], "sketch.sketch_id"),
        title=_string(raw["title"], "sketch.title"),
        caption=_string(raw["caption"], "sketch.caption"),
        author=_string(raw["author"], "sketch.author"),
        created_utc=_string(raw["created_utc"], "sketch.created_utc"),
        asset=_asset(raw["asset"]),
        included_source_id=_string(
            raw.get("included_source_id", ""), "sketch.included_source_id"
        ),
    )


def _source(raw: dict[str, Any]) -> doc_mod.Source:
    raw = _mapping(
        raw,
        required={"source_id", "kind", "title", "author", "dated", "fragments"},
        optional={"sketch", "case_asset", "recording"},
        where="source",
    )
    kind = _string(raw["kind"], "source.kind")
    if kind not in doc_mod.SOURCE_KINDS:
        raise ValueError("source.kind is not supported")
    source = doc_mod.Source(
        _string(raw["source_id"], "source.source_id"),
        kind,
        _string(raw["title"], "source.title"),
        _string(raw["author"], "source.author"),
        _string(raw["dated"], "source.dated"),
        [_fragment(f) for f in _list(raw["fragments"], "source.fragments")],
        _asset(raw["sketch"]) if raw.get("sketch") is not None else None,
        _case_asset(raw["case_asset"])
        if raw.get("case_asset") is not None else None,
        _recording(raw["recording"])
        if raw.get("recording") is not None else None,
    )
    if source.recording is not None:
        if (source.kind != "transcript" or source.case_asset is None
                or not source.case_asset.media_type.startswith("audio/")):
            raise ValueError("recording provenance requires an audio transcript")
        if audio_mod.transcript_digest(
            "\n".join(fragment.text for fragment in source.fragments)
        ) != source.recording.transcript_digest:
            raise ValueError("recording transcript digest mismatch")
        offsets = [fragment.started_ms for fragment in source.fragments]
        if any(value is None for value in offsets):
            raise ValueError("recording transcript offsets are invalid")
        valid_offsets = [cast(int, value) for value in offsets]
        if (valid_offsets != sorted(valid_offsets)
                or any(value < 0 or value > source.recording.duration_ms
                       for value in valid_offsets)):
            raise ValueError("recording transcript offsets are invalid")
    return source


def _paragraph(raw: dict[str, Any]) -> doc_mod.Paragraph:
    raw = _mapping(
        raw,
        required={"text", "evidence_class", "citations", "origin"},
        where="paragraph",
    )
    evidence_class = _string(raw["evidence_class"], "paragraph.evidence_class")
    origin = _string(raw["origin"], "paragraph.origin")
    if evidence_class not in doc_mod.EVIDENCE_LABEL:
        raise ValueError("paragraph.evidence_class is not supported")
    if origin not in {doc_mod.EXTRACTED, doc_mod.CLINICIAN}:
        raise ValueError("paragraph.origin is not supported")
    return doc_mod.Paragraph(
        _string(raw["text"], "paragraph.text"),
        evidence_class,
        [_citation(c) for c in _list(raw["citations"], "paragraph.citations")],
        origin,
    )


def _citation(raw: dict[str, Any]) -> doc_mod.Citation:
    raw = _mapping(
        raw, required={"source_id", "locator"}, where="citation"
    )
    return doc_mod.Citation(
        _string(raw["source_id"], "citation.source_id"),
        _integer(raw["locator"], "citation.locator"),
    )


def _section(raw: dict[str, Any]) -> doc_mod.DocSection:
    raw = _mapping(
        raw,
        required={"name", "guidance", "paragraphs"},
        optional={"index", "offered"},
        where="document section",
    )
    return doc_mod.DocSection(
        _string(raw["name"], "section.name"),
        _string(raw["guidance"], "section.guidance"),
        [_paragraph(p) for p in _list(raw["paragraphs"], "section.paragraphs")],
        index=_boolean(raw.get("index", False), "section.index"),
        offered=[
            _paragraph(p) for p in _list(raw.get("offered", []), "section.offered")
        ],
    )


def _version(raw: dict[str, Any]) -> dict[str, str]:
    raw = _mapping(
        raw, required={"utc", "digest", "note"}, where="document version"
    )
    return {
        "utc": _string(raw["utc"], "version.utc"),
        "digest": _string(raw["digest"], "version.digest"),
        "note": _string(raw["note"], "version.note"),
    }


def _document(raw: dict[str, Any]) -> doc_mod.Document:
    raw = _mapping(
        raw,
        required={
            "doc_id", "template_id", "template_name", "title", "case_ref",
            "subject_ref", "created_utc", "sections", "sources", "status",
            "signed_by", "signed_utc", "frozen_digest", "versions",
        },
        optional={
            "frozen_export_digest", "frozen_export_digest_version",
            "sample_note", "unplaced", "model_receipts", "validations", "finalisation",
        },
        where="document",
    )
    sources = [_source(s) for s in _list(raw["sources"], "document.sources")]
    _unique([source.source_id for source in sources], "document sources")
    template_id = _string(raw["template_id"], "document.template_id")
    template = tpl_mod.TEMPLATES.get(template_id)
    if template is None:
        raise ValueError("document.template_id is not supported")
    template_name = _string(raw["template_name"], "document.template_name")
    if template_name != template.name:
        raise ValueError("document.template_name does not match its template")
    status = _string(raw["status"], "document.status")
    signed_by = _optional_string(raw["signed_by"], "document.signed_by")
    signed_utc = _optional_string(raw["signed_utc"], "document.signed_utc")
    frozen_digest_raw = raw["frozen_digest"]
    frozen_export_raw = raw.get("frozen_export_digest")
    frozen_export_version_raw = raw.get("frozen_export_digest_version")
    frozen_digest: str | None
    frozen_export_digest: str | None
    frozen_export_digest_version: int | None
    if status == doc_mod.SIGNED:
        if not signed_by or not signed_utc or frozen_digest_raw is None:
            raise ValueError("signed document has incomplete signature state")
        frozen_digest = _sha256(frozen_digest_raw, "document.frozen_digest")
        frozen_export_digest = (
            _sha256(frozen_export_raw, "document.frozen_export_digest")
            if frozen_export_raw is not None else None
        )
        frozen_export_digest_version = (
            _integer(
                frozen_export_version_raw,
                "document.frozen_export_digest_version",
            )
            if frozen_export_version_raw is not None else None
        )
        if frozen_export_digest is None and frozen_export_digest_version is not None:
            raise ValueError("export digest version exists without an export digest")
        if (frozen_export_digest_version is not None
                and frozen_export_digest_version not in {2, 3}):
            raise ValueError("document export digest version is not supported")
    elif status == doc_mod.DRAFT:
        if any(value is not None for value in (
            signed_by, signed_utc, frozen_digest_raw, frozen_export_raw,
            frozen_export_version_raw,
        )):
            raise ValueError("draft document carries signed-state fields")
        frozen_digest = None
        frozen_export_digest = None
        frozen_export_digest_version = None
    else:
        raise ValueError("document status is not draft or signed")
    sections = [
        section for section in map(
            _section, _list(raw["sections"], "document.sections")
        )
    ]
    if [section.name for section in sections] != [
        section.name for section in template.sections
    ]:
        raise ValueError("document sections do not match its template")
    document = doc_mod.Document(
        doc_id=_string(raw["doc_id"], "document.doc_id"),
        template_id=template_id,
        template_name=template_name,
        title=_string(raw["title"], "document.title"),
        case_ref=_string(raw["case_ref"], "document.case_ref"),
        subject_ref=_string(raw["subject_ref"], "document.subject_ref"),
        created_utc=_string(raw["created_utc"], "document.created_utc"),
        sections=sections,
        sources=sources,
        status=status,
        signed_by=signed_by,
        signed_utc=signed_utc,
        frozen_digest=frozen_digest,
        frozen_export_digest=frozen_export_digest,
        frozen_export_digest_version=frozen_export_digest_version,
        versions=[v for v in map(_version, _list(raw["versions"], "document.versions"))],
        sample_note=_string(raw.get("sample_note", ""), "document.sample_note"),
        unplaced=[
            _paragraph(p) for p in _list(raw.get("unplaced", []), "document.unplaced")
        ],
        model_receipts=[
            _model_receipt(item)
            for item in _list(raw.get("model_receipts", []), "document.model_receipts")
        ],
        validations=[
            _clinician_validation(item)
            for item in _list(raw.get("validations", []), "document.validations")
        ],
        finalisation=_finalisation(raw.get("finalisation"), status=status, signed_by=signed_by,
                                   signed_utc=signed_utc),
    )
    _unique(
        [item.validation_id for item in document.validations],
        "document clinician validations",
    )
    document.require_intact()
    return document


def _session(raw: dict[str, Any]) -> doc_mod.Session:
    raw = _mapping(
        raw,
        required={
            "session_id", "clinician", "title", "subject_ref", "created_utc",
            "sources", "documents",
        },
        optional={
            "owner_id", "workspace_id", "sketches", "audio", "read_only",
            "working_drafts",
            "model_suggestions",
            "pending_recording",
            "revision",
        },
        where="session",
    )
    sources = [_source(s) for s in _list(raw["sources"], "session.sources")]
    sketches = [_sketch(s) for s in _list(raw.get("sketches", []), "session.sketches")]
    documents = [_document(d) for d in _list(raw["documents"], "session.documents")]
    _unique([source.source_id for source in sources], "session sources")
    _unique([sketch.sketch_id for sketch in sketches], "session sketches")
    _unique([document.doc_id for document in documents], "session documents")
    session = doc_mod.Session(
        session_id=_string(raw["session_id"], "session.session_id"),
        clinician=_string(raw["clinician"], "session.clinician"),
        title=_string(raw["title"], "session.title"),
        subject_ref=_string(raw["subject_ref"], "session.subject_ref"),
        created_utc=_string(raw["created_utc"], "session.created_utc"),
        owner_id=_string(raw.get("owner_id", ""), "session.owner_id"),
        workspace_id=_string(raw.get("workspace_id", ""), "session.workspace_id"),
        sources=sources,
        sketches=sketches,
        documents=documents,
        working_drafts=_working_drafts(raw.get("working_drafts", {})),
        model_suggestions=[
            _model_suggestion(item)
            for item in _list(raw.get("model_suggestions", []), "session.model_suggestions")
        ],
        pending_recording=(
            _pending_recording(raw["pending_recording"])
            if raw.get("pending_recording") is not None else None
        ),
        audio=_string(raw.get("audio", ""), "session.audio"),
        read_only=_boolean(raw.get("read_only", False), "session.read_only"),
        revision=_integer(raw.get("revision", 0), "session.revision"),
    )
    source_by_id = {source.source_id: source for source in session.sources}
    if session.pending_recording is not None and session.transcript is not None:
        raise ValueError("session cannot carry pending and completed transcription")
    for sketch in session.sketches:
        if not sketch.included_source_id:
            continue
        source = source_by_id.get(sketch.included_source_id)
        caption = source.fragments[0].text if source and source.fragments else ""
        if (source is None or source.kind != "sketch"
                or source.sketch != sketch.asset
                or source.title != sketch.title
                or source.author != sketch.author
                or source.dated != sketch.created_utc
                or caption != sketch.caption):
            raise ValueError("included sketch does not match its evidence source")
    document_by_id = {document.doc_id: document for document in session.documents}
    _unique(
        [item.suggestion_id for item in session.model_suggestions],
        "session model suggestions",
    )
    for suggestion in session.model_suggestions:
        document = document_by_id.get(suggestion.doc_id)
        if document is None:
            raise ValueError("model suggestion does not match its document or receipt")
        if suggestion.section not in {section.name for section in document.sections}:
            raise ValueError("model suggestion section is not in its document")
        if any(not quote for quote in suggestion.exact_quotes):
            raise ValueError("model suggestion carries an empty evidence quote")
        adopted = any(
            receipt.run_id == suggestion.receipt.run_id
            and suggestion.suggestion_id in receipt.adopted_suggestion_ids
            for receipt in document.model_receipts
        )
        if adopted != (suggestion.status == "adopted"):
            raise ValueError("model suggestion adoption receipt is inconsistent")
    return session


class Store:
    """Sessions on disk, scoped to their owner."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._sessions: dict[str, doc_mod.Session] = {}
        self._load_error = ""
        self._source_bytes = b""
        self._source_digest = ""
        self._quarantined: dict[str, dict[str, Any]] = {}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    # -- disk ------------------------------------------------------------
    def _load(self) -> None:
        self._sessions = {}
        self._load_error = ""
        self._source_bytes = b""
        self._source_digest = ""
        self._quarantined = {}
        if not self._path.exists():
            return
        try:
            source_bytes = self._path.read_bytes()
            raw = json.loads(source_bytes.decode("utf-8"))
            root = _mapping(raw, required={"sessions"}, where="store")
            entries = _list(root["sessions"], "store.sessions")
        except (KeyError, OSError, TypeError, UnicodeDecodeError, ValueError):
            self._degrade()
            return
        identities: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                self._degrade()
                return
            raw_id = entry.get("session_id")
            if not isinstance(raw_id, str) or not raw_id:
                self._degrade()
                return
            identities.append(raw_id)
        if len(identities) != len(set(identities)):
            self._degrade()
            return
        loaded: dict[str, doc_mod.Session] = {}
        quarantined: dict[str, dict[str, Any]] = {}
        for entry in entries:
            try:
                session = _session(entry)
            except (KeyError, TypeError, ValueError):
                identity = self._quarantine_identity(entry)
                if identity is None:
                    self._degrade()
                    return
                quarantined[identity] = entry
                continue
            loaded[session.session_id] = session
        self._sessions = loaded
        self._source_bytes = source_bytes
        self._source_digest = _digest(source_bytes)
        self._quarantined = quarantined

    @staticmethod
    def _quarantine_identity(entry: dict[str, Any]) -> str | None:
        """Return an attributable session id, or refuse selective recovery."""

        session_id = entry.get("session_id")
        owner_id = entry.get("owner_id")
        workspace_id = entry.get("workspace_id")
        if not all(
            isinstance(item, str) and bool(item.strip())
            for item in (session_id, owner_id, workspace_id)
        ):
            return None
        assert isinstance(session_id, str)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
            return None
        return session_id

    def _degrade(self) -> None:
        self._load_error = (
            "The consultation store failed an integrity check. Its original "
            "file is preserved, and all reads and writes are stopped until "
            "the store is repaired."
        )

    def _require_healthy(self) -> None:
        if self._load_error:
            raise StoreDegraded(self._load_error)

    def _require_writable(self) -> None:
        self._require_healthy()
        if self._quarantined:
            raise StoreRecoveryRequired(
                "One or more attributable consultations failed integrity checks. "
                "Unaffected consultations remain readable, but writes are stopped "
                "until an operator previews and confirms the versioned quarantine."
            )

    @property
    def degraded(self) -> bool:
        """Whether durable state is unavailable and must not be rewritten."""

        with self._lock:
            return bool(self._load_error)

    @property
    def recovery_required(self) -> bool:
        with self._lock:
            return bool(self._quarantined) and not self._load_error

    def recovery_preview(self) -> dict[str, Any]:
        """Describe an attributable repair without exposing clinical payloads."""

        with self._lock:
            self._require_healthy()
            return {
                "schema_version": "health-store-recovery/v1",
                "source_digest": self._source_digest,
                "active_count": len(self._sessions),
                "quarantined": [
                    {
                        "session_id": session_id,
                        "artifact_digest": _digest(_canonical_bytes(raw)),
                    }
                    for session_id, raw in sorted(self._quarantined.items())
                ],
            }

    @property
    def _recovery_root(self) -> Path:
        return self._path.parent / f"{self._path.stem}.recovery"

    @staticmethod
    def _write_once(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if path.read_bytes() != data:
                raise StoreDegraded("a recovery artifact failed its immutable check")

    def confirm_quarantine(self, expected_source_digest: str) -> dict[str, Any]:
        """Preserve, validate and atomically activate one explicit repair."""

        with self._lock:
            self._require_healthy()
            if not self._quarantined:
                raise ValueError("there is no attributable quarantine to confirm")
            current = self._path.read_bytes()
            if (
                expected_source_digest != self._source_digest
                or _digest(current) != self._source_digest
            ):
                raise StoreRecoveryRequired(
                    "the consultation store changed after preview; preview it again"
                )
            transaction = self._recovery_root / self._source_digest
            backup = transaction / "original-sessions.json"
            self._write_once(backup, self._source_bytes)
            objects: list[dict[str, str]] = []
            for session_id, raw in sorted(self._quarantined.items()):
                payload = _canonical_bytes(raw)
                address = _digest(payload)
                self._write_once(transaction / "objects" / f"{address}.json", payload)
                objects.append({"session_id": session_id, "artifact_digest": address})
            manifest = {
                "schema_version": "health-store-recovery/v1",
                "created_utc": _utc_now(),
                "source_digest": self._source_digest,
                "backup_digest": _digest(self._source_bytes),
                "active_session_ids": sorted(self._sessions),
                "quarantined": objects,
                "action": "confirmed-quarantine",
            }
            self._write_once(
                transaction / "manifest.json",
                json.dumps(manifest, indent=1, ensure_ascii=False).encode("utf-8"),
            )
            # Every surviving record is re-parsed before the atomic replacement.
            for session in self._sessions.values():
                _session(_encode(session))
            self._quarantined = {}
            try:
                self._flush(self._sessions)
                repaired = Store(self._path)
                if repaired.degraded or repaired.recovery_required:
                    raise StoreDegraded("the repaired store failed post-repair checks")
            except Exception:
                self._write_restore_bytes(self._source_bytes)
                self._load()
                raise
            self._source_bytes = self._path.read_bytes()
            self._source_digest = _digest(self._source_bytes)
            return manifest

    def _write_restore_bytes(self, data: bytes) -> None:
        tmp = self._path.with_suffix(".recovery-restore.tmp")
        tmp.write_bytes(data)
        tmp.replace(self._path)

    def rollback_recovery(self, source_digest: str) -> None:
        """Restore the exact immutable pre-repair bytes for one transaction."""

        with self._lock:
            backup = (
                self._recovery_root / source_digest / "original-sessions.json"
            )
            data = backup.read_bytes()
            if _digest(data) != source_digest:
                raise StoreDegraded("the recovery backup failed its digest check")
            rollback = {
                "schema_version": "health-store-recovery/v1",
                "action": "rollback",
                "source_digest": source_digest,
                "replaced_digest": (
                    _digest(self._path.read_bytes()) if self._path.exists() else ""
                ),
                "rolled_back_utc": _utc_now(),
            }
            rollback_path = (
                self._recovery_root / source_digest / "rollback.json"
            )
            if not rollback_path.exists():
                self._write_once(
                    rollback_path,
                    json.dumps(rollback, indent=1).encode("utf-8"),
                )
            self._write_restore_bytes(data)
            self._load()

    def _flush(self, sessions: dict[str, doc_mod.Session]) -> None:
        payload = {"sessions": [_encode(s) for s in sessions.values()]}
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8",
                           newline="\n")
            tmp.replace(self._path)
        except OSError as exc:
            self._degrade()
            raise StoreDegraded(self._load_error) from exc

    # -- api -------------------------------------------------------------
    def save(self, session: doc_mod.Session) -> None:
        """Compare-and-set: written only while `session.revision` is still the stored revision."""
        with self._lock:
            self._require_writable()
            current = self._sessions.get(session.session_id)
            if session.revision != (current.revision if current is not None else 0):
                raise StaleSession("this consultation changed since it was read; reload and try again")
            stored = copy.deepcopy(session)
            stored.revision += 1
            candidate = dict(self._sessions)
            candidate[session.session_id] = stored
            self._flush(candidate)
            self._sessions = candidate
            session.revision = stored.revision

    def get(self, session_id: str, owner_id: str) -> doc_mod.Session | None:
        """A session, only for its stable tenant-scoped owner."""

        with self._lock:
            self._require_healthy()
            quarantined = self._quarantined.get(session_id)
            if quarantined is not None:
                if quarantined.get("owner_id") == owner_id:
                    raise StoreRecoveryRequired(
                        "This consultation is quarantined pending operator recovery."
                    )
                return None
            found = self._sessions.get(session_id)
            if found is None or not found.owner_id or found.owner_id != owner_id:
                return None
            # Each request works on its own copy; the stored session changes only through a compare-and-set save.
            return copy.deepcopy(found)

    def list_for(self, owner_id: str) -> list[doc_mod.Session]:
        with self._lock:
            self._require_healthy()
            mine = [copy.deepcopy(s) for s in self._sessions.values()
                    if s.owner_id and s.owner_id == owner_id]
        return sorted(mine, key=lambda s: s.created_utc, reverse=True)

    def delete(self, session_id: str, owner_id: str) -> bool:
        with self._lock:
            self._require_writable()
            found = self._sessions.get(session_id)
            if found is None or not found.owner_id or found.owner_id != owner_id:
                return False
            candidate = dict(self._sessions)
            del candidate[session_id]
            self._flush(candidate)
            self._sessions = candidate
            return True

    def claim_legacy(
        self, clinician_label: str, owner_id: str, workspace_id: str
    ) -> int:
        """Assign pre-identity cases through an explicit operator action.

        Historical records have only a self-asserted display label.  They are
        never claimed automatically at login because identical names can exist
        in different practices.  The bootstrap tool calls this method only
        when an operator names the exact legacy label and target account.
        """

        if not clinician_label or not owner_id or not workspace_id:
            raise ValueError("legacy claim requires label, owner and workspace")
        with self._lock:
            self._require_writable()
            candidate = copy.deepcopy(self._sessions)
            claimed = 0
            for session in candidate.values():
                if session.owner_id or session.clinician != clinician_label:
                    continue
                session.owner_id = owner_id
                session.workspace_id = workspace_id
                claimed += 1
            if claimed:
                self._flush(candidate)
                self._sessions = candidate
            return claimed
