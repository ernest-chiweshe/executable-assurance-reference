"""Validation and provenance for durable consultation recordings."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

from factory.health_ui.intake import AssetReceipt, IntakeRefused, safe_filename

MAX_AUDIO_BYTES = 100 * 1024 * 1024
MAX_DURATION_MS = 4 * 60 * 60 * 1000


@dataclass(frozen=True)
class RecordingReceipt:
    asset: AssetReceipt
    duration_ms: int
    transcript_sha256: str
    captured_utc: str
    transcription_method: str
    browser_language: str
    turn_offsets_ms: tuple[int, ...]


@dataclass(frozen=True)
class RecordingUploadReceipt:
    """Exact audio preserved before a transcript has been accepted."""

    asset: AssetReceipt
    duration_ms: int
    captured_utc: str
    transcription_method: str
    browser_language: str


def transcript_digest(transcript: str) -> str:
    """Digest the stable non-empty turn text, independent of line endings."""

    canonical = "\n".join(
        line.strip() for line in transcript.replace("\r\n", "\n").split("\n")
        if line.strip()
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _audio_media_type(filename: str, content: bytes) -> str:
    low = filename.casefold()
    if content.startswith(b"\x1aE\xdf\xa3"):
        return "audio/webm"
    if content.startswith(b"OggS"):
        return "audio/ogg"
    if len(content) >= 12 and content.startswith(b"RIFF") and content[8:12] == b"WAVE":
        return "audio/wav"
    if content.startswith(b"ID3") or (
        len(content) >= 2 and content[0] == 0xFF and content[1] & 0xE0 == 0xE0
    ):
        return "audio/mpeg"
    if len(content) >= 12 and content[4:8] == b"ftyp" and low.endswith((".m4a", ".mp4")):
        return "audio/mp4"
    raise IntakeRefused("supported recordings are WebM, OGG, WAV, MP3 or M4A")


def inspect_recording(
    filename: str,
    content: bytes,
    *,
    transcript: str,
    duration_ms: int,
    captured_utc: str,
    transcription_method: str,
    browser_language: str,
    turn_offsets_ms: list[int],
) -> RecordingReceipt:
    """Validate exact recording bytes and bind the transcript provenance."""

    upload = inspect_recording_upload(
        filename,
        content,
        duration_ms=duration_ms,
        captured_utc=captured_utc,
        transcription_method=transcription_method,
        browser_language=browser_language,
    )
    if not transcript.strip():
        raise IntakeRefused("the recording has no transcript to bind")
    if any(type(value) is not int or value < 0 or value > duration_ms
           for value in turn_offsets_ms):
        raise IntakeRefused("a transcript turn lies outside the recording")
    if turn_offsets_ms != sorted(turn_offsets_ms):
        raise IntakeRefused("transcript turn times are not chronological")

    return RecordingReceipt(
        asset=replace(upload.asset, extraction_status="transcribed"),
        duration_ms=upload.duration_ms,
        transcript_sha256=transcript_digest(transcript),
        captured_utc=upload.captured_utc,
        transcription_method=upload.transcription_method,
        browser_language=upload.browser_language,
        turn_offsets_ms=tuple(turn_offsets_ms),
    )


def inspect_recording_upload(
    filename: str,
    content: bytes,
    *,
    duration_ms: int,
    captured_utc: str,
    transcription_method: str,
    browser_language: str,
) -> RecordingUploadReceipt:
    """Validate audio for durable storage without claiming it was transcribed."""

    if not content:
        raise IntakeRefused("the consultation recording is empty")
    if len(content) > MAX_AUDIO_BYTES:
        raise IntakeRefused("the consultation recording exceeds 100 MiB")
    if type(duration_ms) is not int or not 1 <= duration_ms <= MAX_DURATION_MS:
        raise IntakeRefused("recording duration is outside the clinical limit")
    if not captured_utc:
        raise IntakeRefused("recording capture time is required")
    if transcription_method not in {
        "browser-speech-recognition", "browser-playback-speech-recognition"
    }:
        raise IntakeRefused("unknown transcription method")
    if not browser_language or len(browser_language) > 35:
        raise IntakeRefused("browser transcription language is invalid")
    clean_name = safe_filename(filename)
    media_type = _audio_media_type(clean_name, content)
    digest = hashlib.sha256(content).hexdigest()
    return RecordingUploadReceipt(
        asset=AssetReceipt(
            asset_id=f"asset-{digest[:20]}",
            filename=clean_name,
            media_type=media_type,
            size_bytes=len(content),
            sha256=digest,
            extraction_status="recording-preserved",
            extraction_method=transcription_method,
            page_count=0,
            missing_pages=(),
            fragments=(),
        ),
        duration_ms=duration_ms,
        captured_utc=captured_utc,
        transcription_method=transcription_method,
        browser_language=browser_language,
    )
