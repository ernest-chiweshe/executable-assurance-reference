"""Secure, provenance-preserving intake for clinical case material.

The raw upload is evidence.  It is therefore identified by the digest of the
exact bytes, stored outside the JSON consultation record, and never silently
replaced by extracted text.  Extraction produces page/paragraph fragments that
point back to that immutable asset.

This module performs no network call.  PDF parsing and OCR are optional local
adapters: when they are unavailable the asset remains preserved with an honest
``extractor-unavailable`` status instead of pretending an empty document was
successfully read.
"""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import re
import secrets
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast
from xml.etree import ElementTree as ET

MAX_FILES = 20
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_TEXT_CHARS = 2_000_000
MAX_PDF_PAGES = 1_000
MAX_DOCX_ENTRIES = 2_000
MAX_DOCX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_ZIP_RATIO = 100
MAX_IMAGE_PIXELS = 25_000_000

_SAFE_NAME = re.compile(r"[^A-Za-z0-9 ._()\[\]-]+")
_PDF_ACTIVE_MARKERS = (
    b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction",
    b"/EmbeddedFile", b"/EmbeddedFiles", b"/RichMedia",
)
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"


class IntakeRefused(ValueError):
    """The bytes are unsafe, unsupported or outside the bounded envelope."""


class ExtractionUnavailable(RuntimeError):
    """A safe local extractor is not installed or configured."""


@dataclass(frozen=True)
class ExtractedFragment:
    locator: int
    label: str
    text: str


@dataclass(frozen=True)
class AssetReceipt:
    asset_id: str
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    extraction_status: str
    extraction_method: str
    page_count: int
    missing_pages: tuple[int, ...]
    fragments: tuple[ExtractedFragment, ...]


class CaseAssetStore(Protocol):
    """Durable byte and metadata authority for uploaded case material."""

    def save(
        self, owner_id: str, session_id: str, receipt: AssetReceipt, content: bytes
    ) -> bool: ...

    def save_batch(
        self,
        owner_id: str,
        session_id: str,
        items: Iterable[tuple[AssetReceipt, bytes]],
    ) -> list[str]: ...

    def remove(self, owner_id: str, session_id: str, asset_id: str) -> None: ...

    def remove_session(self, owner_id: str, session_id: str) -> int: ...

    def load(
        self, owner_id: str, session_id: str, asset_id: str
    ) -> tuple[AssetReceipt, bytes]: ...


class OcrEngine(Protocol):
    """Offline OCR adapter; implementations must not transmit case bytes."""

    def image_text(self, content: bytes, media_type: str) -> str: ...


class _PillowImage(Protocol):
    size: tuple[int, int]

    def verify(self) -> None: ...

    def __enter__(self) -> _PillowImage: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None: ...


class _PillowModule(Protocol):
    def open(self, stream: io.BytesIO) -> _PillowImage: ...


class _TesseractErrorNamespace(Protocol):
    TesseractNotFoundError: type[Exception]


class _TesseractModule(Protocol):
    pytesseract: _TesseractErrorNamespace

    def image_to_string(self, image: object, *, timeout: int) -> str: ...


def _optional_module(name: str) -> ModuleType:
    """Import one local-only OCR dependency without making it mandatory."""

    return importlib.import_module(name)


class TesseractOcr:
    """Bounded local OCR through Pillow and Tesseract, imported lazily."""

    def image_text(self, content: bytes, media_type: str) -> str:
        del media_type
        try:
            image_module = cast(_PillowModule, _optional_module("PIL.Image"))
            tesseract = cast(_TesseractModule, _optional_module("pytesseract"))
        except ModuleNotFoundError as exc:
            raise ExtractionUnavailable(
                "local OCR is unavailable; install Pillow, pytesseract and "
                "the Tesseract executable"
            ) from exc
        try:
            with image_module.open(io.BytesIO(content)) as probe:
                width, height = probe.size
                if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                    raise IntakeRefused("image dimensions exceed the clinical intake limit")
                probe.verify()
            with image_module.open(io.BytesIO(content)) as image:
                try:
                    text = tesseract.image_to_string(image, timeout=30)
                except tesseract.pytesseract.TesseractNotFoundError as exc:
                    raise ExtractionUnavailable(
                        "the local Tesseract executable is not installed"
                    ) from exc
        except IntakeRefused:
            raise
        except ExtractionUnavailable:
            raise
        except Exception as exc:  # local decoder/OCR failures become a clean refusal
            raise IntakeRefused("the image could not be decoded safely") from exc
        return _clean_text(text)


def safe_filename(filename: str) -> str:
    leaf = (filename or "upload").replace("\\", "/").rsplit("/", 1)[-1]
    leaf = "".join(ch for ch in leaf if ch >= " " and ch != "\x7f")
    cleaned = _SAFE_NAME.sub("_", leaf).strip(" .")[:180]
    return cleaned or "upload"


def _clean_text(value: str) -> str:
    text = value.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n")).strip()
    if len(text) > MAX_TEXT_CHARS:
        raise IntakeRefused("extracted text exceeds the clinical intake limit")
    return text


def _media_type(filename: str, content: bytes) -> str:
    low = filename.casefold()
    if content.startswith(b"%PDF-"):
        return "application/pdf"
    if content.startswith(b"PK\x03\x04") and low.endswith(".docx"):
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if low.endswith((".txt", ".md")):
        return "text/plain"
    raise IntakeRefused("supported case material is PDF, DOCX, TXT, PNG, JPEG or TIFF")


def _zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_DOCX_ENTRIES:
        raise IntakeRefused("the DOCX archive has an unsafe entry count")
    expanded = 0
    for member in members:
        name = member.filename.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or ".." in parts or "" in parts[:-1]:
            raise IntakeRefused("the DOCX contains an unsafe path")
        if member.flag_bits & 0x1:
            raise IntakeRefused("encrypted DOCX files are not supported")
        expanded += member.file_size
        if expanded > MAX_DOCX_EXPANDED_BYTES:
            raise IntakeRefused("the DOCX expands beyond the clinical intake limit")
        if member.file_size and member.compress_size == 0:
            raise IntakeRefused("the DOCX has an invalid compression ratio")
        if member.compress_size and member.file_size / member.compress_size > MAX_ZIP_RATIO:
            raise IntakeRefused("the DOCX compression ratio is unsafe")
    return members


def _docx_fragments(content: bytes) -> tuple[ExtractedFragment, ...]:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = _zip_members(archive)
            names = {item.filename.replace("\\", "/") for item in members}
            if "word/document.xml" not in names or "[Content_Types].xml" not in names:
                raise IntakeRefused("the upload is not a valid DOCX document")
            if any(name.startswith("word/embeddings/") or name.endswith("vbaProject.bin")
                   for name in names):
                raise IntakeRefused("embedded objects or macros are not accepted")
            for name in names:
                if not name.endswith(".rels"):
                    continue
                root = ET.fromstring(archive.read(name))
                if any(rel.get("TargetMode") == "External" for rel in root.iter(_REL + "Relationship")):
                    raise IntakeRefused("external DOCX relationships are not accepted")
            root = ET.fromstring(archive.read("word/document.xml"))
    except IntakeRefused:
        raise
    except (zipfile.BadZipFile, KeyError, ET.ParseError, OSError) as exc:
        raise IntakeRefused("the DOCX could not be decoded safely") from exc

    fragments: list[ExtractedFragment] = []
    extracted_chars = 0
    for paragraph in root.iter(_W + "p"):
        text = _clean_text("".join(node.text or "" for node in paragraph.iter(_W + "t")))
        if text:
            extracted_chars += len(text)
            if extracted_chars > MAX_TEXT_CHARS:
                raise IntakeRefused("extracted text exceeds the clinical intake limit")
            index = len(fragments)
            fragments.append(ExtractedFragment(index, f"¶{index + 1}", text))
    if not fragments:
        raise IntakeRefused("the DOCX contains no extractable text")
    return tuple(fragments)


def _pdf_fragments(content: bytes) -> tuple[tuple[ExtractedFragment, ...], int, tuple[int, ...]]:
    if any(marker in content for marker in _PDF_ACTIVE_MARKERS):
        raise IntakeRefused("active or embedded PDF content is not accepted")
    try:
        import pypdf
    except ModuleNotFoundError as exc:
        raise ExtractionUnavailable(
            "local PDF extraction is unavailable; install agent-factory[book]"
        ) from exc
    try:
        reader = pypdf.PdfReader(io.BytesIO(content), strict=False)
        if reader.is_encrypted:
            raise IntakeRefused("encrypted PDFs are not supported")
        if not reader.pages or len(reader.pages) > MAX_PDF_PAGES:
            raise IntakeRefused("the PDF page count is outside the clinical intake limit")
        fragments: list[ExtractedFragment] = []
        missing: list[int] = []
        extracted_chars = 0
        for index, page in enumerate(reader.pages):
            text = _clean_text(page.extract_text() or "")
            if text:
                extracted_chars += len(text)
                if extracted_chars > MAX_TEXT_CHARS:
                    raise IntakeRefused("extracted text exceeds the clinical intake limit")
                fragments.append(ExtractedFragment(index, f"p. {index + 1}", text))
            else:
                missing.append(index + 1)
    except IntakeRefused:
        raise
    except Exception as exc:
        raise IntakeRefused("the PDF could not be decoded safely") from exc
    return tuple(fragments), len(reader.pages), tuple(missing)


def _ocr_pdf_pages(
    content: bytes, pages: tuple[int, ...], ocr: OcrEngine
) -> tuple[ExtractedFragment, ...]:
    """Render only textless PDF pages and OCR them entirely on this host."""

    try:
        import fitz
    except ModuleNotFoundError as exc:
        raise ExtractionUnavailable(
            "scanned PDF OCR is unavailable; install agent-factory[health]"
        ) from exc
    fragments: list[ExtractedFragment] = []
    try:
        with fitz.open(stream=content, filetype="pdf") as document:
            for page_number in pages:
                page = document[page_number - 1]
                pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                if pixmap.width * pixmap.height > MAX_IMAGE_PIXELS:
                    raise IntakeRefused(
                        "a rendered PDF page exceeds the clinical intake limit"
                    )
                text = _clean_text(ocr.image_text(pixmap.tobytes("png"), "image/png"))
                if text:
                    fragments.append(
                        ExtractedFragment(page_number - 1, f"p. {page_number}", text)
                    )
    except (IntakeRefused, ExtractionUnavailable):
        raise
    except Exception as exc:
        raise IntakeRefused("the scanned PDF could not be rendered safely") from exc
    return tuple(fragments)


def inspect_upload(
    filename: str,
    content: bytes,
    *,
    ocr: OcrEngine | None = None,
) -> AssetReceipt:
    """Validate and extract one upload without writing it anywhere."""

    if not content:
        raise IntakeRefused("the uploaded file is empty")
    if len(content) > MAX_FILE_BYTES:
        raise IntakeRefused("the uploaded file exceeds 25 MiB")
    safe_name = safe_filename(filename)
    media = _media_type(safe_name, content)
    digest = hashlib.sha256(content).hexdigest()
    asset_id = f"asset-{digest[:20]}"
    status = "ready"
    method = "plain-text"
    missing: tuple[int, ...] = ()
    page_count = 1

    if media == "application/pdf":
        method = "pypdf"
        try:
            fragments, page_count, missing = _pdf_fragments(content)
            if missing:
                try:
                    recovered = _ocr_pdf_pages(
                        content, missing, ocr or TesseractOcr()
                    )
                except ExtractionUnavailable:
                    recovered = ()
                recovered_pages = {item.locator + 1 for item in recovered}
                missing = tuple(page for page in missing if page not in recovered_pages)
                fragments = tuple(sorted(
                    (*fragments, *recovered), key=lambda item: item.locator
                ))
                if recovered:
                    method = "pypdf+tesseract"
                if missing:
                    status = "partial-ocr-required" if fragments else "ocr-unavailable"
        except ExtractionUnavailable:
            fragments = ()
            page_count = 0
            status = "extractor-unavailable"
            method = "none"
    elif media.endswith("wordprocessingml.document"):
        fragments = _docx_fragments(content)
        method = "ooxml"
    elif media.startswith("image/"):
        method = "tesseract"
        try:
            text = (ocr or TesseractOcr()).image_text(content, media)
        except ExtractionUnavailable:
            text = ""
            status = "ocr-unavailable"
            method = "none"
        fragments = (ExtractedFragment(0, "image", text),) if text else ()
        if not text and status == "ready":
            status = "ocr-required"
    else:
        try:
            text = _clean_text(content.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise IntakeRefused("text uploads must be valid UTF-8") from exc
        if not text:
            raise IntakeRefused("the text upload contains no content")
        fragments = (ExtractedFragment(0, "¶1", text),)

    return AssetReceipt(
        asset_id=asset_id,
        filename=safe_name,
        media_type=media,
        size_bytes=len(content),
        sha256=digest,
        extraction_status=status,
        extraction_method=method,
        page_count=page_count,
        missing_pages=missing,
        fragments=fragments,
    )


def inspect_batch(
    uploads: Iterable[tuple[str, bytes]], *, ocr: OcrEngine | None = None
) -> list[tuple[AssetReceipt, bytes]]:
    """Validate a bounded multi-file batch before any asset is persisted."""

    items = list(uploads)
    if not items or len(items) > MAX_FILES:
        raise IntakeRefused("upload between 1 and 20 case-material files")
    if sum(len(content) for _, content in items) > MAX_TOTAL_BYTES:
        raise IntakeRefused("the upload batch exceeds 100 MiB")
    return [(inspect_upload(name, content, ocr=ocr), content) for name, content in items]


class AssetStore:
    """Immutable raw assets, partitioned by hashed owner and consultation IDs."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _partition(value: str) -> str:
        if not value:
            raise IntakeRefused("asset ownership is required")
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _folder(self, owner_id: str, session_id: str) -> Path:
        return self._root / self._partition(owner_id) / self._partition(session_id)

    def save(
        self, owner_id: str, session_id: str, receipt: AssetReceipt, content: bytes
    ) -> bool:
        if hashlib.sha256(content).hexdigest() != receipt.sha256:
            raise IntakeRefused("asset bytes no longer match their receipt")
        folder = self._folder(owner_id, session_id)
        folder.mkdir(parents=True, exist_ok=True)
        blob = folder / f"{receipt.asset_id}.bin"
        metadata = folder / f"{receipt.asset_id}.json"
        if blob.exists() or metadata.exists():
            existing = self.load(owner_id, session_id, receipt.asset_id)
            if existing[0].sha256 != receipt.sha256 or existing[1] != content:
                raise IntakeRefused("an asset identifier collision was refused")
            return False
        nonce = secrets.token_hex(6)
        blob_tmp = folder / f".{receipt.asset_id}.{nonce}.bin.tmp"
        meta_tmp = folder / f".{receipt.asset_id}.{nonce}.json.tmp"
        blob_committed = False
        metadata_committed = False
        try:
            with blob_tmp.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            with meta_tmp.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(asdict(receipt), handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(blob_tmp, blob)
            blob_committed = True
            os.replace(meta_tmp, metadata)
            metadata_committed = True
        except OSError:
            # This save observed both final paths absent before it began, so
            # any final path it committed belongs to this failed transaction.
            for path in (
                blob_tmp,
                meta_tmp,
                blob if blob_committed else None,
                metadata if metadata_committed else None,
            ):
                if path is None:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        return True

    def save_batch(
        self,
        owner_id: str,
        session_id: str,
        items: Iterable[tuple[AssetReceipt, bytes]],
    ) -> list[str]:
        """Persist a validated batch, rolling back files created by this call."""

        batch = list(items)
        for receipt, content in batch:
            if hashlib.sha256(content).hexdigest() != receipt.sha256:
                raise IntakeRefused("asset bytes no longer match their receipt")
        created: list[str] = []
        try:
            for receipt, content in batch:
                if self.save(owner_id, session_id, receipt, content):
                    created.append(receipt.asset_id)
        except Exception:
            for asset_id in created:
                self.remove(owner_id, session_id, asset_id)
            raise
        return created

    def remove(self, owner_id: str, session_id: str, asset_id: str) -> None:
        """Remove only an exact asset created during a failed higher transaction."""

        if not re.fullmatch(r"asset-[0-9a-f]{20}", asset_id):
            raise IntakeRefused("invalid asset identifier")
        folder = self._folder(owner_id, session_id)
        for suffix in (".bin", ".json"):
            try:
                (folder / f"{asset_id}{suffix}").unlink(missing_ok=True)
            except OSError as exc:
                raise IntakeRefused("the failed asset could not be rolled back") from exc

    def remove_session(self, owner_id: str, session_id: str) -> int:
        """Delete every raw asset for one already-deleted unsigned case.

        The directory names are fixed SHA-256 partitions, never caller paths.
        Unknown entries fail closed before any byte is removed so corruption or
        an operator file is not silently swept away as part of clinical-record
        retention.
        """

        folder = self._folder(owner_id, session_id)
        if not folder.exists():
            return 0
        try:
            entries = list(folder.iterdir())
        except OSError as exc:
            raise IntakeRefused("case assets could not be enumerated for deletion") from exc
        valid = re.compile(r"asset-[0-9a-f]{20}\.(?:bin|json)")
        if any(not path.is_file() or not valid.fullmatch(path.name) for path in entries):
            raise IntakeRefused("case asset deletion refused an unknown stored entry")
        try:
            for path in entries:
                path.unlink()
            folder.rmdir()
            owner_folder = folder.parent
            if not any(owner_folder.iterdir()):
                owner_folder.rmdir()
        except OSError as exc:
            raise IntakeRefused("case assets could not be completely deleted") from exc
        return len(entries) // 2

    def load(
        self, owner_id: str, session_id: str, asset_id: str
    ) -> tuple[AssetReceipt, bytes]:
        if not re.fullmatch(r"asset-[0-9a-f]{20}", asset_id):
            raise IntakeRefused("invalid asset identifier")
        folder = self._folder(owner_id, session_id)
        blob = folder / f"{asset_id}.bin"
        metadata = folder / f"{asset_id}.json"
        try:
            raw = json.loads(metadata.read_text(encoding="utf-8"))
            content = blob.read_bytes()
            raw["missing_pages"] = tuple(raw["missing_pages"])
            raw["fragments"] = tuple(
                ExtractedFragment(**item) for item in raw["fragments"]
            )
            receipt = AssetReceipt(**raw)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntakeRefused("the stored case asset failed integrity checks") from exc
        if receipt.asset_id != asset_id or hashlib.sha256(content).hexdigest() != receipt.sha256:
            raise IntakeRefused("the stored case asset failed its digest check")
        return receipt, content
