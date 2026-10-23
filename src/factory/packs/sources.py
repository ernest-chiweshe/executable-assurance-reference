"""The knowledge sources lock: which standards, regulations and literature a pack's rules rest on.

Research finding carried here: a pack must lock its "canonical source, edition/effective date, digest,
licence, jurisdiction" (bundle anatomy ``knowledge/sources.lock``) and a decision receipt must pin the
source-lock digest (research gate 9). SEC taxonomies, FHIR packages and 1EdTech specifications are
all *editions*; a rule that cites "the standard" without an edition cannot be re-verified later.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

SOURCE_KINDS = ("standard", "regulation", "guidance", "literature", "organization-policy")
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z0-9-]+)*$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_URL = re.compile(r"^https?://\S+$")
_JURISDICTION = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$|^global$")


class SourceError(ValueError):
    """A source lock entry is incomplete; the message lists every defect."""


@dataclass(frozen=True, slots=True)
class SourceLock:
    id: str
    title: str
    kind: str
    edition: str                       # version or edition label ("1.2", "Act 4 of 2013", "2nd ed.")
    effective_date: str                # ISO date the edition took effect or was published
    licence: str
    jurisdiction: str
    url: str = ""                      # empty for licensed text obtained offline
    digest: str = ""                   # sha256 of the locked text where the licence allows storing it

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "kind": self.kind, "edition": self.edition,
                "effective_date": self.effective_date, "licence": self.licence, "jurisdiction": self.jurisdiction,
                "url": self.url, "digest": self.digest}


def validate_sources(raw: Any, *, required: bool = True) -> list[str]:
    if raw is None or raw == []:
        return ["knowledge.sources must name at least one locked source"] if required else []
    if not isinstance(raw, list):
        return ["knowledge.sources must be a list"]
    p: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or not _SOURCE_ID.fullmatch(str(entry.get("id", ""))):
            p.append(f"source {entry!r}: id must be a lowercase dotted identifier")
            continue
        sid = str(entry["id"])
        if sid in seen:
            p.append(f"source {sid}: locked twice")
        seen.add(sid)
        if entry.get("kind") not in SOURCE_KINDS:
            p.append(f"source {sid}: kind must be one of {list(SOURCE_KINDS)}")
        for key in ("title", "edition", "licence"):
            if not str(entry.get(key, "")).strip():
                p.append(f"source {sid}: {key} is required")
        if not _DATE.fullmatch(str(entry.get("effective_date", ""))):
            p.append(f"source {sid}: effective_date must be an ISO date (YYYY-MM-DD)")
        if not _JURISDICTION.fullmatch(str(entry.get("jurisdiction", ""))):
            p.append(f"source {sid}: jurisdiction must be an ISO country code (optionally -region) or 'global'")
        url = str(entry.get("url", "") or "")
        if url and not _URL.fullmatch(url):
            p.append(f"source {sid}: url must be http(s) or empty for licensed text")
        digest = str(entry.get("digest", "") or "")
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            p.append(f"source {sid}: digest must be sha256 hex or empty")
    return p


def sources_from_list(raw: Any, *, required: bool = True) -> tuple[SourceLock, ...]:
    problems = validate_sources(raw, required=required)
    if problems:
        raise SourceError("; ".join(problems))
    return tuple(SourceLock(str(e["id"]), str(e["title"]), str(e["kind"]), str(e["edition"]), str(e["effective_date"]),
                            str(e["licence"]), str(e["jurisdiction"]), str(e.get("url", "") or ""), str(e.get("digest", "") or ""))
                 for e in (raw or []))


def sources_digest(sources: Iterable[SourceLock]) -> str:
    encoded = json.dumps([s.to_dict() for s in sorted(sources, key=lambda s: s.id)], sort_keys=True,
                         separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def vocabulary_problems(vocabularies: Iterable[str], sources: Iterable[SourceLock]) -> list[str]:
    """Every ``name@edition`` vocabulary a pack claims must be a locked source of kind ``standard`` at that edition."""
    standards = {s.id: s.edition for s in sources if s.kind == "standard"}
    p: list[str] = []
    for vocab in vocabularies:
        name, _, edition = vocab.partition("@")
        if name not in standards:
            p.append(f"vocabulary {vocab}: no locked source of kind standard with id {name!r}")
        elif standards[name] != edition:
            p.append(f"vocabulary {vocab}: the locked edition of {name} is {standards[name]!r}")
    return p


__all__ = ["SOURCE_KINDS", "SourceError", "SourceLock", "sources_digest", "sources_from_list", "validate_sources",
           "vocabulary_problems"]
