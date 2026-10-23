"""Teacher-owned lessons and immutable class assignments in pack-declared storage.

This is a domain service, not a second enrollment or assessment authority.
Existing signed exercise files and governed feedback release stay separate.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from factory.packs.collections import CollectionConflict, PackDocument
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import InstalledPack
from .service import WorkbenchError, digest

if TYPE_CHECKING:
    from .service import EducationWorkbench


def available(pack: InstalledPack) -> bool:
    return all(pack.collection_or_none(name) for name in ("teaching-lesson", "teaching-assignment"))


def lesson_content(value: Any) -> dict[str, Any]:
    limits = {"title": 200, "objective": 2000, "prompt": 10000, "success_criteria": 4000,
              "sequence": 200, "source_notes": 4000, "resource_url": 2000}
    if not isinstance(value, dict) or set(value) != set(limits) | {"position", "pathway", "hints"}:
        raise WorkbenchError(400, "A complete structured lesson is required.")
    for name, maximum in limits.items():
        text = value[name]
        if not isinstance(text, str) or len(text) > maximum or (name not in {"resource_url"} and not text.strip()):
            raise WorkbenchError(400, f"Provide a bounded {name.replace('_', ' ')}.")
    if type(value["position"]) is not int or not 1 <= value["position"] <= 1000:
        raise WorkbenchError(400, "Sequence position must be between 1 and 1000.")
    if not isinstance(value["pathway"], str) or value["pathway"] not in {"form-1", "form-5", "exam-recovery", "practical-skills"}:
        raise WorkbenchError(400, "Choose a supported learning pathway.")
    hints = value["hints"]
    if not isinstance(hints, list) or len(hints) > 5 or any(not isinstance(h, str) or not 1 <= len(h.strip()) <= 2000 for h in hints):
        raise WorkbenchError(400, "Supply at most five bounded teacher hints.")
    if value["resource_url"]:
        try:
            url = urlsplit(value["resource_url"])
            safe = url.scheme == "https" and bool(url.hostname) and not url.username and not url.password
        except ValueError:
            safe = False
        if not safe:
            raise WorkbenchError(400, "An optional lesson resource must be an HTTPS link without credentials.")
    return dict(json.loads(json.dumps(value, allow_nan=False)))


class TeachingLibrary:
    def __init__(self, workbench: EducationWorkbench):
        self.workbench = workbench

    def authority(self, tenant: str, principal: str, class_id: str, *, teacher: bool = False) -> InstalledPack:
        pack, role = self.workbench.authority(tenant, principal, class_id)
        if teacher and role != "teacher":
            raise WorkbenchError(403, "Only an enrolled teacher can author or assign lessons.")
        if not available(pack):
            raise WorkbenchError(503, "The active Education pack does not yet declare teacher lesson storage. Built-in exercises remain available.")
        return pack

    def lessons(self, tenant: str, principal: str, class_id: str, after: str | None = None) -> dict[str, Any]:
        self.authority(tenant, principal, class_id, teacher=True)
        rows, cursor = self.scoped_page(tenant, "teaching-lesson", class_id, after, principal=principal)
        return {"items": [r.to_dict() for r in rows], "next_cursor": cursor}

    def scoped_page(self, tenant: str, collection: str, class_id: str, after: str | None,
                    *, principal: str | None = None) -> tuple[tuple[PackDocument, ...], str | None]:
        # The shared store pages by tenant. Skip unrelated bounded pages rather
        # than reporting an empty class/library while its first item is later.
        while True:
            rows, cursor = self.workbench.page(tenant, collection, after)
            matches = tuple(r for r in rows if r.payload["classId"] == class_id
                            and (principal is None or r.payload["principal"] == principal))
            if matches or cursor is None:
                return matches, cursor
            if after is not None and cursor <= after:
                raise WorkbenchError(503, "Teaching pagination did not advance. Reload to reconcile.")
            after = cursor

    def save(self, tenant: str, principal: str, class_id: str, ident: str, value: Any, expected: Any, key: str) -> PackDocument:
        pack = self.authority(tenant, principal, class_id, teacher=True)
        content = lesson_content(value)
        if expected is not None and (type(expected) is not int or expected < 1):
            raise WorkbenchError(400, "Expected lesson revision must be a positive integer or null.")
        if not ident:
            if expected is not None or not 1 <= len(key) <= 100:
                raise WorkbenchError(400, "A new lesson requires an idempotency key and no prior revision.")
            ident = digest(["lesson", principal, class_id, key])
        prior = self.workbench.store.get(EDUCATION_ID, "teaching-lesson", tenant, ident)
        if prior and (prior.payload["classId"] != class_id or prior.payload["principal"] != principal):
            raise WorkbenchError(404, "Lesson not found for this teacher and class.")
        if prior and expected is None and prior.payload["content"] == content:
            return prior
        if expected is not None and prior is None:
            raise WorkbenchError(404, "Lesson not found.")
        try:
            return self.workbench.write(pack, tenant, principal, class_id, "", "teaching-lesson", ident, content, expected, require_role="teacher")
        except CollectionConflict:
            latest = self.workbench.store.get(EDUCATION_ID, "teaching-lesson", tenant, ident)
            if latest and latest.version == (1 if expected is None else expected + 1) and latest.payload["content"] == content:
                return latest
            raise

    def assign(self, tenant: str, principal: str, class_id: str, lesson_id: str, expected: Any, key: str) -> PackDocument:
        pack = self.authority(tenant, principal, class_id, teacher=True)
        if type(expected) is not int or expected < 1 or not 1 <= len(key) <= 100:
            raise WorkbenchError(400, "A saved lesson revision and bounded idempotency key are required.")
        lesson = self.workbench.store.get(EDUCATION_ID, "teaching-lesson", tenant, lesson_id)
        if lesson is None or lesson.payload["classId"] != class_id or lesson.payload["principal"] != principal:
            raise WorkbenchError(404, "Lesson not found for this teacher and class.")
        ident = "assignment-" + digest([principal, class_id, key])
        prior = self.workbench.store.get(EDUCATION_ID, "teaching-assignment", tenant, ident)
        if prior:
            if prior.payload["content"]["lesson_id"] != lesson_id or prior.payload["content"]["lesson_version"] != expected:
                raise CollectionConflict("Assignment key was already used for a different lesson revision.")
            return prior
        if lesson.version != expected:
            raise CollectionConflict("The lesson changed. Reread it before assigning this revision.")
        content = {"lesson_id": lesson.key, "lesson_version": lesson.version, "lesson_digest": lesson.digest,
                   "lesson": lesson_content(lesson.payload["content"]), "authority": "teacher-authored-not-publisher-verified"}
        try:
            return self.workbench.write(pack, tenant, principal, class_id, ident, "teaching-assignment", ident, content, None, require_role="teacher")
        except CollectionConflict:
            prior = self.workbench.store.get(EDUCATION_ID, "teaching-assignment", tenant, ident)
            if prior and prior.payload["content"] == content:
                return prior
            raise

    def assignment(self, pack: InstalledPack, tenant: str, class_id: str, ident: str) -> PackDocument | None:
        if not available(pack):
            return None
        row = self.workbench.store.get(EDUCATION_ID, "teaching-assignment", tenant, ident)
        return row if row and row.payload["classId"] == class_id else None

    @staticmethod
    def exercise(row: PackDocument) -> dict[str, Any]:
        content = row.payload["content"]
        lesson = lesson_content(content["lesson"])
        return {**lesson, "id": row.key, "validation": lesson["success_criteria"], "response_schema": "lumi.geometry/1",
                "authority": content["authority"], "teacher": row.payload["principal"], "lesson_digest": content["lesson_digest"],
                "assignment_digest": row.digest}

    def assignments(self, tenant: str, principal: str, class_id: str, after: str | None = None) -> dict[str, Any]:
        self.authority(tenant, principal, class_id)
        rows, cursor = self.scoped_page(tenant, "teaching-assignment", class_id, after)
        return {"items": [self.exercise(r) for r in rows], "next_cursor": cursor}
