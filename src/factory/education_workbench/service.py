"""Authenticated construction records; no models and no automatic assessment.

Trusted school provisioning binds the session principal to an active OneRoster
enrollment. These routes cannot create enrollment or promote a learner.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from factory.packs.collections import CollectionConflict, PackCollectionStore, PackDocument, document_key
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import InstalledPack, PackRegistry


class WorkbenchError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def geometry(value: Any, *, layer: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "units", "coordinateUnitsPerMm", "width", "height", "shapes", "reasoning"}:
        raise WorkbenchError(400, "A structured geometry document is required.")
    if value["schema"] != "lumi.geometry/1" or value["units"] != "mm" or value["coordinateUnitsPerMm"] != 10 or value["width"] != 800 or value["height"] != 500:
        raise WorkbenchError(400, "Unsupported geometry schema or units.")
    if not isinstance(value["reasoning"], str) or len(value["reasoning"]) > 10000 or not isinstance(value["shapes"], list) or len(value["shapes"]) > 500:
        raise WorkbenchError(400, "Geometry exceeds the pilot limits.")
    ids: set[str] = set()
    for shape in value["shapes"]:
        required = {"id", "kind", "layer", "label", "points"}
        if not isinstance(shape, dict) or not required <= set(shape) or set(shape) - required - {"intent", "colour"}:
            raise WorkbenchError(400, "Invalid shape.")
        if (("intent" in shape and (not isinstance(shape["intent"], str) or shape["intent"] not in {"correct", "correction", "question", "note"}))
                or ("colour" in shape and (not isinstance(shape["colour"], str) or shape["colour"] not in {"green", "red", "blue", "purple"}))
                or (layer != "teacher" and ("intent" in shape or "colour" in shape))):
            raise WorkbenchError(400, "Invalid teacher mark meaning or colour.")
        if "colour" in shape and shape["colour"] != {"correct": "green", "correction": "red", "question": "purple", "note": "blue"}.get(shape.get("intent", "")):
            raise WorkbenchError(400, "Teacher mark colour must match its meaning.")
        ident = shape["id"]
        if not isinstance(ident, str) or not ident or len(ident) > 100 or ident in ids or shape["layer"] != layer or not isinstance(shape["kind"], str) or shape["kind"] not in {"pen", "line", "circle", "label"} or not isinstance(shape["label"], str) or len(shape["label"]) > 200:
            raise WorkbenchError(400, "Invalid shape identity or layer.")
        ids.add(ident)
        points = shape["points"]
        if not isinstance(points, list) or not 1 <= len(points) <= 10000 or (shape["kind"] in {"line", "circle"} and len(points) != 2):
            raise WorkbenchError(400, "Invalid construction points.")
        for point in points:
            if not isinstance(point, dict) or set(point) != {"x", "y"}:
                raise WorkbenchError(400, "Invalid point.")
            for axis, maximum in (("x", 800), ("y", 500)):
                n = point[axis]
                if isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) or not 0 <= n <= maximum:
                    raise WorkbenchError(400, "Point is outside the sheet.")
    result: dict[str, Any] = json.loads(json.dumps(value, allow_nan=False))
    return result


class EducationWorkbench:
    def __init__(self, registry: PackRegistry, store: PackCollectionStore, *,
                 entitlement: Callable[[str, str], bool], require_durable: bool = True,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        if require_durable and not store.durable:
            raise WorkbenchError(503, "Education requires a durable collection store.")
        self.registry, self.store, self.entitlement = registry, store, entitlement
        self._clock = clock

    def exercises(self, pack: InstalledPack) -> list[dict[str, Any]]:
        name = "exercises/geometry.json"
        path = pack.root / name
        if name not in pack.manifest.files or not path.is_file():
            raise WorkbenchError(503, "The signed pack has no geometry exercises.")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != pack.manifest.files[name]:
            raise WorkbenchError(503, "The exercise declaration has changed since signing.")
        payload = json.loads(raw)
        if payload.get("schema") != "lumi.geometry-exercises/1" or not isinstance(payload.get("exercises"), list):
            raise WorkbenchError(503, "Invalid signed exercise declaration.")
        return list(payload["exercises"])

    def check_exercise(self, pack: InstalledPack, exercise: str, *, tenant: str = "", class_id: str = "") -> PackDocument | None:
        if any(e.get("id") == exercise and e.get("response_schema") == "lumi.geometry/1" for e in self.exercises(pack)):
            return None
        from .teaching import TeachingLibrary
        assignment = TeachingLibrary(self).assignment(pack, tenant, class_id, exercise)
        if assignment is None:
            raise WorkbenchError(400, "This exercise is neither a signed built-in exercise nor an assignment for this class.")
        TeachingLibrary.exercise(assignment)
        return assignment

    def page(self, tenant: str, collection: str, after: str | None) -> tuple[tuple[PackDocument, ...], str | None]:
        if after is not None and (not isinstance(after, str) or len(after) > 512):
            raise WorkbenchError(400, "Invalid page cursor.")
        rows = self.store.list(EDUCATION_ID, collection, tenant, limit=201, after_key=after)
        return rows[:200], rows[199].key if len(rows) > 200 else None

    def authority(self, tenant: str, principal: str, class_id: str) -> tuple[InstalledPack, str]:
        if not self.entitlement(tenant, "education-feedback"):
            raise WorkbenchError(403, f"Education access is not enabled for the signed-in account ({principal}) in this workspace. Ask the school administrator to enable it for this account.")
        pack = self.registry.for_tenant(tenant, EDUCATION_ID)
        if pack is None:
            raise WorkbenchError(503, "No signed Education pack is active for this workspace.")
        spec = pack.collection("roster-user")
        key = document_key(spec, {"sourcedId": principal, "classSourcedId": class_id})
        row = self.store.get(EDUCATION_ID, spec.name, tenant, key)
        if row is None or row.payload.get("status") != "active" or row.payload.get("role") not in {"student", "teacher"}:
            raise WorkbenchError(403, "An active school enrollment is required.")
        payload = row.payload
        start, end = payload.get("enrollmentEffectiveFromUs"), payload.get("enrollmentEffectiveUntilUs")
        generation = payload.get("enrollmentGeneration")
        now = int(self._clock().timestamp() * 1_000_000)
        signed_content = {"tenant_id": tenant, "principal": principal, "class_id": class_id,
                          "role": payload.get("role"), "status": payload.get("status"),
                          "given_name": payload.get("givenName"), "family_name": payload.get("familyName")}
        if (type(start) is not int or type(end) is not int or type(generation) is not int or generation < 1
                or start > now or (end != 0 and now >= end)
                or not payload.get("enrollmentAuthority")
                or not isinstance(payload.get("enrollmentDocumentDigest"), str)
                or len(payload["enrollmentDocumentDigest"]) != 64
                or payload.get("enrollmentPayloadDigest") != digest(signed_content)):
            raise WorkbenchError(403, "A current, verified school enrollment is required; ask the school to renew it.")
        return pack, str(row.payload["role"])

    def write(self, pack: InstalledPack, tenant: str, principal: str, class_id: str, exercise: str,
              collection: str, ident: str, content: dict[str, Any], expected: int | None, *, require_role: str) -> PackDocument:
        """Recheck the required school role while enrollment is stable through save."""
        with self.registry.ledger.resolution_guard(tenant, EDUCATION_ID) as record:
            if record is None or record.reference != pack.reference or record.pack_digest != pack.manifest.digest:
                raise WorkbenchError(409, "The active Education pack changed. Reopen your workspace before saving.")
            from .authority_guard import authority_guard
            # Match provisioning's lock order: pack first, then enrollment. A new
            # school write must not rely on a role read before revocation.
            with authority_guard(self.store, tenant, class_id, [principal]):
                if self.authority(tenant, principal, class_id)[1] != require_role:
                    raise WorkbenchError(403, "The required school role is no longer active.")
                payload = {"id": ident, "principal": principal, "classId": class_id, "exerciseId": exercise,
                           "content": content, "pins": self.registry.receipt_pins_for_record(record)}
                spec = pack.collection(collection)
                return self.store.put(spec, PackDocument(EDUCATION_ID, collection, tenant, ident,
                    1 if expected is None else expected + 1, payload, datetime.now(timezone.utc),
                    schema_version=spec.version), expected_version=expected)

    def draft(self, tenant: str, principal: str, class_id: str, exercise: str) -> PackDocument | None:
        pack, _ = self.authority(tenant, principal, class_id)
        self.check_exercise(pack, exercise, tenant=tenant, class_id=class_id)
        return self.store.get(EDUCATION_ID, "geometry-draft", tenant, digest([principal, class_id, exercise]))

    def save(self, tenant: str, principal: str, class_id: str, exercise: str, drawing: Any, expected: int | None) -> PackDocument:
        pack, role = self.authority(tenant, principal, class_id)
        self.check_exercise(pack, exercise, tenant=tenant, class_id=class_id)
        if role != "student":
            raise WorkbenchError(403, "Only an enrolled learner can save learner work.")
        if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int) or expected < 1):
            raise WorkbenchError(400, "expected_revision must be a positive integer or null for a new draft.")
        return self.write(pack, tenant, principal, class_id, exercise, "geometry-draft",
                          digest([principal, class_id, exercise]), geometry(drawing, layer="learner"), expected, require_role="student")

    def submit(self, tenant: str, principal: str, class_id: str, exercise: str, expected: int, key: str) -> PackDocument:
        pack, role = self.authority(tenant, principal, class_id)
        assignment = self.check_exercise(pack, exercise, tenant=tenant, class_id=class_id)
        if role != "student":
            raise WorkbenchError(403, "Only an enrolled learner can submit work.")
        ident = digest([principal, class_id, exercise, key])
        prior = self.store.get(EDUCATION_ID, "geometry-submission", tenant, ident)
        if prior:
            if prior.payload["content"]["draft_revision"] != expected:
                raise CollectionConflict("Idempotency key was used for another draft revision.")
            return prior
        draft = self.draft(tenant, principal, class_id, exercise)
        if draft is None or draft.version != expected:
            raise CollectionConflict("Save and reread the intended draft revision before submitting.")
        content = {"drawing": json.loads(json.dumps(draft.payload["content"], allow_nan=False)), "draft_revision": draft.version,
                   "draft_digest": draft.digest, "geometry_digest": digest(draft.payload["content"])}
        if assignment is not None:
            content["assignment_digest"] = assignment.digest
            content["lesson_digest"] = assignment.payload["content"]["lesson_digest"]
        try:
            return self.write(pack, tenant, principal, class_id, exercise, "geometry-submission", ident, content, None, require_role="student")
        except CollectionConflict:
            prior = self.store.get(EDUCATION_ID, "geometry-submission", tenant, ident)
            if prior and prior.payload["content"] == content:
                return prior
            raise

    def submissions(self, tenant: str, principal: str, class_id: str, after: str | None = None) -> dict[str, Any]:
        _, role = self.authority(tenant, principal, class_id)
        rows, cursor = self.page(tenant, "geometry-submission", after)
        return {"items": [r.to_dict() for r in rows if r.payload["classId"] == class_id and (role == "teacher" or r.payload["principal"] == principal)], "next_cursor": cursor}

    def annotate(self, tenant: str, principal: str, class_id: str, submission_id: str, drawing: Any, key: str) -> PackDocument:
        pack, role = self.authority(tenant, principal, class_id)
        if role != "teacher":
            raise WorkbenchError(403, "Only an enrolled teacher can annotate class submissions.")
        source = self.store.get(EDUCATION_ID, "geometry-submission", tenant, submission_id)
        if source is None or source.payload["classId"] != class_id:
            raise WorkbenchError(404, "Submission not found.")
        content = {"drawing": geometry(drawing, layer="teacher"), "submission_id": submission_id,
                   "submission_digest": source.digest}
        ident = digest([principal, submission_id, key])
        prior = self.store.get(EDUCATION_ID, "geometry-annotation", tenant, ident)
        if prior:
            if prior.payload["content"] != content:
                raise CollectionConflict("Idempotency key was used for another annotation.")
            return prior
        try:
            return self.write(pack, tenant, principal, class_id, str(source.payload["exerciseId"]), "geometry-annotation", ident, content, None, require_role="teacher")
        except CollectionConflict:
            prior = self.store.get(EDUCATION_ID, "geometry-annotation", tenant, ident)
            if prior and prior.payload["content"] == content:
                return prior
            raise

    def annotations(self, tenant: str, principal: str, class_id: str, submission_id: str, after: str | None = None) -> dict[str, Any]:
        _, role = self.authority(tenant, principal, class_id)
        source = self.store.get(EDUCATION_ID, "geometry-submission", tenant, submission_id)
        if source is None or source.payload["classId"] != class_id or (role != "teacher" and source.payload["principal"] != principal):
            raise WorkbenchError(404, "Submission not found.")
        rows, cursor = self.page(tenant, "geometry-annotation", after)
        return {"items": [r.to_dict() for r in rows if r.payload["content"]["submission_id"] == submission_id], "next_cursor": cursor}
