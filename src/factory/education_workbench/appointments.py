"""Owner-signed pilot reviewer appointments through the existing enrollment store.

No customer route grants authority. The host pins the owner's authority and the
school belonging to each tenant. Existing student/teacher enrollment is untouched.
Every read re-verifies the retained signed document, including its scope and expiry.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from factory.packs.collections import CollectionError, CollectionSpec, PackCollectionStore, PackDocument, document_key
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import PackRegistry
from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import Signature, TrustDirectory

from .service import WorkbenchError
from .authority_guard import authority_guard

COLLECTION = "reviewer-appointment"
POLICY = "school-reviewer-appointment"
ROLE = "head-of-department"
_FIELDS = frozenset({"tenant_id", "school_id", "principal", "class_id", "role", "status",
                     "given_name", "family_name", "owner_approval_ref"})


def _decode(raw: Any) -> PolicyDocument:
    try:
        if not isinstance(raw, dict):
            raise ValueError("document is not an object")
        values = dict(raw)
        values["signature"] = Signature(**values["signature"])
        values["jurisdictions"] = tuple(values["jurisdictions"])
        return PolicyDocument(**values)
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkbenchError(403, "Invalid retained appointment document.") from exc


class ReviewerAppointments:
    """Operator-only writes, verified reads, and CAS-protected grant/revocation lineage.

    An owner approval reference is part of the signed named appointment. Supplying
    a reference without the pinned owner's signature never grants authority.
    Construction does not sign, migrate, activate or generate any key.
    """

    def __init__(self, registry: PackRegistry, store: PackCollectionStore, *, trust: TrustDirectory,
                 owner_authority: str, schools: Mapping[str, str]) -> None:
        if not owner_authority or not trust.is_known(owner_authority):
            raise ValueError("appointment owner authority needs an explicit trust anchor")
        if not schools or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                              for k, v in schools.items()):
            raise ValueError("explicit tenant-to-school bindings are required")
        self.registry, self.store, self.trust = registry, store, trust
        self.owner_authority, self.schools = owner_authority, dict(schools)

    def _validate(self, document: PolicyDocument, *, tenant: str, principal: str,
                  class_id: str, now_us: int, current: bool = True) -> None:
        try:
            content = document.content
            if (document.vertical != "education" or document.policy_id != POLICY
                    or not verify_document(self.trust, document, authority=self.owner_authority)
                    or not isinstance(content, dict) or set(content) != _FIELDS
                    or any(not isinstance(content[k], str) or not content[k].strip()
                           or len(content[k]) > 200 for k in _FIELDS)
                    or content["tenant_id"] != tenant or content["principal"] != principal
                    or content["class_id"] != class_id or content["role"] != ROLE
                    or tenant not in self.schools or content["school_id"] != self.schools[tenant]
                    or content["status"] not in {"active", "revoked"}
                    or type(document.effective_from_us) is not int
                    or type(document.effective_until_us) is not int
                    or document.effective_from_us < 0
                    or document.effective_until_us <= document.effective_from_us
                    or not isinstance(document.version, str) or not document.version.isascii()
                    or not document.version.isdigit() or int(document.version) < 1
                    or (current and not document.effective_at(now_us))):
                raise ValueError("invalid authority, scope, generation or validity window")
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise WorkbenchError(403, "A current owner-signed appointment for this person, school and class is required.") from exc

    def _spec(self, tenant: str) -> CollectionSpec:
        pack = self.registry.for_tenant(tenant, EDUCATION_ID)
        if pack is None:
            raise WorkbenchError(503, "Signed Education pack must be active before reviewer appointments.")
        try:
            return pack.collection(COLLECTION)
        except CollectionError as exc:
            raise WorkbenchError(503, "The active signed pack must declare reviewer appointments.") from exc

    def provision(self, document: PolicyDocument, *, now_us: int,
                  expected_revision: int | None = None) -> PackDocument:
        """Apply the exact signed appointment or revocation; never infer a person's role."""
        content = document.content
        if not isinstance(content, dict) or any(not isinstance(content.get(k), str) for k in ("tenant_id", "class_id", "principal")):
            raise WorkbenchError(400, "Invalid appointment content.")
        with self.registry.ledger.resolution_guard(content["tenant_id"], EDUCATION_ID):
            with authority_guard(self.store, content["tenant_id"], content["class_id"], [content["principal"]], exclusive=True):
                return self._provision(document, now_us=now_us, expected_revision=expected_revision)

    def _provision(self, document: PolicyDocument, *, now_us: int,
                   expected_revision: int | None = None) -> PackDocument:
        content = document.content
        if not isinstance(content, dict):
            raise WorkbenchError(400, "Invalid appointment content.")
        tenant, principal, class_id = (content.get(k, "") for k in ("tenant_id", "principal", "class_id"))
        self._validate(document, tenant=tenant, principal=principal, class_id=class_id, now_us=now_us)
        spec = self._spec(tenant)
        payload = {"principal": principal, "schoolId": content["school_id"],
                   "classId": class_id, "role": ROLE, "document": asdict(document)}
        key = document_key(spec, payload)
        prior = self.store.get(EDUCATION_ID, COLLECTION, tenant, key)
        if prior is not None:
            old = _decode(prior.payload.get("document"))
            self._validate(old, tenant=tenant, principal=principal, class_id=class_id, now_us=now_us, current=False)
            if document.digest() == old.digest():
                return prior
            if (int(document.version) <= int(old.version)
                    or document.effective_from_us < old.effective_from_us
                    or document.supersedes != old.digest()):
                raise WorkbenchError(409, "Appointment must supersede the exact latest grant or revocation.")
        elif document.supersedes:
            raise WorkbenchError(409, "An initial appointment cannot supersede an unknown record.")
        return self.store.put(spec, PackDocument(
            EDUCATION_ID, COLLECTION, tenant, key,
            1 if expected_revision is None else expected_revision + 1, payload,
            datetime.fromtimestamp(now_us / 1_000_000, tz=timezone.utc), schema_version=spec.version),
            expected_version=expected_revision)

    def current(self, tenant: str, principal: str, class_id: str, *, now_us: int) -> PolicyDocument:
        spec = self._spec(tenant)
        key = document_key(spec, {"principal": principal, "classId": class_id, "role": ROLE})
        row = self.store.get(EDUCATION_ID, COLLECTION, tenant, key)
        if row is None:
            raise WorkbenchError(403, "No owner-approved appointment exists for this person and class.")
        document = _decode(row.payload.get("document"))
        self._validate(document, tenant=tenant, principal=principal, class_id=class_id, now_us=now_us)
        if document.content["status"] != "active":
            raise WorkbenchError(403, "This reviewer appointment has been revoked.")
        return document
