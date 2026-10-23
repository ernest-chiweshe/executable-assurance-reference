"""Operator-only signed school enrollment bootstrap; never exposed as a customer route."""
from __future__ import annotations

from datetime import datetime, timezone

from factory.packs.collections import PackCollectionStore, PackDocument, document_key
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import PackRegistry
from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import TrustDirectory

from .service import WorkbenchError, digest
from .authority_guard import authority_guard


def provision_enrollment(registry: PackRegistry, store: PackCollectionStore, document: PolicyDocument, *,
                         trust: TrustDirectory, school_authority: str, now_us: int,
                         expected_revision: int | None = None) -> PackDocument:
    content = document.content
    if not isinstance(content, dict) or any(not isinstance(content.get(k), str) for k in ("tenant_id", "class_id", "principal")):
        raise WorkbenchError(400, "Invalid signed enrollment fields.")
    with registry.ledger.resolution_guard(content["tenant_id"], EDUCATION_ID):
        with authority_guard(store, content["tenant_id"], content["class_id"], [content["principal"]], exclusive=True):
            return _provision_enrollment(registry, store, document, trust=trust, school_authority=school_authority,
                                          now_us=now_us, expected_revision=expected_revision)


def _provision_enrollment(registry: PackRegistry, store: PackCollectionStore, document: PolicyDocument, *,
                         trust: TrustDirectory, school_authority: str, now_us: int,
                         expected_revision: int | None = None) -> PackDocument:
    """Apply one signed enrollment whose workspace and exact session principal are explicit.

    Trusted operator supplies the school-specific authority key; trusting some other
    publisher is insufficient. Compare-and-swap protects role changes/revocations.
    """
    if (document.vertical != "education" or document.policy_id != "school-enrollment"
            or not document.effective_at(now_us) or not verify_document(trust, document, authority=school_authority)):
        raise WorkbenchError(403, "A current school-authority enrollment signature is required.")
    content = document.content
    required = {"tenant_id", "principal", "class_id", "role", "status", "given_name", "family_name"}
    if set(content) != required or any(not isinstance(content[k], str) or not content[k] or len(content[k]) > 200 for k in required):
        raise WorkbenchError(400, "Invalid signed enrollment fields.")
    if content["role"] not in {"student", "teacher"} or content["status"] not in {"active", "tobedeleted"}:
        raise WorkbenchError(400, "Invalid school role or status.")
    if not document.version.isascii() or not document.version.isdigit() or int(document.version) < 1:
        raise WorkbenchError(400, "Enrollment version must be a positive integer generation.")
    pack = registry.for_tenant(content["tenant_id"], EDUCATION_ID)
    if pack is None:
        raise WorkbenchError(503, "Signed Education pack must be active before enrollment.")
    spec = pack.collection("roster-user")
    payload = {"sourcedId": content["principal"], "classSourcedId": content["class_id"],
               "role": content["role"], "status": content["status"],
               "givenName": content["given_name"], "familyName": content["family_name"],
               "enrollmentDocumentDigest": document.digest(), "enrollmentGeneration": int(document.version),
               "enrollmentAuthority": school_authority, "enrollmentEffectiveFromUs": document.effective_from_us,
               "enrollmentEffectiveUntilUs": document.effective_until_us, "enrollmentPayloadDigest": digest(content)}
    key = document_key(spec, payload)
    prior = store.get(EDUCATION_ID, spec.name, content["tenant_id"], key)
    if prior is not None:
        if prior.payload.get("enrollmentDocumentDigest") == document.digest():
            return prior  # Exact signed replay cannot alter a newer state or consume another revision.
        generation = prior.payload.get("enrollmentGeneration", 0)
        since = prior.payload.get("enrollmentEffectiveFromUs", 0)
        if (type(generation) is not int or type(since) is not int
                or int(document.version) <= generation or document.effective_from_us < since):
            raise WorkbenchError(409, "An older signed enrollment cannot replace a newer grant or revocation.")
    return store.put(spec, PackDocument(EDUCATION_ID, spec.name, content["tenant_id"], document_key(spec, payload),
        1 if expected_revision is None else expected_revision + 1, payload,
        datetime.fromtimestamp(now_us / 1_000_000, tz=timezone.utc), schema_version=spec.version), expected_version=expected_revision)
