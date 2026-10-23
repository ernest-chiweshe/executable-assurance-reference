"""Explicit local operator provisioning; no hosted login or deployment entrypoint.

The caller supplies read-only membership and already composed stores. Membership
is observed at preflight time, not held atomically against later revocation.
Writes use the original signed grant provisioners. A batch is not atomic.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from factory.education_workbench.appointments import ReviewerAppointments, _decode
from factory.education_workbench.provisioning import provision_enrollment
from factory.packs.collections import PackCollectionStore
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import PackRegistry
from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import TrustDirectory

ROLES = ("teacher", "student", "head-of-department")


@dataclass(frozen=True)
class OperatorScope:
    tenant: str
    school: str
    class_id: str
    pack_reference: str
    enrollment_authority: str
    appointment_authority: str


@dataclass(frozen=True)
class PinnedAuthority:
    role: str
    principal: str
    path: Path
    file_sha256: str
    document_digest: str
    expected_revision: int | None = None


class ProvisioningStopped(RuntimeError):
    """Inspect the receipt and retained state before deciding whether to retry."""

    def __init__(self, receipt: dict[str, Any]) -> None:
        super().__init__("Provisioning stopped; inspect retained state.")
        self.receipt = receipt


def _digest_pin(value: str) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _inputs(scope: OperatorScope, pins: Sequence[PinnedAuthority],
            trust: TrustDirectory, appointments: ReviewerAppointments,
            now_us: int) -> dict[str, PolicyDocument]:
    if len(pins) != 3 or {pin.role for pin in pins} != set(ROLES):
        raise ValueError("Exactly one explicit input for each declared role is required.")
    signed = {}
    for pin in pins:
        if (not isinstance(pin.principal, str) or not pin.principal
                or not _digest_pin(pin.file_sha256) or not _digest_pin(pin.document_digest)
                or (pin.expected_revision is not None
                    and (type(pin.expected_revision) is not int or pin.expected_revision < 1))):
            raise ValueError("Explicit principal, digest pins and valid revision are required.")
        raw = Path(pin.path).read_bytes()
        if sha256(raw).hexdigest() != pin.file_sha256:
            raise ValueError("Authority file digest differs.")
        document = _decode(json.loads(raw))
        content = document.content
        authority = (scope.appointment_authority if pin.role == ROLES[2]
                     else scope.enrollment_authority)
        if (not isinstance(content, dict)
                or document.digest() != pin.document_digest
                or document.vertical != "education"
                or document.issued_by != authority
                or not verify_document(trust, document, authority=authority)
                or type(document.effective_from_us) is not int
                or type(document.effective_until_us) is not int
                or document.effective_from_us < 0
                or document.effective_until_us <= document.effective_from_us
                or not document.effective_at(now_us)
                or not isinstance(document.version, str)
                or not document.version.isascii() or not document.version.isdigit()
                or int(document.version) < 1
                or content.get("tenant_id") != scope.tenant
                or content.get("class_id") != scope.class_id
                or content.get("principal") != pin.principal
                or content.get("role") != pin.role
                or content.get("status") != "active"):
            raise ValueError("A pinned current signed authority for the exact scope is required.")
        if pin.role == ROLES[2]:
            appointments._validate(document, tenant=scope.tenant, principal=pin.principal,
                                   class_id=scope.class_id, now_us=now_us)
        else:
            fields = {"tenant_id", "principal", "class_id", "role", "status",
                      "given_name", "family_name"}
            if (document.policy_id != "school-enrollment" or set(content) != fields
                    or any(not isinstance(content[k], str) or not content[k]
                           or len(content[k]) > 200 for k in fields)):
                raise ValueError("Invalid signed enrollment fields.")
        signed[pin.role] = document
    return signed


def provision_pinned_authorities(
    registry: PackRegistry, store: PackCollectionStore, trust: TrustDirectory,
    member: Callable[[str, str], bool], *, scope: OperatorScope,
    pins: Sequence[PinnedAuthority], now_us: int, execute: bool = False,
) -> dict[str, Any]:
    """Default preflight; explicit execute applies and reads back existing members.

    No identity is accepted from an operator key. Host authentication, member
    directory semantics and clock custody are outside this local operator step.
    """
    if type(execute) is not bool or type(now_us) is not int or now_us < 0:
        raise ValueError("Explicit boolean execution choice and integer time are required.")
    if any(not isinstance(v, str) or not v.strip() for v in (
        scope.tenant, scope.school, scope.class_id, scope.pack_reference,
        scope.enrollment_authority, scope.appointment_authority,
    )):
        raise ValueError("Every host scope binding must be explicit.")
    pins = tuple(pins)
    appointments = ReviewerAppointments(
        registry, store, trust=trust, owner_authority=scope.appointment_authority,
        schools={scope.tenant: scope.school},
    )
    signed = _inputs(scope, pins, trust, appointments, now_us)
    pack = registry.for_tenant(scope.tenant, EDUCATION_ID)
    if pack is None or pack.reference != scope.pack_reference:
        raise ValueError("The exact selected Education pack must be active.")
    memberships = [member(scope.tenant, signed[role].content["principal"]) for role in ROLES]
    if any(present is not True for present in memberships):
        raise ValueError("Every approved individual membership must already exist.")
    receipt: dict[str, Any] = {
        "schema": "reference/operator-authority-provisioning/v1",
        "status": "preflight-clear", "workspace": scope.tenant,
        "pack": scope.pack_reference, "authorities": [],
        "account_writes": 0, "signing_calls": 0, "model_calls": 0,
    }
    if not execute:
        return receipt
    by_role = {pin.role: pin for pin in pins}
    for role in ROLES:
        document = signed[role]
        receipt["attempted_role"] = role
        try:
            # Recheck the selection immediately before each guarded write.
            current_pack = registry.for_tenant(scope.tenant, EDUCATION_ID)
            if current_pack is None or current_pack.reference != scope.pack_reference:
                raise ValueError("The selected pack changed; inspect state.")
            if role == ROLES[2]:
                saved = appointments.provision(
                    document, now_us=now_us, expected_revision=by_role[role].expected_revision)
            else:
                saved = provision_enrollment(
                    registry, store, document, trust=trust,
                    school_authority=scope.enrollment_authority, now_us=now_us,
                    expected_revision=by_role[role].expected_revision)
            reread = store.get(EDUCATION_ID, saved.collection, scope.tenant, saved.key)
            if (reread is None or reread.version != saved.version
                    or reread.payload != saved.payload):
                raise ValueError("Exact retained authority readback failed.")
            retained_digest = (_decode(reread.payload.get("document")).digest()
                               if role == ROLES[2]
                               else reread.payload.get("enrollmentDocumentDigest"))
            if retained_digest != document.digest():
                raise ValueError("Retained signed-document digest differs.")
            receipt["authorities"].append({
                "role": role, "digest": document.digest(), "revision": reread.version,
            })
        except Exception as exc:
            receipt.update(status="stopped-inspect-state", retry=False,
                           attempted_write_outcome="inspect-state",
                           error_class=type(exc).__name__)
            # No database exception text or parameters enter the receipt.
            raise ProvisioningStopped(receipt) from None
    receipt.pop("attempted_role")
    receipt["status"] = "provisioned-and-read-back"
    return receipt
