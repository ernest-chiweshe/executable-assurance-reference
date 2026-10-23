"""Pilot credentials from explicit enrollment/appointments and host-bound assessments.

The host supplies an authoritative assessment resolver and active member lookup.
Neither is derived from a caller's role, administrator status or editable project
fields. No default resolver or mock authority is composed by this module.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from typing import Any
from types import MappingProxyType
from collections.abc import Mapping

from factory.customer.tenancy import customer_tenant_id

from factory.packs.collections import PackCollectionStore, document_key
from factory.packs.examples import EDUCATION_ID
from factory.packs.registry import InstalledPack, PackRegistry
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import digest_hex
from regulated_core.identity_provider import CredentialError, CredentialReceipt
from regulated_core.signing import Signer, TrustDirectory

from .appointments import ROLE, ReviewerAppointments
from .authority_guard import authority_guard
from .service import WorkbenchError, digest
from .source_material import work_digest


@dataclass(frozen=True)
class AssessmentScope:
    """Host-resolved retained assessment binding, including the exact reviewed contract."""

    tenant: str
    school_id: str
    class_id: str
    assessment_id: str
    project_id: str
    contract_digest: str
    expires_at_us: int


@dataclass(frozen=True)
class EnrollmentCredentialFactory:
    """Bind credentials to the registry composed by the host, without late mutation.

    Supply this to RuntimeAuthorities only for the education domain composition.
    Other domains keep their own explicit credential authorities.
    """

    store: PackCollectionStore
    trust: TrustDirectory
    signer: Signer
    owner_authority: str
    schools: dict[str, str]
    school_authorities: dict[str, str]
    assessment_scope: Callable[[str, str], AssessmentScope | None]
    member_active: Callable[[str, str], bool]
    workspace_bindings: Mapping[str, str] | None = None

    def for_pack(self, pack: InstalledPack, registry: PackRegistry) -> EnrollmentCredentialVerifier:
        if pack.manifest.id != EDUCATION_ID or registry.get(pack.reference) is not pack:
            raise ValueError("pilot enrollment credentials require the installed Education pack")
        pack.collection("reviewer-appointment")  # Missing shipping declaration fails closed.
        appointments = ReviewerAppointments(registry, self.store, trust=self.trust,
            owner_authority=self.owner_authority, schools=self.schools)
        return EnrollmentCredentialVerifier(appointments, signer=self.signer,
            school_authorities=self.school_authorities, assessment_scope=self.assessment_scope,
            member_active=self.member_active, workspace_bindings=self.workspace_bindings)

    def verify(self, actor_id: str, tenant: str, role: str, *, jurisdiction: str | None,
               now_us: int) -> CredentialReceipt:
        raise CredentialError("pilot credential factory must bind the installed pack registry first")


class EnrollmentCredentialVerifier:
    """Issue a scope-bound receipt and recheck live authority before release.

    The appointment signer is the pinned owner authority; the credential signer
    only attests a verified lookup. Giving the runtime a signer cannot appoint a HoD.
    The caller retains the host pool and supplies adapters using that same pool.
    """

    requires_stored_review = True
    provider_backed = True

    def __init__(self, appointments: ReviewerAppointments, *, signer: Signer,
                 school_authorities: dict[str, str],
                 assessment_scope: Callable[[str, str], AssessmentScope | None],
                 member_active: Callable[[str, str], bool],
                 workspace_bindings: Mapping[str, str] | None = None) -> None:
        if not appointments.trust.is_known(signer.key_id):
            raise ValueError("credential signer requires an explicit trust anchor")
        if (set(school_authorities) != set(appointments.schools)
                or any(not key or not appointments.trust.is_known(key) for key in school_authorities.values())):
            raise ValueError("each school enrollment authority needs an explicit trust anchor")
        bindings = dict(workspace_bindings or {})
        if any(not isinstance(workspace, str) or workspace not in appointments.schools
               or tenant != customer_tenant_id(workspace) for tenant, workspace in bindings.items()):
            raise ValueError("workspace bindings must match the canonical tenant and configured school")
        self.workspace_bindings = MappingProxyType(bindings)
        self.appointments, self.signer = appointments, signer
        self.school_authorities = dict(school_authorities)
        self.assessment_scope, self.member_active = assessment_scope, member_active
        self._guard_scope: ContextVar[AssessmentScope | None] = ContextVar("education_review_scope", default=None)

    def authority_tenant(self, tenant: str) -> str:
        """Resolve explicitly admitted internal tenants to signed workspace authority."""
        if not self.workspace_bindings:
            return tenant
        workspace = self.workspace_bindings.get(tenant)
        if workspace is None:
            raise CredentialError("the internal tenant has no admitted workspace authority binding")
        return workspace

    @contextmanager
    def review_guard(self, *, contract: dict[str, Any], context: EmissionContext,
                     actors: Sequence[str]) -> Iterator[None]:
        scope = self.assessment_scope(context.tenant, context.project_id)
        if not isinstance(scope, AssessmentScope) or scope.contract_digest != work_digest(contract):
            raise CredentialError("the retained assessment scope is unavailable or changed")
        with authority_guard(self.appointments.store, self.authority_tenant(context.tenant), scope.class_id, actors):
            token = self._guard_scope.set(scope)
            try:
                yield
            finally:
                self._guard_scope.reset(token)

    def verify(self, actor_id: str, tenant: str, role: str, *, jurisdiction: str | None,
               now_us: int) -> CredentialReceipt:
        raise CredentialError("pilot reviewer verification requires the retained assessment scope")

    def teacher_binding(self, actor_id: str, *, contract: dict[str, Any],
                        context: EmissionContext) -> tuple[AssessmentScope, str, int]:
        """Read current signed teacher authority without issuing a credential.

        Callers retain review_guard for this actor through the dependent operation.
        """
        return self._binding(actor_id, context.tenant, "teacher", contract, context)

    def _binding(self, actor_id: str, tenant: str, role: str, contract: dict[str, Any],
                 context: EmissionContext) -> tuple[AssessmentScope, str, int]:
        authority_tenant = self.authority_tenant(tenant)
        scope = self.assessment_scope(tenant, context.project_id)
        now = context.now_us
        guarded = self._guard_scope.get()
        if (not isinstance(scope, AssessmentScope) or scope.tenant != tenant or context.tenant != tenant
                or (guarded is not None and scope != guarded)
                or scope.project_id != context.project_id or not scope.project_id
                or not scope.assessment_id or not scope.class_id
                or scope.school_id != self.appointments.schools.get(authority_tenant)
                or scope.contract_digest != work_digest(contract)
                or type(scope.expires_at_us) is not int or scope.expires_at_us <= now
                or not self.member_active(authority_tenant, actor_id)):
            raise CredentialError("active member and exact retained school/class/assessment binding are required")
        try:
            if role == ROLE:
                appointment = self.appointments.current(authority_tenant, actor_id, scope.class_id, now_us=now)
                return scope, appointment.digest(), min(scope.expires_at_us, appointment.effective_until_us)
            if role != "teacher":
                raise CredentialError("pilot review requires an explicit teacher or HoD credential")
            pack = self.appointments.registry.for_tenant(authority_tenant, EDUCATION_ID)
            if pack is None:
                raise CredentialError("the Education pack is not active")
            spec = pack.collection("roster-user")
            key = document_key(spec, {"sourcedId": actor_id, "classSourcedId": scope.class_id})
            row = self.appointments.store.get(pack.manifest.id, spec.name, authority_tenant, key)
            payload = row.payload if row is not None else {}
            content = {"tenant_id": authority_tenant, "principal": actor_id, "class_id": scope.class_id,
                       "role": payload.get("role"), "status": payload.get("status"),
                       "given_name": payload.get("givenName"), "family_name": payload.get("familyName")}
            start, end = payload.get("enrollmentEffectiveFromUs"), payload.get("enrollmentEffectiveUntilUs")
            generation, doc_digest = payload.get("enrollmentGeneration"), payload.get("enrollmentDocumentDigest")
            if (payload.get("role") != "teacher" or payload.get("status") != "active"
                    or payload.get("enrollmentAuthority") != self.school_authorities[authority_tenant]
                    or payload.get("enrollmentPayloadDigest") != digest(content)
                    or type(start) is not int or type(end) is not int or start > now
                    or (end != 0 and end <= now) or type(generation) is not int or generation < 1
                    or not isinstance(doc_digest, str) or len(doc_digest) != 64):
                raise CredentialError("a current signed teacher enrollment in this class is required")
            return scope, doc_digest, min(scope.expires_at_us, end or scope.expires_at_us)
        except WorkbenchError as exc:
            raise CredentialError(str(exc)) from exc

    def verify_review(self, actor_id: str, tenant: str, role: str, *, contract: dict[str, Any],
                      context: EmissionContext, jurisdiction: str | None) -> CredentialReceipt:
        scope, grant_digest, expires = self._binding(actor_id, tenant, role, contract, context)
        if jurisdiction is not None and jurisdiction != scope.school_id:
            raise CredentialError("review jurisdiction differs from the configured school")
        provider = f"owner-enrollment:{digest_hex(asdict(scope))}:{grant_digest}"
        body = {"schema": "regulated/credential-receipt/v1", "subject_id": actor_id, "tenant": tenant,
                "role": role, "licence_type": "pilot-school-reviewer", "jurisdiction": scope.school_id,
                "status": "active", "expires_at_us": expires, "verified_at_us": context.now_us,
                "provider": provider}
        return CredentialReceipt(actor_id, tenant, role, "pilot-school-reviewer", scope.school_id,
                                 "active", expires, context.now_us, provider, self.signer.sign(body))

    def validate_review(self, receipt: CredentialReceipt, *, contract: dict[str, Any],
                        context: EmissionContext) -> None:
        """Read-only revalidation; never refresh a stale receipt by issuing another signature."""
        scope, grant_digest, expires = self._binding(receipt.subject_id, context.tenant,
                                                    receipt.role, contract, context)
        if (receipt.tenant != context.tenant or receipt.status != "active"
                or receipt.signature.key_id != self.signer.key_id
                or not self.appointments.trust.verify(receipt.signed_body(), receipt.signature)
                or receipt.jurisdiction != scope.school_id or receipt.licence_type != "pilot-school-reviewer"
                or receipt.provider != f"owner-enrollment:{digest_hex(asdict(scope))}:{grant_digest}"
                or receipt.expires_at_us != expires or context.now_us >= expires
                or receipt.verified_at_us > context.now_us):
            raise CredentialError("reviewer authority or assessment scope changed after approval")
