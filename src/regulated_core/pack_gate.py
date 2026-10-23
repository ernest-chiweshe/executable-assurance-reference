"""Generic signed rulebook adapter over the existing regulated release engine.

Consumes the installed RulebookPolicy without translating or re-signing its content.
Only explicitly injected host verifiers/signers supply non-deterministic controls.
The pack activation read lock spans the local authorization operation, so revocation
cannot interleave between version validation and emission authority issuance.
"""
from __future__ import annotations

from .production_gate import PackReadiness, ReleaseReadiness

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from factory.packs.registry import InstalledPack, PackRegistry
from factory.projectos.regulated import EmissionContext, EmissionDecision, ReleaseOutcome
from factory.projectos.spec import VerticalSpec

from .document_gate import Verifier, VerifierRegistry
from .engine import RegulatedEngine
from .identity_provider import CredentialError
from .target import ReleaseAdmissionUnavailable
from .models import Actor, DataClass, SignedVerification, VerificationResult
from .policy_document import verify_document
from .preflight import IntendedUse, IntendedUseRegistry
from .registry import PolicyRegistry
from .outage import OutageAlarm
from .projectos_gate import CredentialVerifier, QualificationRegistry, _RegulatedGateBase, require_retention_store
from .signing import Signer, TrustDirectory
from .verification import sign_verification
from .worm import WormStore
from .review_store import ReviewStore


@dataclass(frozen=True)
class PackGateFactory:
    """Host composition callback; every authority is injected, never generated.

    Fits PackComposition's (pack, registry, surface) seam. Construction performs
    no signing, activation or storage mutation. A surface must bind the exact
    installed policy before the existing gate builder is invoked.
    """

    trust: TrustDirectory
    engine: RegulatedEngine
    host_verifiers: VerifierRegistry
    verifier_signers: Mapping[str, Signer]
    credential_verifier: CredentialVerifier
    intended_uses: IntendedUseRegistry
    worm: WormStore
    qualifications: QualificationRegistry | None = None
    production_assurance: PackReadiness | None = None
    required_jurisdiction: str | None = None
    review_store: ReviewStore | None = None
    review_extension_factory: Any = None
    # The host's composed outage alarm (A17); absent, the gate's default log channel.
    outage_alarm: OutageAlarm | None = None

    def __post_init__(self) -> None:
        require_retention_store(self.worm)

    def __call__(self, pack: InstalledPack, registry: PackRegistry, surface: Any) -> RulebookGate:
        spec = getattr(surface, "_spec", None) or getattr(surface, "spec", None)
        block = getattr(spec, "regulated", None)
        document = pack.rulebook.document
        if (block is None or block.pack_version != pack.reference
                or block.policy_ref != f"{document.vertical}/{document.policy_id}"
                or block.policy_digest != document.digest()):
            raise ValueError("surface must bind the exact installed signed policy")
        return build_pack_gate(
            pack, registry=registry, trust=self.trust, engine=self.engine,
            host_verifiers=self.host_verifiers, verifier_signers=self.verifier_signers,
            credential_verifier=self.credential_verifier, intended_uses=self.intended_uses,
            worm=self.worm, qualifications=self.qualifications,
            required_jurisdiction=self.required_jurisdiction,
            review_store=self.review_store, review_extension_factory=self.review_extension_factory,
            outage_alarm=self.outage_alarm, production_assurance=self.production_assurance,
        )


class RulebookGate(_RegulatedGateBase):
    def __init__(self, *, pack: InstalledPack, registry: PackRegistry, engine: RegulatedEngine,
                 verifiers: Mapping[str, Verifier], verifier_signers: Mapping[str, Signer],
                 credential_verifier: CredentialVerifier, worm: WormStore,
                 qualifications: QualificationRegistry | None = None,
                 required_jurisdiction: str | None = None, review_store: ReviewStore | None = None,
                 source_reviews: Any = None, outage_alarm: OutageAlarm | None = None,
                 release_readiness: ReleaseReadiness | None = None) -> None:
        super().__init__(engine, verifier_signers=dict(verifier_signers), worm=worm,
                         worm_retain_us=pack.rulebook.retention_years * 365 * 86_400_000_000,
                         credential_verifier=credential_verifier, qualifications=qualifications,
                         release_readiness=release_readiness,
                         required_jurisdiction=required_jurisdiction, review_store=review_store,
                         outage_alarm=outage_alarm)
        self.pack = pack
        self.registry = registry
        self.verifiers = dict(verifiers)
        self.source_reviews = source_reviews
        policy = pack.rulebook
        self.VERTICAL = policy.document.vertical
        self.CONTENT_TYPE = next(iter(policy.content_types))
        self.DRAFT_ACTION = policy.actions("reversible")[0]
        self.EMIT_ACTION = policy.actions("external")[0]
        self.DATA_CLASSES = frozenset(DataClass[str(n).upper()] for n in policy.effective_content.get("data_classes", ()))
        self.RISK_TIER = int(policy.effective_content.get("risk_tier", 3))
        self.PURPOSE = f"{self.VERTICAL}:emit"

    def _verify(self, draft: str, contract: dict[str, Any], *, assertion_id: str, content_digest: str,
                tenant_id: str, now_us: int) -> tuple[SignedVerification, ...]:
        return self._verification_results(draft, contract, assertion_id=assertion_id, content_digest=content_digest,
                                          tenant_id=tenant_id, now_us=now_us)

    def _verify_for_context(self, draft: str, contract: dict[str, Any], *, assertion_id: str,
                            content_digest: str, context: EmissionContext) -> tuple[SignedVerification, ...]:
        return self._verification_results(draft, contract, assertion_id=assertion_id, content_digest=content_digest,
                                          tenant_id=context.tenant, now_us=context.now_us, context=context)

    def _verification_results(self, draft: str, contract: dict[str, Any], *, assertion_id: str, content_digest: str,
                              tenant_id: str, now_us: int, context: EmissionContext | None = None) -> tuple[SignedVerification, ...]:
        results = []
        for check_id, verifier in self.verifiers.items():
            contextual = getattr(verifier, "verify_context", None)
            result = contextual(draft, contract, context) if context is not None and callable(contextual) else verifier(draft, contract)
            outcome, reasons = result if isinstance(result, tuple) else (result, ())
            signer = self._vsign[check_id]
            results.append(sign_verification(
                signer, assertion_id=assertion_id, content_digest=content_digest, tenant_id=tenant_id,
                result=VerificationResult(verification_class=check_id, outcome=outcome,
                                          verifier_id=signer.key_id, verifier_version=self.pack.rulebook.check_version(check_id),
                                          reason_codes=tuple(reasons)), verified_at_us=now_us))
        return tuple(results)

    @contextmanager
    def _operation_guard(self, contract: Mapping[str, Any], context: EmissionContext, *, writer: bool = False) -> Iterator[Any]:
        if self.source_reviews is not None:
            with self.source_reviews.release_guard(dict(contract), context, writer=writer):
                yield self.registry.ledger.resolve_record(context.tenant, self.pack.manifest.id)
        else:
            with self.registry.resolution_guard(context.tenant, self.pack.manifest.id, now_us=context.now_us,
                                                expected_reference=self.pack.reference) as record:
                yield record

    def get_source_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        self._review_scope(spec, context)
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                raise ValueError(reason)
            if self.source_reviews is None:
                return {"required": False}
            result: dict[str, Any] = self.source_reviews.view(contract, context)
            return result

    def confirm_source_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                              expected_material_digest: str, confirmed: bool, request_id: str) -> dict[str, Any]:
        self._review_scope(spec, context)
        if self.source_reviews is None:
            raise ValueError("human source review is not configured")
        with self._operation_guard(contract, context, writer=True) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                raise ValueError(reason)
            result: dict[str, Any] = self.source_reviews.confirm_from_context(
                contract=contract, context=context,
                expected_material_digest=expected_material_digest, confirmed=confirmed, request_id=request_id)
            return result

    def _refusal(self, record: Any, context: EmissionContext, spec: VerticalSpec | None = None) -> str:
        if record is None or record.reference != self.pack.reference or record.pack_digest != self.pack.manifest.digest:
            return "pack is inactive, revoked, or the tenant is pinned to a different artifact"
        document = self.pack.rulebook.document
        if not document.effective_at(context.now_us):
            return "signed pack policy is outside its effective window"
        if spec is not None:
            block = spec.regulated
            if (block is None or block.policy_ref != f"{document.vertical}/{document.policy_id}"
                    or block.policy_digest != document.digest() or block.pack_version != self.pack.reference):
                return "project policy pins do not match the release gate"
        return ""

    def review_draft(self, *, spec: VerticalSpec, contract: Mapping[str, Any], context: EmissionContext) -> EmissionDecision:
        context = self._trusted(context)
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                return EmissionDecision(allowed=False, reason=reason)
            return super().review_draft(spec=spec, contract=dict(contract), context=context)

    def request_approval(self, contract: dict[str, Any], context: EmissionContext, approvers: tuple[Actor, ...]) -> Any:
        context = self._trusted(context)
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context)
            if reason:
                raise ValueError(reason)
            return super().request_approval(contract, context, approvers)

    def authorize_release(self, *, spec: VerticalSpec, contract: Mapping[str, Any], out_path: str,
                          context: EmissionContext, artifact: bytes) -> EmissionDecision:
        context = self._trusted(context)
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                return self._recorded_refusal(contract, context, "PACK_AUTHORITY_REFUSED", reason)
            return super().authorize_release(spec=spec, contract=dict(contract), out_path=out_path, context=context,
                                             artifact=artifact)

    def commit_release(self, *, spec: VerticalSpec, contract: Mapping[str, Any], decision: EmissionDecision,
                       artifact: bytes, out_path: str, context: EmissionContext) -> ReleaseOutcome:
        """Commit under the SAME activation guard as the authorisation: a pack revoked or replaced between the
        permit and the commit refuses here, before the target is touched."""
        context = self._trusted(context)
        try:
            # Customer/clinician parents precede the pack and target locks.
            with self._release_admission(contract, context, decision) as current:
                with self._operation_guard(contract, context) as record:
                    reason = self._refusal(record, context, spec)
                    if reason:
                        refused = self._recorded_refusal(contract, context, "PACK_AUTHORITY_CHANGED",
                                                        f"pack authority changed before commit: {reason}")
                        return ReleaseOutcome("failed", refused.reason, dict(refused.evidence))
                    return self._commit_admitted_release(
                        spec=spec, contract=contract, decision=decision, artifact=artifact,
                        out_path=out_path, context=context, effect_check=current,
                    )
        except CredentialError as refused:
            return self._cancel_refused_release(decision, out_path, context, str(refused))
        except ReleaseAdmissionUnavailable as down:
            # Includes a lost acknowledgement closing the admission transaction
            # after a file effect. Never label that uncertainty as no effect.
            self._cancel_refused_release(decision, out_path, context, str(down))
            return ReleaseOutcome("unknown", str(down))

    def _review_call(self, method: str, *, spec: VerticalSpec, contract: dict[str, Any],
                     context: EmissionContext, **kwargs: Any) -> dict[str, Any]:
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                raise ValueError(reason)
            operation = getattr(super(), method)
            result: dict[str, Any] = operation(spec=spec, contract=contract, context=context, **kwargs)
            return result

    def open_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        return self._review_call("open_review", spec=spec, contract=contract, context=context)

    def resolve_review_context(self, *, spec: VerticalSpec, contract: dict[str, Any],
                               context: EmissionContext) -> EmissionContext:
        with self._operation_guard(contract, context) as record:
            reason = self._refusal(record, context, spec)
            if reason:
                raise ValueError(reason)
            return super().resolve_review_context(spec=spec, contract=contract, context=context)

    def get_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                   review_id: str) -> dict[str, Any]:
        return self._review_call("get_review", spec=spec, contract=contract, context=context, review_id=review_id)

    def grant_review(self, *, spec: VerticalSpec, contract: dict[str, Any], context: EmissionContext,
                     review_id: str, role: str) -> dict[str, Any]:
        return self._review_call("grant_review", spec=spec, contract=contract, context=context, review_id=review_id, role=role)


    def open_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any],
                               context: EmissionContext, destinations: tuple[str, ...],
                               expires_in_us: int, admit_within_us: int,
                               delegable: bool) -> dict[str, Any]:
        return self._review_call(
            "open_delegation_review", spec=spec, contract=contract, context=context,
            destinations=destinations, expires_in_us=expires_in_us,
            admit_within_us=admit_within_us, delegable=delegable,
        )

    def get_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any],
                              context: EmissionContext, delegation_review_id: str) -> dict[str, Any]:
        return self._review_call(
            "get_delegation_review", spec=spec, contract=contract, context=context,
            delegation_review_id=delegation_review_id,
        )

    def grant_delegation_review(self, *, spec: VerticalSpec, contract: dict[str, Any],
                                context: EmissionContext, delegation_review_id: str,
                                role: str) -> dict[str, Any]:
        return self._review_call(
            "grant_delegation_review", spec=spec, contract=contract, context=context,
            delegation_review_id=delegation_review_id, role=role,
        )

    def admit_delegation(self, *, spec: VerticalSpec, contract: dict[str, Any],
                         context: EmissionContext, delegation_review_id: str) -> dict[str, Any]:
        return self._review_call(
            "admit_delegation", spec=spec, contract=contract, context=context,
            delegation_review_id=delegation_review_id,
        )

    def delegation_root(self, *, spec: VerticalSpec, contract: dict[str, Any],
                        context: EmissionContext, delegation_review_id: str) -> dict[str, Any]:
        return self._review_call(
            "delegation_root", spec=spec, contract=contract, context=context,
            delegation_review_id=delegation_review_id,
        )

    def _audit(self, *, envelope: Any, assertion: Any, approval_cert: Any, permit: Any,
               qualifications: dict[str, Any] | None = None) -> dict[str, Any]:
        document = self.pack.rulebook.document
        return {"policy_ref": f"{document.vertical}/{document.policy_id}", "policy_version": document.version,
                "policy_digest": document.digest(), "pack_version": self.pack.reference,
                "pack_digest": self.pack.manifest.digest, "rulebook_digest": self.pack.rulebook.effective_digest,
                "assertion_id": assertion.assertion_id, "content_digest": assertion.content_digest,
                "decision": {"kind": envelope.record.decision.kind.value,
                             "reason_codes": list(envelope.record.decision.reason_codes)},
                "approval": None if approval_cert is None else {"approvers": list(approval_cert.approver_ids)},
                "emission_permit": None if permit is None else {"output_digest": permit.output_digest, "nonce": permit.nonce},
                "qualifications": qualifications, "evidence_head_hash": envelope.record_hash}


def build_pack_gate(pack: InstalledPack, *, registry: PackRegistry, trust: TrustDirectory,
                    engine: RegulatedEngine, host_verifiers: VerifierRegistry,
                    verifier_signers: Mapping[str, Signer], credential_verifier: CredentialVerifier,
                    intended_uses: IntendedUseRegistry, worm: WormStore,
                    qualifications: QualificationRegistry | None = None,
                    required_jurisdiction: str | None = None, review_store: ReviewStore | None = None,
                    review_extension_factory: Any = None, outage_alarm: OutageAlarm | None = None,
                    production_assurance: PackReadiness | None = None) -> RulebookGate:
    policy = pack.rulebook
    if registry.get(pack.reference) is not pack or not verify_document(trust, policy.document):
        raise ValueError("gate requires an installed, trusted signed pack")
    if credential_verifier is None:
        raise ValueError("pack release requires a credential authority")
    bind_credentials = getattr(credential_verifier, "for_pack", None)
    if callable(bind_credentials):
        credential_verifier = bind_credentials(pack, registry)
        if not callable(getattr(credential_verifier, "verify", None)):
            raise ValueError("pack credential factory did not return a credential verifier")
    if len(policy.content_types) != 1 or len(policy.actions("external")) != 1 or len(policy.actions("reversible")) != 1:
        raise ValueError("a release gate requires one content type, one draft action and one external action")
    source_reviews = review_extension_factory(pack=pack, registry=registry, credential_verifier=credential_verifier,
                                              review_store=review_store) if review_extension_factory is not None else None
    verifiers: dict[str, Verifier] = {}
    for check_id in policy.check_ids():
        check = pack.checks.get(check_id)
        verifier = check.run if check is not None else host_verifiers.resolve(check_id)
        if check_id == "source:fidelity" and source_reviews is not None:
            verifier = source_reviews  # Explicit host human verifier replaces any fixture registration.
        if verifier is None or check_id not in verifier_signers:
            raise ValueError(f"pack check {check_id} requires an explicit verifier and signer")
        verifiers[check_id] = verifier
    # Policy versions own the same content type. Share durable authority services,
    # but isolate policy lookup so a concurrently pinned version cannot see latest.
    policy_registry = PolicyRegistry()
    policy_registry.register(policy)
    risk_tier = int(policy.effective_content.get("risk_tier", 3))
    use = IntendedUse(policy.document.vertical, policy.actions("external")[0], risk_tier)
    version_uses = IntendedUseRegistry()
    version_uses.declare(use)
    version_engine = engine.for_policy(registry=policy_registry, preflight=engine._preflight.for_uses(version_uses))
    intended_uses.declare(use)
    return RulebookGate(pack=pack, registry=registry, engine=version_engine, verifiers=verifiers,
                        verifier_signers=verifier_signers, credential_verifier=credential_verifier,
                        worm=worm, qualifications=qualifications, required_jurisdiction=required_jurisdiction,
                        review_store=review_store, source_reviews=source_reviews, outage_alarm=outage_alarm,
                        release_readiness=(production_assurance.bind(
                            pack.manifest.id, tuple(policy.check_ids()), credential_verifier,
                        ) if production_assurance is not None else None))
