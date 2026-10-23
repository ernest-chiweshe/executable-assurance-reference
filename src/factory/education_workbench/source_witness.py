"""Explicit human source-review witnesses; draft awaiting host integration.

The host injects its signer, trust, bounded review store and existing enrollment
authority. Viewing and verification never sign. The host must hold release_guard
through the complete approval/release operation, not only verifier dispatch.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from typing import Any

from factory.education_workbench.authority_guard import authority_guard
from factory.education_workbench.reviewer_credentials import AssessmentScope, EnrollmentCredentialVerifier
from factory.packs.examples import EDUCATION_ID
from factory.projectos.regulated import EmissionContext
from regulated_core.canonical import digest_hex
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Outcome
from regulated_core.review_store import ReviewStore
from regulated_core.signing import Signature, Signer, TrustDirectory

from .source_material import SourceMaterial, retained_source_material, work_digest

SCHEMA = 'education/human-source-review/v1'
LOG_SCHEMA = 'education/human-source-review-log/v1'
HOUR_US = 3_600_000_000


class SourceWitnessError(ValueError):
    """An explicit, current human source review is unavailable."""


class HumanSourceReviews:
    def __init__(self, *, authority: EnrollmentCredentialVerifier, store: ReviewStore,
                 signer: Signer, trust: TrustDirectory) -> None:
        if not trust.is_known(signer.key_id):
            raise SourceWitnessError('Source-review signer requires an explicit trust anchor')
        self.authority, self.store, self.signer, self.trust = authority, store, signer, trust
        self._held: ContextVar[tuple[AssessmentScope, bool] | None] = ContextVar('human_source_scope', default=None)

    def __call__(self, draft: str, contract: dict[str, Any]) -> tuple[Outcome, tuple[str, ...]]:
        return Outcome.FAIL, ('human-source-review-context-required',)

    def material(self, contract: dict[str, Any], context: EmissionContext) -> SourceMaterial:
        state = getattr(context, 'retained_state', None)
        if not isinstance(state, dict):
            raise SourceWitnessError('The server-retained source snapshot is required')
        return retained_source_material(state, contract)

    def verify_context(self, draft: str, contract: dict[str, Any],
                       context: EmissionContext) -> tuple[Outcome, tuple[str, ...]]:
        try:
            if draft != contract.get('body'):
                raise SourceWitnessError('The verifier draft differs from the contract')
            return self.verify(material=self.material(contract, context), contract=contract, context=context)
        except ValueError:
            return Outcome.FAIL, ('human-source-review-required',)

    def view(self, contract: dict[str, Any], context: EmissionContext) -> dict[str, Any]:
        self._human(context)
        material = self.material(contract, context)
        with self.release_guard(contract, context):
            try:
                with self.authority.review_guard(contract=contract, context=context, actors=(context.actor_id,)):
                    self.authority.teacher_binding(context.actor_id, contract=contract, context=context)
                may_confirm = True
            except CredentialError:
                may_confirm = False
            result, reasons = self.verify(material=material, contract=contract, context=context)
            return {'required': True, 'material': material.public_view(), 'material_digest': material.digest(),
                    'can_confirm': may_confirm, 'confirmed': result == Outcome.PASS, 'evidence': list(reasons)}

    def confirm_from_context(self, *, contract: dict[str, Any], context: EmissionContext,
                             expected_material_digest: str, confirmed: bool, request_id: str) -> dict[str, Any]:
        try:
            return self.confirm(material=self.material(contract, context), contract=contract, context=context,
                                expected_material_digest=expected_material_digest, confirmed=confirmed, request_id=request_id)
        except CredentialError as exc:
            raise SourceWitnessError('Current signed teacher authority is required for source confirmation') from exc

    @staticmethod
    def _human(context: EmissionContext) -> None:
        if (not context.actor_id or context.actor_roles or context.is_producer
                or type(context.now_us) is not int or context.now_us <= 0):
            raise SourceWitnessError('An authenticated human without self-supplied roles is required')

    @staticmethod
    def _id(context: EmissionContext) -> str:
        return 'source-review:' + digest_hex([context.tenant, context.project_id])

    @contextmanager
    def release_guard(self, contract: dict[str, Any], context: EmissionContext,
                      *, writer: bool = False) -> Iterator[AssessmentScope]:
        """Lifecycle -> source project -> teacher authority, on the existing session.

        The Education gate uses this IN PLACE OF its ordinary lifecycle wrapper
        around the WHOLE operation. Confirmations
        take the exclusive counterpart, so a rejection cannot interleave between
        source verification and release issuance. Reentrant shared use is supported
        by the existing memory/PG authority guard.
        """
        scope = self.authority.assessment_scope(context.tenant, context.project_id)
        if (not isinstance(scope, AssessmentScope) or scope.tenant != context.tenant
                or scope.project_id != context.project_id or not scope.class_id
                or not scope.assessment_id or scope.contract_digest != work_digest(contract)
                or type(scope.expires_at_us) is not int or scope.expires_at_us <= context.now_us):
            raise SourceWitnessError('The retained assessment binding is missing, changed or expired')
        held = self._held.get()
        if held is not None:
            if held[0] != scope or (writer and not held[1]):
                raise SourceWitnessError('A source-review guard cannot change scope or upgrade its lock')
            yield scope
            return
        registry = self.authority.appointments.registry
        pack = registry.for_tenant(context.tenant, EDUCATION_ID)
        if pack is None:
            raise SourceWitnessError('The Education pack is inactive')
        with registry.resolution_guard(context.tenant, EDUCATION_ID, now_us=context.now_us,
                                       expected_reference=pack.reference) as record:
            if (record is None or record.reference != pack.reference
                    or record.pack_digest != pack.manifest.digest
                    or not pack.rulebook.document.effective_at(context.now_us)):
                raise SourceWitnessError('The Education pack is inactive or changed')
            with authority_guard(self.authority.appointments.store, context.tenant,
                    scope.class_id, ['source-review-project:' + context.project_id], exclusive=writer):
                actors: tuple[str, ...] = ()
                if not writer:
                    current = self.store.get(context.tenant, self._id(context))
                    if current is not None:
                        log = self._log(current)
                        body, _ = self._read_witness(log['requests'].get(log['current_request']))
                        if not isinstance(body.get('teacher_id'), str) or not body['teacher_id']:
                            raise SourceWitnessError('The source witness has no teacher')
                        actors = (body['teacher_id'],)
                guard = self.authority.review_guard(contract=contract, context=context, actors=actors) if actors else nullcontext()
                with guard:
                    token = self._held.set((scope, writer))
                    try:
                        yield scope
                    finally:
                        self._held.reset(token)

    def _read_witness(self, raw: Any) -> tuple[dict[str, Any], str]:
        if not isinstance(raw, dict) or set(raw) != {'body', 'signature'}:
            raise SourceWitnessError('Missing or malformed human source witness')
        body, signature = raw['body'], raw['signature']
        try:
            signed = Signature(**signature)
            if (not isinstance(body, dict) or body.get('schema') != SCHEMA
                    or body.get('method') != 'human' or signed.key_id != self.signer.key_id
                    or not self.trust.verify(body, signed)):
                raise SourceWitnessError('Untrusted human source witness')
        except (TypeError, KeyError, ValueError) as exc:
            raise SourceWitnessError('Untrusted human source witness') from exc
        return body, digest_hex(raw)

    def _log(self, value: Any) -> dict[str, Any]:
        if (not isinstance(value, dict) or value.get('schema') != LOG_SCHEMA
                or not isinstance(value.get('requests'), dict)
                or not isinstance(value.get('current_request'), str)):
            raise SourceWitnessError('Invalid retained source-review history')
        return value

    def confirm(self, *, material: SourceMaterial, contract: dict[str, Any],
                context: EmissionContext, expected_material_digest: str,
                confirmed: bool, request_id: str) -> dict[str, Any]:
        self._human(context)
        if type(confirmed) is not bool or not isinstance(request_id, str) or not request_id.strip():
            raise SourceWitnessError('An explicit yes/no decision and request identity are required')
        material.require_displayed(expected_material_digest)
        if material.contract_digest != work_digest(contract):
            raise SourceWitnessError('The comparison does not match the retained contract')
        with self.release_guard(contract, context, writer=True) as scope:
            with self.authority.review_guard(contract=contract, context=context, actors=(context.actor_id,)):
                # Read current authority without issuing another signed credential.
                bound, grant_digest, authority_expiry = self.authority.teacher_binding(
                    context.actor_id, contract=contract, context=context)
                if bound != scope:
                    raise SourceWitnessError('The teacher assessment binding changed')
                body = {'schema': SCHEMA, 'method': 'human', 'scope': asdict(scope),
                        'teacher_id': context.actor_id, 'teacher_grant_digest': grant_digest,
                        'material_digest': material.digest(), 'confirmed': confirmed,
                        'request_id': request_id, 'issued_at_us': context.now_us,
                        'expires_at_us': min(authority_expiry, scope.expires_at_us, context.now_us + HOUR_US)}

                def retain(old: dict[str, Any] | None) -> dict[str, Any]:
                    log: dict[str, Any] = self._log(old) if old is not None else {
                        'schema': LOG_SCHEMA, 'requests': {}, 'current_request': ''}
                    prior = log['requests'].get(request_id)
                    if prior is not None:
                        previous, _ = self._read_witness(prior)
                        if (log['current_request'] != request_id
                                or any(previous.get(k) != body[k] for k in
                                       ('scope', 'teacher_id', 'teacher_grant_digest', 'material_digest', 'confirmed', 'request_id'))
                                or not previous['issued_at_us'] <= context.now_us < previous['expires_at_us']):
                            raise SourceWitnessError('This confirmation request is changed, expired or superseded')
                        return log  # Idempotent current confirmation; no repeated Sign.
                    signature = self.signer.sign(body)
                    witness = {'body': body, 'signature': asdict(signature)}
                    self._read_witness(witness)  # Verify before persistence.
                    return {'schema': LOG_SCHEMA, 'requests': {**log['requests'], request_id: witness},
                            'current_request': request_id}

                state = self.store.transact(context.tenant, self._id(context), retain)
                witness = state['requests'][state['current_request']]
                saved, fingerprint = self._read_witness(witness)
                return {'method': 'human', 'confirmed': saved['confirmed'], 'teacher_id': saved['teacher_id'],
                        'witness_digest': fingerprint, 'expires_at_us': saved['expires_at_us']}

    def verify(self, *, material: SourceMaterial, contract: dict[str, Any],
               context: EmissionContext) -> tuple[Outcome, tuple[str, ...]]:
        """Read and revalidate the latest explicit teacher decision; never signs."""
        try:
            if material.contract_digest != work_digest(contract):
                raise SourceWitnessError('The source comparison changed')
            with self.release_guard(contract, context) as scope:
                log = self._log(self.store.get(context.tenant, self._id(context)))
                body, fingerprint = self._read_witness(log['requests'].get(log['current_request']))
                if (body.get('scope') != asdict(scope) or body.get('material_digest') != material.digest()
                        or body.get('confirmed') is not True
                        or body.get('request_id') != log['current_request']
                        or type(body.get('issued_at_us')) is not int or type(body.get('expires_at_us')) is not int
                        or not body['issued_at_us'] <= context.now_us < body['expires_at_us']
                        or body['expires_at_us'] > scope.expires_at_us
                        or body['expires_at_us'] - body['issued_at_us'] > HOUR_US
                        or not isinstance(body.get('teacher_id'), str)):
                    raise SourceWitnessError('The human source review is missing, negative, stale or expired')
                actor = body['teacher_id']
                with self.authority.review_guard(contract=contract, context=context, actors=(actor,)):
                    bound, grant, expiry = self.authority.teacher_binding(actor, contract=contract, context=context)
                    if bound != scope or grant != body.get('teacher_grant_digest') or expiry <= context.now_us:
                        raise SourceWitnessError('The source reviewer no longer holds the recorded teacher authority')
                return Outcome.PASS, ('human-source-review', 'teacher:' + actor, 'witness:' + fingerprint)
        except (ValueError, KeyError, TypeError, CredentialError):
            return Outcome.FAIL, ('human-source-review-required',)


@dataclass(frozen=True)
class EducationSourceReviewFactory:
    """Explicit domain extension supplied by the host; constructs no new authority."""

    signer: Signer
    trust: TrustDirectory

    def __call__(self, *, pack: Any, registry: Any, credential_verifier: Any,
                 review_store: ReviewStore | None) -> HumanSourceReviews | None:
        if pack.manifest.id != EDUCATION_ID:
            return None
        if (review_store is None
                or not isinstance(credential_verifier, EnrollmentCredentialVerifier)
                or credential_verifier.appointments.registry is not registry):
            raise SourceWitnessError('Human Education review requires the composed enrollment authority and review store')
        return HumanSourceReviews(authority=credential_verifier, store=review_store,
                                  signer=self.signer, trust=self.trust)
