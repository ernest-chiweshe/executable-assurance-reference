"""A signed policy boundary for the reference's domain-pack-free examples."""

from contextlib import contextmanager
from dataclasses import replace

from assurance_reference.qualified_engine import QualifiedReferenceEngine
from assurance_reference.retention_contract import require_retention_operations
from regulated_core.approval_exchange import ReviewError
from regulated_core.document_gate import DocumentGate, build_document_gate
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.policy_document import verify_document


class SignedReferenceDocumentGate(DocumentGate):
    """Retain the original gate and additionally enforce the host's policy pin.

    The policy is a host-issued local fixture, not a domain pack or an owner
    signature. Its signature/window is checked at entry and at the effect.
    Stored receipts remain readable after the policy's effective window.
    """

    def __init__(self, *, factory, document, authority):
        require_retention_operations(factory.worm)
        if not isinstance(factory.engine, QualifiedReferenceEngine):
            raise TypeError("document gate requires the qualified reference engine")
        if not callable(getattr(factory.credential_verifier, "admit_release", None)):
            raise ValueError("document gate requires receiving-side session admission")
        if factory.production_assurance is not None or factory.review_extension_factory is not None:
            raise ValueError("this local document composition does not yet support those configured extensions")
        self._document_trust, self._document_authority = factory.trust, authority
        self._document_digest = document.digest()
        self._check_document(document, factory.engine.targets.now_us())
        parameters = dict(engine=factory.engine, verifiers=factory.host_verifiers,
            verifier_signers=factory.verifier_signers, pack_version="document:" + self._document_digest,
            worm=factory.worm, credential_verifier=factory.credential_verifier,
            required_jurisdiction=factory.required_jurisdiction, qualifications=factory.qualifications,
            review_store=factory.review_store)
        validated = build_document_gate(document, intended_uses=factory.intended_uses, **parameters)
        engine = parameters.pop("engine")
        super().__init__(engine, policy=validated.policy, **parameters)
        if factory.outage_alarm is not None:
            self._outage = factory.outage_alarm

    def _check_document(self, document, now):
        if (document.digest() != self._document_digest
                or not verify_document(self._document_trust, document, authority=self._document_authority)
                or not document.effective_at(now)):
            raise CredentialError("host-pinned policy is untrusted, changed or outside its effective window")

    def _trusted(self, context):
        current = super()._trusted(context)
        document = self.policy.document
        self._check_document(document, current.now_us)
        if document.effective_until_us:
            current = replace(current, not_after_us=min(
                current.not_after_us or document.effective_until_us, document.effective_until_us))
        return current

    def _check_spec(self, spec):
        block = spec.regulated
        if (block is None or spec.name != self.VERTICAL
                or block.policy_digest != self._document_digest
                or block.policy_ref != self.pinning["policy_ref"]
                or block.pack_version != self.pinning["pack_version"]):
            raise ReviewError("reference document policy must match the host-bound vertical specification")

    def _review_scope(self, spec, context):
        super()._review_scope(spec, context)
        self._check_spec(spec)
        self._check_document(self.policy.document, self._engine.targets.now_us())

    def open_review(self, *, context, **kwargs):
        return super().open_review(context=self._trusted(context), **kwargs)

    def grant_review(self, *, context, **kwargs):
        return super().grant_review(context=self._trusted(context), **kwargs)

    def get_review(self, *, context, **kwargs):
        return super().get_review(context=self._trusted(context), **kwargs)

    def resolve_review_context(self, *, context, **kwargs):
        return super().resolve_review_context(context=self._trusted(context), **kwargs)

    def record_entrance_refusal(self, *, context, **kwargs):
        # Original export() has no caller context. Record the refusal in the
        # authenticated host's tenant, retaining its unattributed actor label.
        # This grants no release authority and never supplies a human approver.
        if context.actor_id == "unattributed-export":
            context = replace(context, tenant=self._credverify.authenticated.tenant)
        return super().record_entrance_refusal(context=self._trusted(context), **kwargs)

    def review_draft(self, *, spec, **kwargs):
        self._check_spec(spec)
        return super().review_draft(spec=spec, **kwargs)

    def authorize_release(self, *, spec, **kwargs):
        self._check_spec(spec)
        return super().authorize_release(spec=spec, **kwargs)

    def commit_release(self, *, spec, **kwargs):
        self._check_spec(spec)
        return super().commit_release(spec=spec, **kwargs)

    @contextmanager
    def _release_admission(self, contract, context, decision):
        self._check_document(self.policy.document, self._engine.targets.now_us())
        with super()._release_admission(contract, context, decision) as current:
            def check():
                current()
                try:
                    self._check_document(self.policy.document, self._engine.targets.now_us())
                except CredentialError as error:
                    raise EmissionError(str(error)) from error
            check()
            yield check
