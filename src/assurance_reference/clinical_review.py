"""Explicit retained-review caller for clinical finalisation.

The ordinary inherited finalise path is unchanged. These methods prepare a
frozen attempt and later complete its stored review through the same gate,
artifact, receiving admission and settlement paths. Reviewer admission is
composed separately by the host; this caller never invents an approver.
"""
from dataclasses import replace
from hashlib import sha256

from assurance_reference.clinical_review_attempts import prepare_packet
from factory.health_ui import documents as doc_mod
from factory.health_ui.clinical_release import (
    ClinicalFinalisation, FinalisationRefused, _REFUSALS, _UNAVAILABLE,
    CREDENTIAL_SERVICE_UNAVAILABLE,
)
from factory.projectos.regulated import EmissionContext, ReleaseOutcome


class ReviewedClinicalFinalisation(ClinicalFinalisation):
    def __init__(self, *, review_attempts, **configuration):
        if not callable(getattr(review_attempts, "retain", None)) or not callable(
                getattr(review_attempts, "get", None)):
            raise ValueError("clinical reviewed finalisation requires retained preparation storage")
        super().__init__(**configuration)
        self._review_attempts = review_attempts

    def begin_review(self, session, document, clinician):
        """Freeze/render once and open an idempotent retained owner review."""
        if document.finalisation is None or document.finalisation.state == doc_mod.FINALISATION_FAILED:
            record, context, contract, content = self._prepare_finalisation(session, document, clinician)
            packet = prepare_packet(context=context, contract=contract,
                                    artifact_address=record.artifact_address, artifact=content)
            # Failure after freezing stays pending for the existing bounded
            # receipt-recovery path; never render or silently retry a new nonce.
            self._review_attempts.retain(packet)
        contract, context, _ = self._pending_review(session, document, clinician)
        return self._gate.open_review(spec=self._spec, contract=contract, context=context)

    def review_request(self, session, document, clinician):
        """Return exact owner-admitted inputs for the host's review composition."""
        contract, context, _ = self._pending_review(session, document, clinician)
        return contract, context

    def _pending_review(self, session, document, clinician):
        if clinician.workspace_id != self._workspace or session.owner_id != clinician.owner_id:
            raise FinalisationRefused("only the document's own clinician can continue its review")
        current = self._store.get(session.session_id, clinician.owner_id)
        stored = current.document(document.doc_id) if current is not None else None
        record = stored.finalisation if stored is not None else None
        if (record is None or record.state != doc_mod.FINALISATION_PENDING
                or document.finalisation is None or document.finalisation.nonce != record.nonce
                or stored.digest() != record.document_digest):
            raise FinalisationRefused("the retained document has no matching pending review attempt")
        packet = self._review_attempts.get(record.nonce)
        if packet is None:
            raise FinalisationRefused("pending preparation is unavailable; use receipt recovery after its deadline")
        context = EmissionContext(**packet["context"])
        now = self._now_us()
        if now >= context.not_after_us:
            raise FinalisationRefused("review attempt reached its recovery deadline; resolve its receipt")
        if (context.not_after_us != record.started_us + self._window_us
                or context.nonce != record.nonce
                or packet["artifact_address"] != record.artifact_address
                or packet["artifact_sha256"] != record.artifact_sha256):
            raise FinalisationRefused("retained review preparation differs from the pending attempt")
        content = self._artifacts.get(self._tenant, record.artifact_address)
        if sha256(content).hexdigest() != record.artifact_sha256:
            raise FinalisationRefused("retained review artifact digest differs")
        fresh = self._context(current, stored, clinician, record)
        contract = self._contract(current, stored, record, content, fresh, clinician)
        # This also preserves the original login reference and expiry. A later
        # login cannot rebind an already prepared clinical review.
        if (contract != packet["contract"]
                or replace(fresh, now_us=context.now_us) != replace(context, actor_roles=tuple(context.actor_roles))):
            raise FinalisationRefused("clinical review inputs or authenticated session changed")
        return contract, replace(fresh, now_us=now), content

    def complete_review(self, session, document, clinician):
        """Resolve signed human review, then use the existing authorize/commit path."""
        contract, context, content = self._pending_review(session, document, clinician)
        opened = self._gate.open_review(spec=self._spec, contract=contract, context=context)
        # An incomplete quorum stays pending. No direct approval fallback exists.
        approved = self._gate.resolve_review_context(spec=self._spec, contract=contract,
            context=replace(context, approval=opened["review_id"]))
        try:
            decision = self._gate.authorize_release(spec=self._spec, contract=contract,
                out_path=context.release_target, context=approved, artifact=content)
        except _REFUSALS as refused:
            return self._settle(session, document, ReleaseOutcome("failed", str(refused)))
        except _UNAVAILABLE as down:
            return self._settle(session, document, ReleaseOutcome("failed",
                f"{CREDENTIAL_SERVICE_UNAVAILABLE}: {down}; nothing was approved or written"))
        if not decision.allowed:
            return self._settle(session, document, ReleaseOutcome("failed", decision.reason))
        outcome = self._gate.commit_release(spec=self._spec, contract=contract, decision=decision,
            artifact=content, out_path=context.release_target,
            context=replace(approved, now_us=self._now_us()))
        return self._settle(session, document, outcome)
