"""Retained Education approvals and source authority held through the effect.

Composition binds one authenticated verifier to its own real pack gate. The
receiving check reloads the signed stored review; request-supplied receipts or
approval objects never substitute for it. Verification issues no new receipts.
"""

from contextlib import contextmanager
from dataclasses import replace

from assurance_reference.education_review_sessions import SessionEnrollmentReviewer
from assurance_reference.education_source_sessions import SessionHumanSourceReviews
from assurance_reference.session_credentials import SessionBoundCredentials
from factory.packs.examples import EDUCATION_ID
from regulated_core.approval import ApprovedDecision
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Outcome
from regulated_core.permit import EmissionError
from regulated_core.target import ReleaseAdmissionUnavailable


class EducationReleaseAuthority(SessionEnrollmentReviewer):
    """One session, one source service, one gate; incomplete composition refuses."""

    def __init__(self, *args, review_store, witness_signer, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_reviews = SessionHumanSourceReviews(authority=self, store=review_store,
            signer=witness_signer, trust=self.appointments.trust)
        self._receiving_gate = None

    def review_extension(self, *, pack, registry, credential_verifier, review_store):
        if (pack.manifest.id != EDUCATION_ID or credential_verifier is not self
                or registry is not self.appointments.registry
                or registry.get(pack.reference) is not pack
                or review_store is not self.source_reviews.store):
            raise ValueError("Education source authority must share the composed gate and store")
        return self.source_reviews

    def bind_receiving_gate(self, gate, spec):
        # This is host construction, before serving any request. Rebinding is
        # prohibited so the resolver cannot be replaced by a request callback.
        from regulated_core.pack_gate import RulebookGate
        if (self._receiving_gate is not None or not isinstance(gate, RulebookGate)
                or gate._credverify is not self or gate.source_reviews is not self.source_reviews
                or gate.registry is not self.appointments.registry):
            raise ValueError("Education receiving authority requires its own complete pack gate")
        self._receiving_gate = (gate, spec)

    def _stored_approval(self, contract, context, authorization):
        if self._receiving_gate is None:
            raise CredentialError("Education receiving gate has not been bound")
        gate, spec = self._receiving_gate
        reference = authorization.permit.permit.approval_ref
        if not reference:
            raise CredentialError("Education release requires a retained approval reference")
        resolved = gate.resolve_review_context(spec=spec, contract=dict(contract),
            context=replace(self._current_context(context), approval=reference))
        approval = resolved.approval
        if not isinstance(approval, ApprovedDecision) or not approval.credential_receipts:
            raise CredentialError("Education release requires stored reviewer receipts")
        record = authorization.envelope.record
        if (approval.certificate.request_id != reference
                or replace(approval.envelope.record, record_id=record.record_id,
                           decided_at_us=record.decided_at_us) != record):
            raise CredentialError("stored Education approval differs from the authorized decision")
        return approval

    def _check_authority(self, contract, context, authorization, approved):
        current = self._current_context(context)
        retained = self._stored_approval(contract, current, authorization)
        if retained != approved:
            raise CredentialError("the retained Education approval changed during admission")
        for receipt in retained.credential_receipts:
            self.validate_review(receipt, contract=contract, context=current)
        if self.source_reviews.verify_context(contract.get("body"), contract, current)[0] != Outcome.PASS:
            raise CredentialError("current explicit Education source confirmation is required")

    @contextmanager
    def admit_release(self, *, contract, context, authorization):
        try:
            # Reuse the existing exact session/contract/principal/permit checks
            # and deadline, including the session row lock through the effect.
            with SessionBoundCredentials.admit_release(self, contract=contract,
                    context=context, authorization=authorization) as session_current:
                session_current()
                token = self._session_check.set(session_current)
                try:
                    # Session -> lifecycle -> source project/witness teacher ->
                    # all reviewers. Nested gate operations reuse these guards.
                    with self.source_reviews.release_guard(contract, self._current_context(context)):
                        approved = self._stored_approval(contract, context, authorization)
                        actors = tuple(sorted({r.subject_id for r in approved.credential_receipts}))
                        with self.review_guard(contract=contract, context=context, actors=actors):
                            self._check_authority(contract, context, authorization, approved)

                            def before_effect():
                                try:
                                    session_current()
                                    self._check_authority(contract, context, authorization, approved)
                                    session_current()
                                    # Repeat the intact permit/revocation/margin
                                    # check after these additional blocking reads.
                                    self._receiving_gate[0]._engine.targets.current(
                                        authorization.permit, at_effect=True)
                                except (CredentialError, ValueError) as error:
                                    raise EmissionError(str(error)) from error
                                except EmissionError:
                                    raise
                                except Exception as error:
                                    raise ReleaseAdmissionUnavailable(
                                        "Education authority unavailable before effect") from error

                            yield before_effect
                finally:
                    self._session_check.reset(token)
        except (CredentialError, ValueError, EmissionError) as error:
            raise CredentialError(str(error)) from error
        except ReleaseAdmissionUnavailable:
            raise
        except Exception as error:
            raise ReleaseAdmissionUnavailable("Education admission unavailable; reconcile any effect") from error
