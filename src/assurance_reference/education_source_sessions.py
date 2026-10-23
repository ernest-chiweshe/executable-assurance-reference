"""Authenticated composition of the pinned retained-source witness service.

The host supplies retained material and current assessment authority. Viewing
does not confirm, and verification never signs. No effect port is composed here.
"""

from contextlib import contextmanager
from dataclasses import replace

from assurance_reference.education_review_sessions import SessionEnrollmentReviewer
from factory.education_workbench.source_witness import HumanSourceReviews, SourceWitnessError
from regulated_core.identity_provider import CredentialError
from regulated_core.models import Outcome


class SessionHumanSourceReviews(HumanSourceReviews):
    def __init__(self, *, authority, store, signer, trust):
        if not isinstance(authority, SessionEnrollmentReviewer):
            raise TypeError("source review requires session-bound Education authority")
        super().__init__(authority=authority, store=store, signer=signer, trust=trust)

    @contextmanager
    def release_guard(self, contract, context, *, writer=False):
        # Session parents precede pack lifecycle, source-project and teacher
        # locks. Original nested calls reuse the same admitted session.
        with self.authority._admitted(context):
            with super().release_guard(contract, self.authority._current_context(context),
                                       writer=writer) as scope:
                yield scope

    def view(self, contract, context):
        with self.authority._admitted(context):
            return super().view(contract, self.authority._current_context(context))

    def confirm(self, *, material, contract, context, expected_material_digest, confirmed, request_id):
        with self.authority._admitted(context):
            current = self.authority._current_context(context)
            if material != self.material(contract, current):
                raise SourceWitnessError("confirmation must use the server-retained material")
            result = super().confirm(material=material, contract=contract, context=current,
                expected_material_digest=expected_material_digest, confirmed=confirmed,
                request_id=request_id)
            fresh = self.authority._current_context(context)
            if (result["expires_at_us"] <= fresh.now_us or
                    (confirmed and self.verify(material=material, contract=contract,
                                               context=fresh)[0] != Outcome.PASS)):
                raise SourceWitnessError("confirmation was recorded but is no longer current")
            return result

    def verify(self, *, material, contract, context):
        try:
            # ApprovalExchange re-evaluates the original requester's policy
            # while the authenticated reviewer holds this service's guard.
            # That read-only source lookup uses the already admitted human;
            # it does not issue credentials or admit a different session.
            held = self._held.get()
            identity = self.authority.authenticated
            if (held is not None and self.authority._session_check.get() is not None
                    and (context.tenant, context.project_id) == (held[0].tenant, held[0].project_id)
                    and context.tenant == identity.tenant
                    and not context.actor_roles and not context.is_producer):
                context = replace(context, actor_id=identity.principal)
            with self.authority._admitted(context):
                current = self.authority._current_context(context)
                if material != self.material(contract, current):
                    raise SourceWitnessError("verification must use the server-retained material")
                return super().verify(material=material, contract=contract, context=current)
        except (CredentialError, ValueError):
            return Outcome.FAIL, ("human-source-review-required",)
