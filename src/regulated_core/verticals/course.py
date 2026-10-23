"""Forgiving course vertical (non-regulated). The proof that ONE core serves both worlds.

This policy needs no verifications, no lineage, no calibrated confidence, no data classes — it
works on the LEAN base assertion. It discloses uncertainty and proceeds for reversible renders,
and asks a human only at the external publish boundary. It is a pure addition: registering it
touches no core file, and it demonstrates that the regulated machinery does not tax a normal
research/education/content workload.
"""
from __future__ import annotations

from ..models import Action, ActionEffect, Annotation, ApprovalRequirement, Assertion, Decision, PolicyContext, PolicyRef

RENDER, PUBLISH = "course:render-lesson", "course:publish-lesson"


class CoursePolicy:
    content_types = frozenset({"course:lesson"})
    ref = PolicyRef(vertical="course", policy_id="forgiving-course", version="1.0.0")

    def evaluate(self, a: Assertion, action: Action, ctx: PolicyContext) -> Decision:
        if action.effect is ActionEffect.REVERSIBLE:
            # disclose uncertainty and proceed; no verification burden
            if a.confidence is None:
                return Decision.allow_with("RENDER_UNVERIFIED", "rendered with an unverified-content disclosure",
                                           Annotation("disclaimer", "educational draft — not independently verified"))
            return Decision.allow("RENDER", "reversible educational render")
        # publishing outside is the only human checkpoint
        req = ApprovalRequirement((frozenset({"instructor"}),), 1, action.action_id,
                                  "an instructor signs off before a lesson is published", 24 * 3600 * 1_000_000)
        return Decision.require_approval("PUBLISH_REVIEW", "human review at the publish boundary", req)
