"""Retained source comparison for explicit human Education review.

Draft implementation against frozen product35e. No authority, signing, network,
or persistence side effects. The caller supplies a server-loaded state/contract
snapshot; browser values can only name the expected material digest.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from factory.projectos.governed_release import vertical_contract
from regulated_core.canonical import digest_hex


class SourceMaterialError(ValueError):
    """Retained material does not support this exact source review."""


def _text_hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _text(source: Mapping[str, Any], name: str) -> str:
    value = source.get(name)
    if not isinstance(value, str) or not value.strip():
        raise SourceMaterialError(f"Retained {name} must be nonempty text")
    return value


@dataclass(frozen=True)
class SourceMaterial:
    """Exactly the learner work, feedback and rubric shown for a human decision."""

    learner_draft: str
    feedback: str
    rubric: str
    rubric_identifier: str
    rubric_criteria: tuple[str, ...]
    media_reference: str
    contract_digest: str
    learner_digest: str
    feedback_digest: str
    rubric_digest: str

    def public_view(self) -> dict[str, Any]:
        return {
            "schema": "education/source-review-material/v1",
            "review_method": "human",
            "learner_draft": self.learner_draft,
            "feedback": self.feedback,
            "rubric": self.rubric,
            "rubric_identifier": self.rubric_identifier,
            "rubric_criteria": list(self.rubric_criteria),
            "media_reference": self.media_reference,
            "contract_digest": self.contract_digest,
            "learner_digest": self.learner_digest,
            "feedback_digest": self.feedback_digest,
            "rubric_digest": self.rubric_digest,
        }

    def digest(self) -> str:
        return digest_hex(self.public_view())

    def require_displayed(self, expected_digest: str) -> None:
        """Refuse a decision submitted against an older browser comparison."""
        if not isinstance(expected_digest, str) or expected_digest != self.digest():
            raise SourceMaterialError("The reviewed material changed; reload and review it again")


def work_digest(contract: Mapping[str, Any]) -> str:
    """The identity of the learner's work an assessment scope and a source review bind: the vertical contract,
    never the release governance around it, which the review and the door bind separately."""
    return digest_hex(vertical_contract(contract))


def retained_source_material(state: Mapping[str, Any], contract: Mapping[str, Any]) -> SourceMaterial:
    """Match retained SDK material to the full contract without claiming fidelity.

    A matching digest only establishes what a human will review. It is never a
    semantic PASS, teacher credential, signed witness or release permission.
    """
    learner = _text(state, "learner_draft")
    rubric = _text(state, "rubric")
    identifier = _text(state, "rubric_identifier")
    feedback = _text(contract, "body")
    criteria = contract.get("rubric_criteria")
    if (not isinstance(criteria, list) or not criteria
            or any(not isinstance(item, str) or not item.strip() for item in criteria)
            or len(set(criteria)) != len(criteria)):
        raise SourceMaterialError("The retained contract requires distinct rubric criteria")
    if contract.get("rubric_identifier") != identifier:
        raise SourceMaterialError("The retained rubric identity differs from the contract")
    retained_criteria = state.get("rubric_criteria")
    if isinstance(retained_criteria, str):
        retained_criteria = retained_criteria.splitlines()
    if (not isinstance(retained_criteria, list)
            or any(not isinstance(item, str) for item in retained_criteria)
            or [item.strip() for item in retained_criteria if item.strip()] != criteria):
        raise SourceMaterialError("The retained rubric criteria differ from the contract")
    media = state.get("submission_media_ref", "")
    if not isinstance(media, str) or contract.get("media", "") != media:
        raise SourceMaterialError("The retained submission media differs from the contract")
    # Exactly the SDK's rubric serialization, including its default ASCII escaping.
    rubric_document = {"identifier": identifier, "text": rubric, "criteria": criteria}
    rubric_digest = _text_hash(json.dumps(rubric_document, sort_keys=True, separators=(",", ":")))
    learner_digest, feedback_digest = _text_hash(learner), _text_hash(feedback)
    for field, expected in (("learner_draft_digest", learner_digest),
                            ("feedback_digest", feedback_digest), ("rubric_digest", rubric_digest)):
        if contract.get(field) != expected:
            raise SourceMaterialError(f"The retained {field} differs from the contract")
    return SourceMaterial(learner, feedback, rubric, identifier, tuple(criteria), media,
                          work_digest(contract), learner_digest, feedback_digest, rubric_digest)
