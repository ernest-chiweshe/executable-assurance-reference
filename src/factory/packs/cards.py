"""Advisory cards and the human's decision on them, shaped like CDS Hooks.

The platform never acts on a customer's behalf in a regulated domain; it SUGGESTS, a qualified human
ACCEPTS or OVERRIDES, and the outcome is fed back and kept. CDS Hooks already defines that shape
for clinicians (a card with ``summary``, ``indicator``, ``source``, ``suggestions`` with concrete
``actions``, ``selectionBehavior``, ``overrideReasons``, and a feedback message whose ``outcome`` is
``accepted`` or ``overridden``). A teacher reviewing feedback, a compliance officer reviewing a
brief and a clinician reviewing patient education read the same card and answer the same way.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

INDICATORS = ("info", "warning", "critical")
SELECTION = ("at-most-one", "any")
OUTCOMES = ("accepted", "overridden")
_UUID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CardError(ValueError):
    """A card or a feedback record is malformed."""


@dataclass(frozen=True, slots=True)
class Coding:
    code: str
    display: str
    system: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "display": self.display, "system": self.system}


@dataclass(frozen=True, slots=True)
class CardAction:
    type: str                       # create | update | delete
    description: str
    resource: Mapping[str, Any] | None = None
    resource_id: str = ""

    def __post_init__(self) -> None:
        if self.type not in ("create", "update", "delete"):
            raise CardError("action type must be create, update or delete")
        if not self.description.strip():
            raise CardError("an action needs a human-readable description")
        if self.type in ("create", "update") and self.resource is None:
            raise CardError(f"a {self.type} action carries its resource")
        if self.type == "delete" and not self.resource_id:
            raise CardError("a delete action names the resource id")

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "description": self.description,
                "resource": None if self.resource is None else dict(self.resource), "resourceId": self.resource_id}


@dataclass(frozen=True, slots=True)
class Suggestion:
    uuid: str
    label: str
    actions: tuple[CardAction, ...] = ()
    is_recommended: bool = False

    def __post_init__(self) -> None:
        if not _UUID.fullmatch(self.uuid) or not self.label.strip():
            raise CardError("a suggestion needs a bounded uuid and a label")

    def to_dict(self) -> dict[str, Any]:
        return {"uuid": self.uuid, "label": self.label, "isRecommended": self.is_recommended,
                "actions": [a.to_dict() for a in self.actions]}


@dataclass(frozen=True, slots=True)
class Source:
    label: str
    rulebook_ref: str
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "rulebookRef": self.rulebook_ref, "url": self.url}


@dataclass(frozen=True, slots=True)
class Link:
    label: str
    url: str
    type: str = "absolute"

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "url": self.url, "type": self.type}


@dataclass(frozen=True, slots=True)
class Card:
    uuid: str
    summary: str
    indicator: str
    source: Source
    detail: str = ""
    suggestions: tuple[Suggestion, ...] = ()
    selection_behavior: str = ""
    override_reasons: tuple[Coding, ...] = ()
    links: tuple[Link, ...] = ()

    def __post_init__(self) -> None:
        if not _UUID.fullmatch(self.uuid):
            raise CardError("card uuid must be a bounded identifier")
        if not 1 <= len(self.summary) <= 140 or "\n" in self.summary:
            raise CardError("summary is one sentence under 140 characters")
        if self.indicator not in INDICATORS:
            raise CardError(f"indicator must be one of {INDICATORS}")
        if self.suggestions and self.selection_behavior not in SELECTION:
            raise CardError("a card with suggestions declares selection_behavior (at-most-one | any)")
        if not self.suggestions and self.selection_behavior:
            raise CardError("selection_behavior only accompanies suggestions")
        ids = [s.uuid for s in self.suggestions]
        if len(set(ids)) != len(ids):
            raise CardError("suggestion uuids must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid, "summary": self.summary, "indicator": self.indicator, "detail": self.detail,
            "source": self.source.to_dict(), "suggestions": [s.to_dict() for s in self.suggestions],
            "selectionBehavior": self.selection_behavior, "overrideReasons": [c.to_dict() for c in self.override_reasons],
            "links": [link.to_dict() for link in self.links],
        }


@dataclass(frozen=True, slots=True)
class Feedback:
    card_uuid: str
    outcome: str                    # accepted | overridden
    actor: str
    outcome_timestamp: str          # ISO 8601 UTC
    accepted_suggestions: tuple[str, ...] = ()
    override_reason: Coding | None = None
    comment: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise CardError(f"outcome must be one of {OUTCOMES}")
        if not _UUID.fullmatch(self.card_uuid) or not self.actor.strip():
            raise CardError("feedback names the card and the actor")
        if not self.outcome_timestamp.endswith(("Z", "+00:00")):
            raise CardError("outcome_timestamp is an ISO 8601 UTC instant")
        if self.outcome == "overridden" and self.override_reason is None and not self.comment.strip():
            raise CardError("an override carries a reason code or a comment")
        if self.outcome == "accepted" and self.override_reason is not None:
            raise CardError("an acceptance carries no override reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "card": self.card_uuid, "outcome": self.outcome, "actor": self.actor,
            "outcomeTimestamp": self.outcome_timestamp,
            "acceptedSuggestions": [{"id": s} for s in self.accepted_suggestions],
            "overrideReason": None if self.override_reason is None else {**self.override_reason.to_dict(),
                                                                          "userComment": self.comment},
        }


def validate_feedback(card: Card, feedback: Feedback) -> list[str]:
    """What the card allows: accepted suggestions must exist, at-most-one means one, an override
    reason must be one the card offered (or a comment when it offered none)."""
    p: list[str] = []
    if feedback.card_uuid != card.uuid:
        p.append("feedback names a different card")
    known = {s.uuid for s in card.suggestions}
    unknown = [s for s in feedback.accepted_suggestions if s not in known]
    if unknown:
        p.append(f"accepted suggestions not on the card: {unknown}")
    if feedback.outcome == "accepted" and card.suggestions and not feedback.accepted_suggestions:
        p.append("accepting a card with suggestions names which suggestions were accepted")
    if card.selection_behavior == "at-most-one" and len(feedback.accepted_suggestions) > 1:
        p.append("this card allows at most one accepted suggestion")
    if feedback.outcome == "overridden" and card.override_reasons and feedback.override_reason is not None \
            and feedback.override_reason.code not in {c.code for c in card.override_reasons}:
        p.append("override reason is not one the card offered")
    return p


def card_from_template(template: Mapping[str, Any], *, uuid: str, rulebook_ref: str, source_label: str,
                       detail: str = "", suggestions: tuple[Suggestion, ...] = (),
                       selection_behavior: str = "") -> Card:
    """A rulebook's card template (indicator, summary, override reasons) becomes a concrete card."""
    reasons = tuple(Coding(str(r["code"]), str(r["display"]), str(r.get("system", "")))
                    for r in template.get("override_reasons", ()) or ())
    return Card(uuid=uuid, summary=str(template["summary"]), indicator=str(template["indicator"]),
                source=Source(source_label, rulebook_ref), detail=detail, suggestions=suggestions,
                selection_behavior=selection_behavior if suggestions else "", override_reasons=reasons)


__all__ = ["INDICATORS", "OUTCOMES", "SELECTION", "Card", "CardAction", "CardError", "Coding", "Feedback", "Link",
           "Source", "Suggestion", "card_from_template", "validate_feedback"]
