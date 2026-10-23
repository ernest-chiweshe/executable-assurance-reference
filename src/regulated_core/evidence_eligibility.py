"""Eligibility key projections and raw query qualification (SPEC029/030/031).

No caller activation. Stored projections require a decoded envelope already
qualified by verify_envelope; append and lookup verifiers enforce that rule.
"""
from decimal import Decimal
from fractions import Fraction
from typing import Any

from .models import Action, ActionEffect
from .evidence_questions import QuestionRefused, QuestionResult, qualify_question, normalize_json_key

DECISION_ELIGIBLE = "release_decision_eligible"
OUTCOME_ELIGIBLE = "release_outcome_eligible"


def qualify_action_question(action: Any) -> QuestionResult:
    kind = type(action)
    if kind is not Action:
        # Identity comparisons avoid foreign metaclass equality and attributes.
        if any(kind is safe for safe in (type(None), bool, int, str, float, Decimal,
                                        Fraction, list, dict, tuple, bytes, bytearray,
                                        set, frozenset)):
            return QuestionResult(False)
        raise QuestionRefused("unsupported action question type")
    values = [object.__getattribute__(action, name) for name in ("action_id", "effect", "destination")]
    if type(values[1]) is ActionEffect:
        values[1] = values[1].value
    # Evaluate the complete raw tuple in one gate: REFUSE takes priority over
    # NO_MATCH, and structural limits apply to the complete field collection.
    result = qualify_question(values)
    return QuestionResult(result.matchable, normalize_json_key(result.value) if result.matchable else None)


def stored_action_view(action: Action) -> list[Any]:
    if type(action) is not Action or type(action.effect) is not ActionEffect:
        raise ValueError("eligibility projection requires a decoded Action")
    return normalize_json_key([action.action_id, action.effect.value, action.destination])


def _scope(key_id: str, clock_domain: str) -> None:
    if type(key_id) is not str or not key_id or type(clock_domain) is not str:
        raise QuestionRefused("invalid recorder eligibility scope")


def decision_question(record_hash: Any, *, key_id: str, clock_domain: str) -> QuestionResult:
    _scope(key_id, clock_domain)
    result = qualify_question([record_hash, key_id, clock_domain])
    return QuestionResult(result.matchable, normalize_json_key(result.value) if result.matchable else None)


def outcome_question(record_hash: Any, assertion_id: Any, action: Any, *,
                     key_id: str, clock_domain: str) -> QuestionResult:
    _scope(key_id, clock_domain)
    # A type-based action NO_MATCH must not hide an unsupported other field.
    action_result = qualify_action_question(action)
    fields = qualify_question([record_hash, assertion_id, key_id, clock_domain])
    if not action_result.matchable or not fields.matchable:
        return QuestionResult(False)
    # Requalify the complete question to enforce aggregate structural bounds.
    result = qualify_question([fields.value[0], fields.value[1], action_result.value, key_id, clock_domain])
    return QuestionResult(True, normalize_json_key(result.value))


def stored_eligibility_pairs(envelope: Any) -> list[tuple[str, list[Any]]]:
    """Project a verified decoded envelope; no signature or time is cached here."""
    record = envelope.record
    scope = [envelope.signature.key_id, envelope.clock_domain]
    pairs = [(DECISION_ELIGIBLE, [envelope.record_hash, *scope])]
    named = [a.message for a in record.decision.annotations if a.kind == "outcome-of-decision"]
    if len(named) == 1 and record.decision.reason_codes[:1] in (("OUTCOME_COMMITTED",), ("RECONCILED_COMMITTED",)):
        pairs.append((OUTCOME_ELIGIBLE, [named[0], record.assertion_id, stored_action_view(record.action), *scope]))
    return pairs
