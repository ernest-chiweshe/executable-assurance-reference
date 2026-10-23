"""Exact-domain question qualification; no caller or permit activation.

The gate's deliberate refusals are specified in SPEC-EVIDENCE-SERVICE-027/028.
NO_MATCH is a type-based result, never an authenticated map absence. Stored
normalization has no question-size limits and never changes signed bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import math
from .evidence_encoding import (integer_admitted, MAX_QUESTION_BYTES, D_MAX,
                                string_size, RepresentationError)
from typing import Any


class QuestionRefused(ValueError):
    """Unsupported or excessive question; must never be converted to absence."""


@dataclass(frozen=True)
class QuestionResult:
    matchable: bool
    value: Any = None


_NO_JSON_MATCH = (tuple, bytes, bytearray, set, frozenset)
# Explicit identities, never a spoofable __module__ == "builtins" check.
_BUILTIN_NONSTRING_KEYS = (int, bool, type(None), float, tuple, bytes, frozenset,
                          complex, range, object, type, memoryview, type(Ellipsis), type(NotImplemented))


def _walk(value: Any, *, question: bool) -> QuestionResult:
    # Explicit enter/exit stack keeps shared acyclic children distinct from cycles.
    output = [None]
    stack = [(False, value, output, 0, 0)]
    active: set[int] = set()
    visited = 0
    no_match = False
    encoded_size = 0

    def charge(amount):
        nonlocal encoded_size
        if question:
            encoded_size += amount
            if encoded_size > MAX_QUESTION_BYTES:
                raise QuestionRefused("question encoding exceeds 64 KiB")

    def scalar(item):
        if not question:
            return
        if type(item) is str:
            try:
                charge(string_size(item, MAX_QUESTION_BYTES - encoded_size))
            except RepresentationError as exc:
                raise QuestionRefused(str(exc)) from exc
        elif type(item) is int:
            if not integer_admitted(item):
                raise QuestionRefused("question integer exceeds admitted domain")
            try:
                charge(len(str(item)))
            except ValueError as exc:
                raise QuestionRefused("integer encoding unavailable") from exc
        elif type(item) is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
    while stack:
        exiting, current, parent, slot, depth = stack.pop()
        if exiting:
            active.remove(current)
            continue
        visited += 1
        if question and (visited > 10_000 or depth > 64):
            raise QuestionRefused("question exceeds structural limits")
        kind = type(current)
        if current is None or kind is str or kind is int:
            scalar(current)
            parent[slot] = current
        elif kind is bool:
            scalar(current)
            parent[slot] = current if question else int(current)
        elif kind is list or kind is dict or (question and kind is tuple):
            identity = id(current)
            if identity in active:
                raise QuestionRefused("cyclic value is outside the JSON domain")
            active.add(identity)
            stack.append((True, identity, None, None, 0))
            if kind is list or kind is tuple:
                if kind is tuple:
                    no_match = True
                count = list.__len__(current) if kind is list else tuple.__len__(current)
                if question and count > 10_000 - visited:
                    raise QuestionRefused("question exceeds element limit")
                charge(2 + max(0, count - 1))
                target = [None] * count
                parent[slot] = target
                for index in range(count - 1, -1, -1):
                    child = (list.__getitem__(current, index) if kind is list
                             else tuple.__getitem__(current, index))
                    stack.append((False, child, target, index, depth + 1))
            else:
                count = dict.__len__(current)
                # Dictionary keys count as elements as well as their values.
                if question and count * 2 > 10_000 - visited:
                    raise QuestionRefused("question exceeds element limit")
                charge(2 + max(0, count - 1) + count)
                visited += count
                target = {}
                parent[slot] = target
                # items reads existing entries without calling a foreign key's hash.
                for key, item in dict.items(current):
                    if type(key) is str:
                        scalar(key)
                        target[key] = None
                        stack.append((False, item, target, key, depth + 1))
                    elif question and any(type(key) is safe for safe in _BUILTIN_NONSTRING_KEYS):
                        no_match = True
                        # Still inspect values: REFUSE takes priority over NO_MATCH.
                        stack.append((False, item, [None], 0, depth + 1))
                    else:
                        raise QuestionRefused("unsupported dictionary key type")
        elif question and kind is float:
            if math.isfinite(current) and float.is_integer(current):
                converted = float.__int__(current)
                scalar(converted)
                parent[slot] = converted
            else:
                no_match = True
        elif question and kind is Fraction:
            if current.denominator == 1:
                if not integer_admitted(current.numerator):
                    raise QuestionRefused("question integer exceeds admitted domain")
                converted = Fraction.__int__(current)
                scalar(converted)
                parent[slot] = converted
            else:
                no_match = True
        elif question and kind is Decimal:
            if Decimal.is_snan(current):
                raise QuestionRefused("signaling NaN is not a supported question")
            if not Decimal.is_finite(current):
                no_match = True
            elif Decimal.is_zero(current):
                scalar(0)
                parent[slot] = 0
            elif Decimal.adjusted(current) >= D_MAX:
                raise QuestionRefused("question Decimal exceeds admitted domain")
            elif current == Decimal.to_integral_value(current):
                converted = Decimal.__int__(current)
                scalar(converted)
                parent[slot] = converted
            else:
                no_match = True
        elif question and any(kind is safe for safe in _NO_JSON_MATCH):
            no_match = True
        else:
            # No foreign conversion, iteration or equality hook is invoked.
            raise QuestionRefused("unsupported value type")
    return QuestionResult(not no_match, None if no_match else output[0])


def qualify_question(value: Any) -> QuestionResult:
    """Classify a finite caller question without consulting any stored evidence."""
    return _walk(value, question=True)


def normalize_json_key(value: Any) -> Any:
    """Equality normal form for decoded JSON only, preserving all string bytes.

    This is index material, not a mutation of the envelope. Booleans share their
    integer key because Python equality treats True == 1 and False == 0.
    """
    return _walk(value, question=False).value
