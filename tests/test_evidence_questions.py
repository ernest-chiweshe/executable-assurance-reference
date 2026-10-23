"""Defensive question-domain checks; this module does not migrate callers."""
from decimal import Decimal
from fractions import Fraction
from itertools import product

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_questions import (
    QuestionRefused, normalize_json_key, qualify_question,
)


ATOMS = [None, False, True, -1, 0, 1, 7, "", "x", "7", "\0"]
CORPUS = (ATOMS + [list(p) for p in product(ATOMS, repeat=2)]
          + [{"k": v} for v in ATOMS] + [{"k": [v, True]} for v in ATOMS])


def test_json_equality_is_bidirectional_and_strings_keep_bytes():
    forms = [canonical_bytes(normalize_json_key(v)) for v in CORPUS]
    for i, left in enumerate(CORPUS):
        result = qualify_question(left)
        assert result.matchable and result.value == left
        for j, right in enumerate(CORPUS):
            assert (left == right) == (forms[i] == forms[j])
    for text in ["", "x", "\0", "a" * 64, "A" * 64, "\u2603"]:
        assert canonical_bytes(normalize_json_key(text)) == canonical_bytes(text)


@pytest.mark.parametrize("question", [7.0, -0.0, Decimal(7), Decimal("-0"), Fraction(7),
                                     [Decimal(1), {"k": Fraction(7)}]])
def test_numeric_equivalence_with_stored_json(question):
    result = qualify_question(question)
    assert result.matchable
    for stored in CORPUS:
        assert (stored == question) == (stored == result.value)


@pytest.mark.parametrize("question", [1.5, float("nan"), float("inf"), float("-inf"),
    Decimal("1.5"), Decimal("NaN"), Decimal("Infinity"), Fraction(1, 2),
    (), ("x",), b"x", bytearray(b"x"), set(), frozenset({1}),
    {7: "x"}, {None: "x"}, [1.5], {"k": [Decimal("0.5")]}])
def test_no_match_is_type_based_and_agrees_with_json(question):
    result = qualify_question(question)
    assert not result.matchable and result.value is None
    assert not any(stored == question for stored in CORPUS)


class HostileInt(int):
    def __int__(self):
        raise AssertionError("foreign conversion must not run")


class HostileList(list):
    def __iter__(self):
        raise AssertionError("foreign iteration must not run")


class HostileEquality:
    def __eq__(self, other):
        raise AssertionError("foreign equality must not run")


class StringSubclass(str):
    pass


@pytest.mark.parametrize("question", [HostileInt(7), HostileList([1]), HostileEquality(),
    StringSubclass("x"), {StringSubclass("x"): 1}, {"k": HostileEquality()},
    [1.5, HostileEquality()], [HostileEquality(), 1.5], Decimal("sNaN"), object()])
def test_explicit_refusals_never_invoke_foreign_hooks(question):
    with pytest.raises(QuestionRefused):
        qualify_question(question)


def test_cycles_refuse_but_shared_children_are_not_cycles():
    cyclic = []
    cyclic.append(cyclic)
    mapping = {}
    mapping["self"] = mapping
    for value in (cyclic, mapping):
        with pytest.raises(QuestionRefused, match="cyclic"):
            qualify_question(value)
    shared = [1, {"x": True}]
    assert qualify_question([shared, shared]).value == [shared, shared]


def test_depth_and_element_limits_are_explicit_refusals():
    value = 0
    for _ in range(64):
        value = [value]
    assert qualify_question(value).matchable
    with pytest.raises(QuestionRefused, match="structural"):
        qualify_question([value])
    assert qualify_question([0] * 9999).matchable  # root plus children = 10,000
    with pytest.raises(QuestionRefused, match="element"):
        qualify_question([0] * 10_000)
    with pytest.raises(QuestionRefused, match="element"):
        qualify_question({str(i): 0 for i in range(5000)})


def test_stored_normalization_has_no_question_limits_or_coercions():
    assert len(normalize_json_key([True] * 10_001)) == 10_001
    assert normalize_json_key({"a": [True, False, 1, "1"]}) == {"a": [1, 0, 1, "1"]}
    for value in (1.0, Decimal(1), (1,), b"1", HostileInt(1)):
        with pytest.raises(QuestionRefused):
            normalize_json_key(value)


def test_normalization_does_not_mutate_input():
    value = {"x": [True, {"y": False}]}
    before = canonical_bytes(value)
    assert normalize_json_key(value) == {"x": [1, {"y": 0}]}
    assert canonical_bytes(value) == before


@pytest.mark.parametrize("key", [7, True, None, 1.5, (), b"x", frozenset({1}),
    1j, range(2), object(), int, memoryview(b"x"), Ellipsis, NotImplemented])
def test_exact_builtin_nonstring_dict_keys_are_no_match(key):
    result = qualify_question({key: "value"})
    assert not result.matchable
    assert not any(stored == {key: "value"} for stored in CORPUS)


def test_tuple_containing_cycle_or_excessive_container_is_structurally_refused():
    child = []
    cyclic = (child,)
    child.append(cyclic)
    with pytest.raises(QuestionRefused, match="cyclic"):
        qualify_question(cyclic)
    with pytest.raises(QuestionRefused, match="element"):
        qualify_question(tuple(range(10_000)))
