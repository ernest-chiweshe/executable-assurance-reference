"""Bounded scalar snapshots preserve bytes, errors and caller mutation visibility."""
from dataclasses import dataclass
import pytest
from regulated_core import evidence_encoding as e

@pytest.fixture(autouse=True)
def clear_memo():
    e._flat_document_bytes.cache_clear()
    yield
    e._flat_document_bytes.cache_clear()

@pytest.mark.parametrize("value", [
    {}, {"key": "\u03bb\n\"\U0001f600"}, {"n": 1}, {"n": True},
    {"n": None}, {"n": -(2**127)}, {"n": 2**128},
    {"key": "x"*2049}, {"nested": [1, {"x": False}]},
    {str(i): i for i in range(17)},
])
def test_differential_bytes(value):
    expected = e._canonical_bytes_uncached(value)
    assert e.canonical_bytes(value) == expected
    assert e.canonical_bytes(value) == expected

@pytest.mark.parametrize("value", [{"x": 1.5}, {1: "bad"}, {"x": 10**4301}])
def test_error_type_and_message_preserved(value):
    with pytest.raises(Exception) as original:
        e._canonical_bytes_uncached(value)
    with pytest.raises(type(original.value)) as candidate:
        e.canonical_bytes(value)
    assert str(candidate.value) == str(original.value)

def test_boolean_and_integer_snapshots_do_not_alias():
    assert e.canonical_bytes({"n": True}) == b'{"n":true}'
    assert e.canonical_bytes({"n": 1}) == b'{"n":1}'
    assert e.canonical_bytes({"n": False}) == b'{"n":false}'
    assert e.canonical_bytes({"n": 0}) == b'{"n":0}'

def test_mutation_and_independent_dictionaries():
    value = {"n": 1}
    assert e.canonical_bytes(value) == b'{"n":1}'
    assert e.canonical_bytes(dict(value)) == b'{"n":1}'
    assert e._flat_document_bytes.cache_info().hits == 1
    value["n"] = 2
    assert e.canonical_bytes(value) == b'{"n":2}'
    value["n"] = [3]
    assert e.canonical_bytes(value) == b'{"n":[3]}'
    value["n"].append(4)
    assert e.canonical_bytes(value) == b'{"n":[3,4]}'

def test_nested_dataclass_and_subclasses_use_original_path():
    class CustomInt(int): pass
    @dataclass(frozen=True)
    class Wrapper:
        value: list
    for value in ({"n": CustomInt(1)}, {"nested": {}}, Wrapper([1])):
        assert e.canonical_bytes(value) == e._canonical_bytes_uncached(value)
    assert e._flat_document_bytes.cache_info().currsize == 0

def test_cache_bound_and_eviction():
    for i in range(300):
        assert e.canonical_bytes({"n": i}) == e._canonical_bytes_uncached({"n": i})
    assert e._flat_document_bytes.cache_info().currsize == 256
    assert e.canonical_bytes({"n": 0}) == b'{"n":0}'
