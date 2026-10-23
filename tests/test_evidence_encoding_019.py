"""Encoding bounds and trusted-object behavior under builtin dispatch."""
from collections import UserDict, UserList
from dataclasses import dataclass
from enum import Enum, IntEnum
from types import MappingProxyType
import pytest
from regulated_core.evidence_encoding import (
    TEN_D, RepresentationError, canonical_bytes, check_depth, check_numeric_domain,
)

@dataclass
class Box:
    value: object

class Number(IntEnum):
    ONE = 1

class Text(str, Enum):
    A = "a"

class Integer(int):
    def __lt__(self, other):raise AssertionError("comparison hook")
    def __gt__(self, other):raise AssertionError("comparison hook")
    def __int__(self):raise AssertionError("conversion hook")

@pytest.mark.parametrize("wrap", [lambda x:x, lambda x:{"k":x}, lambda x:[x],
    lambda x:(x,), lambda x:{x}, lambda x:frozenset({x}), Box, Integer])
@pytest.mark.parametrize("value", [TEN_D, -TEN_D, 1<<20000, -(1<<20000)], ids=["positive-bound", "negative-bound", "huge-positive", "huge-negative"])
def test_large_integer_guard_in_all_existing_traversals(wrap, value):
    with pytest.raises(RepresentationError):check_numeric_domain(wrap(value))

@pytest.mark.parametrize("value", [TEN_D-1, -TEN_D+1, True, False, 0, Integer(7)], ids=["positive-edge", "negative-edge", "true", "false", "zero", "subclass"])
def test_integer_boundary_and_subclass_hooks(value):
    check_numeric_domain(value)

@pytest.mark.parametrize("wrap", [lambda x:[x], Box, lambda x:UserList([x]), lambda x:UserDict(k=x),
    lambda x:MappingProxyType({"k":x})])
def test_depth_limit_and_shared_children(wrap):
    value=0
    for _ in range(64):value=wrap(value)
    check_depth(value)
    with pytest.raises(RepresentationError):check_depth(wrap(value))
    leaf=wrap(0)
    check_depth([leaf,leaf])

def test_cycle_through_dataclass_and_list_is_refused():
    value=[];box=Box(value);value.append(box)
    with pytest.raises(RepresentationError):check_depth(box)

@pytest.mark.parametrize("behavior", [True,False,"raise"])
def test_foreign_metaclass_equality_is_not_called(behavior):
    calls=[]
    class Meta(type):
        def __eq__(cls,other):
            calls.append(other)
            if behavior=="raise":raise AssertionError("equality hook")
            return behavior
        __hash__=type.__hash__
    class Foreign(metaclass=Meta):pass
    check_depth(Foreign());check_numeric_domain(Foreign())
    assert not calls

def test_typed_envelope_bytes_and_custom_container_precedence():
    @dataclass
    class Model(list):
        label:str="model"
    assert canonical_bytes(Box([Text.A,Number.ONE,b"ab",None,True]))==b'{"value":["a",1,"6162",null,true]}'
    assert canonical_bytes(Model())==b'{"label":"model"}'
    assert canonical_bytes(MappingProxyType({"k":7}))==b'{"k":7}'
