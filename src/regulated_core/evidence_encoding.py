"""Evidence-only representation limits; original signed bytes are never rewritten.

The JSON pre-scan is linear in input bytes and uses constant nesting state.
Transport callers must apply their own byte limits before reading a document.
"""
from __future__ import annotations

import json
from functools import lru_cache
from dataclasses import fields, is_dataclass
from enum import Enum

from .canonical import _normalize

D_MAX = 4300
TEN_D = 10 ** D_MAX
MAX_JSON_DEPTH = 64
MAX_QUESTION_BYTES = 65536


class RepresentationError(ValueError):
    pass


def integer_admitted(value: int) -> bool:
    # The screen avoids constructing abs() of an already enormous negative int.
    return (int.bit_length(value) <= 14286
            and int.__gt__(value, -TEN_D) and int.__lt__(value, TEN_D))


def check_numeric_domain(value) -> None:
    stack = [value]
    seen = set()
    while stack:
        item = stack.pop()
        kind = type(item)
        # Exact builtin leaves cannot contain integers or custom accessors.
        # Identity checks avoid invoking a foreign metaclass equality hook.
        if item is None or kind is str or kind is bytes or kind is bytearray or kind is float:
            continue
        if kind is int or kind is bool:
            numeric = True
        elif kind is dict or kind is list or kind is tuple or kind is set or kind is frozenset:
            numeric = False
        else:
            # Preserve builtin descriptor handling for integer subclasses and
            # the established Enum/dataclass fallback for all other objects.
            try:
                int.bit_length(item)
            except TypeError:
                numeric = False
            else:
                numeric = True
        if numeric:
            if not integer_admitted(item):
                raise RepresentationError("integer exceeds admitted evidence domain")
        elif kind is dict or kind is list or kind is tuple or kind is set or kind is frozenset:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            if kind is dict:
                stack.extend(dict.keys(item))
                stack.extend(dict.values(item))
            else:
                stack.extend(item)
        elif isinstance(item, Enum):
            stack.append(item.value)
        elif is_dataclass(item) and not isinstance(item, type):
            identity = id(item)
            if identity not in seen:
                seen.add(identity)
                stack.extend(getattr(item, f.name) for f in fields(item))


def _canonical_bytes_uncached(value) -> bytes:
    try:
        # Check typed envelopes before normalization can format set-sort keys.
        check_depth(value)
        check_numeric_domain(value)
        normalized = _normalize(value)
        check_numeric_domain(normalized)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (RecursionError, ValueError) as exc:
        raise RepresentationError("invalid evidence canonical representation") from exc


@lru_cache(maxsize=256)
def _flat_document_bytes(items: tuple) -> bytes:
    # Exact builtin snapshots only. First use runs every original representation
    # check; subsequent identical snapshots reuse only the resulting bytes.
    return _canonical_bytes_uncached({key: value for key, kind, value in items})


def canonical_bytes(value) -> bytes:
    # Generated heads, key digests, summaries and occurrences are small flat
    # documents. Never memoize object identity or mutable/nested field values.
    if type(value) is dict and len(value) <= 16:
        items = []
        remaining = 2048
        for key, item in value.items():
            kind = type(item)
            if type(key) is not str:
                break
            remaining -= len(key)
            if kind is str:
                remaining -= len(item)
                tag = "str"
            elif kind is int and item.bit_length() <= 128:
                tag = "int"
            elif kind is bool:
                tag = "bool"
            elif item is None:
                tag = "null"
            else:
                break
            if remaining < 0:
                break
            items.append((key, tag, item))
        else:
            return _flat_document_bytes(tuple(items))
    return _canonical_bytes_uncached(value)


def loads(raw, **kwargs):
    if type(raw) is bytes or type(raw) is bytearray:
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise RepresentationError("evidence JSON must be UTF-8") from exc
    elif type(raw) is str:
        text = raw
    else:
        raise RepresentationError("invalid evidence JSON input type")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character == "[" or character == "{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise RepresentationError("evidence JSON nesting exceeds 64 levels")
        elif character == "]" or character == "}":
            depth -= 1
    try:
        value = json.loads(text, **kwargs)
        check_numeric_domain(value)
        return value
    except (RecursionError, ValueError) as exc:
        raise RepresentationError("invalid evidence JSON representation") from exc


def string_size(value: str, remaining: int) -> int:
    """Count ensure_ascii JSON bytes, stopping before exceeding the budget."""
    size = 2
    for character in value:
        code = ord(character)
        if character in ('"', "\\", "\b", "\f", "\n", "\r", "\t"):
            size += 2
        elif code < 32 or 127 <= code <= 65535:
            size += 6
        elif code > 65535:
            size += 12
        else:
            size += 1
        if size > remaining:
            raise RepresentationError("question encoding exceeds 64 KiB")
    return size


def reject_nul(value):
    """Linear traversal of the admitted JSON body; never a constant-work claim."""
    stack=[value]
    while stack:
        item=stack.pop()
        if type(item) is str:
            if "\x00" in item:raise RepresentationError("NUL is not representable in JSONB")
        elif type(item) is dict:
            stack.extend(item.keys());stack.extend(item.values())
        elif type(item) is list:stack.extend(item)


def check_depth(value):
    """Check container depth before recursive trusted canonical normalization.

    Linear in the supplied object graph. Typed signing objects retain their
    established accessors; this is not an untrusted-object/no-hook guarantee.
    """
    from collections.abc import Mapping, Sequence
    active=set();stack=[(value,0,False)]
    while stack:
        item,depth,leave=stack.pop()
        if leave:active.remove(id(item));continue
        kind=type(item)
        # Exact scalar builtins have no children. Subclasses and custom objects
        # still use the original Enum/dataclass/Mapping/Sequence accessors.
        if item is None or kind is str or kind is bytes or kind is bytearray or kind is float or kind is int or kind is bool:
            continue
        children=None
        if kind is dict:children=list(item.values())
        elif kind is list or kind is tuple or kind is set or kind is frozenset:children=list(item)
        elif isinstance(item,Enum):children=[item.value]
        elif is_dataclass(item) and not isinstance(item,type):children=[getattr(item,f.name) for f in fields(item)]
        elif isinstance(item,Mapping):children=list(item.values())
        elif isinstance(item,Sequence) and not isinstance(item,(str,bytes,bytearray)):children=list(item)
        if children is not None:
            if depth>=MAX_JSON_DEPTH or id(item) in active:raise RepresentationError("evidence nesting exceeds64 or cycles")
            active.add(id(item));stack.append((item,depth,True));stack.extend((child,depth+1,False) for child in reversed(children))


MAX_ENVELOPE_BYTES = 1048576

def envelope_bytes(value):
    """Admit at most1MiB canonical envelope bytes; encoding remains linear.

    This is a stored/retained object limit, not a pre-allocation memory bound.
    Network transports enforce byte caps before decoding separately.
    """
    raw=canonical_bytes(value)
    if len(raw)>MAX_ENVELOPE_BYTES:raise RepresentationError("evidence envelope exceeds1MiB")
    return raw
