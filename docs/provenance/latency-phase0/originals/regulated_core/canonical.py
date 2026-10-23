"""Canonical serialization: one meaning, one byte-string, one digest.

Everything signed, hashed, or chained passes through here so a claim produces the same bytes
on every host. Floats are refused (no stable cross-runtime spelling); scores and money are
carried as fixed decimal strings, time as integer microseconds. Dataclasses, enums, bytes and
sets are normalized deterministically.

Merged-core note: the substrate (source review) and the graft (integration review) both had a correct canonical
form; this keeps the more general one (handles dataclasses/enums/sets) and the stricter float
ban, and standardizes time on integer microseconds to keep the signed surface small.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _normalize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are forbidden in signed evidence; use decimal strings or int micros")
    if isinstance(value, datetime):  # defensive: prefer int micros, but never sign a naive tz
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("datetime must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (str, int)):
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise CanonicalizationError("canonical mappings require string keys")
        return {k: _normalize(value[k]) for k in sorted(value)}
    if isinstance(value, (set, frozenset)):
        return sorted((_normalize(v) for v in value), key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(v) for v in value]
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest_hex(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()
