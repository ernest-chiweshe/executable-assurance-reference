"""Byte compatibility for the serialization hot path; no performance thresholds."""

from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from types import MappingProxyType

import pytest

from regulated_core.canonical import CanonicalizationError, canonical_bytes


class Text(str, Enum):
    VALUE = "text"


class Number(IntEnum):
    VALUE = 7


@dataclass
class Box:
    value: object


@dataclass
class ListModel(list):
    label: str = "dataclass-precedes-sequence"


Pair = namedtuple("Pair", "left right")


@pytest.mark.parametrize(("value", "expected"), [
    ({"z": [None, True, False, 2**64], "a": ("é", b"\x00\xff")},
     b'{"a":["\\u00e9","00ff"],"z":[null,true,false,18446744073709551616]}'),
    (Box((Text.VALUE, Number.VALUE, frozenset({"z", "a"}))),
     b'{"value":["text",7,["a","z"]]}'),
    (ListModel(), b'{"label":"dataclass-precedes-sequence"}'),
    (Box(Pair(1, Box("x"))), b'{"value":[1,{"value":"x"}]}'),
    (MappingProxyType({"z": 1, "a": 2}), b'{"a":2,"z":1}'),
    (datetime(2026, 10, 18, 2, 0, 0, 4, timezone(timedelta(hours=2))),
     b'"2026-10-18T00:00:00.000004Z"'),
])
def test_canonical_byte_contract(value, expected):
    assert canonical_bytes(value) == expected


@pytest.mark.parametrize("value", [1.5, {"nested": [1.5]}, {1: "bad"},
                                  Box({1: "bad"}), datetime(2026, 1, 1), bytearray(b"x")])
def test_unsupported_signed_values_remain_refused(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_dataclass_copy_contract_is_not_broadened():
    # Direct mapping proxies are supported; dataclasses.asdict cannot copy one.
    # The optimization must not silently broaden the accepted signed domain.
    with pytest.raises(TypeError):
        canonical_bytes(Box(MappingProxyType({"x": 1})))


def test_repeated_serialization_observes_current_container_values():
    payload = {"a": [1]}
    assert canonical_bytes(payload) == b'{"a":[1]}'
    payload["a"].append(2)
    assert canonical_bytes(payload) == b'{"a":[1,2]}'


def test_seeded_nested_values_keep_the_preoptimization_fingerprint():
    from hashlib import sha256
    import random

    rng = random.Random(10818)

    def tree(depth):
        if depth == 0:
            return rng.choice([None, True, False, -20, 1000000, "a", "é", b"bytes"])
        kind = rng.randrange(5)
        if kind == 0:
            return Box(tree(depth - 1))
        if kind == 1:
            return {str(i): tree(depth - 1) for i in range(rng.randrange(5))}
        if kind == 2:
            return tuple(tree(depth - 1) for _ in range(rng.randrange(5)))
        if kind == 3:
            return [tree(depth - 1) for _ in range(rng.randrange(5))]
        return tree(0)

    digest = sha256()
    for _ in range(1000):
        digest.update(canonical_bytes(tree(4)) + b"\n")
    # Captured with the preserved pre-optimization serializer, not this one.
    assert digest.hexdigest() == "4edf19c090b1cdedbd5f1e94a9ebaee4c81b6300bc70842a17d64c55a3c968d9"


def test_historical_signed_envelope_and_retention_bytes_are_preserved():
    from hashlib import sha256
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from regulated_core import (
        Action, ActionEffect, Actor, Assertion, Decision, Ed25519Signer,
        PolicyContext, PolicyRef, TrustDirectory,
    )
    from regulated_core.evidence import DecisionRecorder
    from regulated_core.worm import LocalWormStore, anchor_evidence_chain

    # Public deterministic fixture key, never a deployment credential.
    signer = Ed25519Signer("fixture:latency", Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
    trust = TrustDirectory()
    trust.register_signer(signer)
    recorder = DecisionRecorder(signer, trust)
    tenant = "synthetic-latency"
    for i in range(100):
        recorder.record(
            Assertion("fixture", tenant, "course:lesson", "a" * 64),
            Action("course:review", ActionEffect.REVERSIBLE),
            PolicyContext(tenant, Actor("reviewer", tenant, frozenset()), "review", str(i), i),
            PolicyRef("course", "fixture", "1"),
            Decision.deny("PENDING", "Synthetic retained record"),
        )
    store = LocalWormStore()
    receipt = anchor_evidence_chain(store, recorder, tenant, retain_us=1000, now_us=100)
    # Captured with pre-optimization canonical.py (SHA256 7fc6f90a...e8993b).
    assert sha256(canonical_bytes(recorder.entries(tenant))).hexdigest() == (
        "5b36efb53caf6a0e7054eb34c461c439f9aaf64f7285e28dbbb9f033626a67e9")
    assert receipt.content_digest == "d801244536a32b4ac9e56ed4d821bd491137cd0ab4f19c60dc17a02f787372de"
    assert recorder.verify_chain(tenant)
    assert store.verify(receipt)
