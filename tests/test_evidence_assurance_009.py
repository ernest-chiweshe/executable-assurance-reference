"""Defensive regressions for reviewed CORE009 corrections; no guard-removal tests."""
import ast
import json
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from time import perf_counter

import pytest

from regulated_core.canonical import canonical_bytes as legacy_bytes
from regulated_core.evidence_encoding import (
    TEN_D, RepresentationError, canonical_bytes, loads, string_size,
)
from regulated_core.evidence_questions import qualify_question, QuestionRefused
from regulated_core.evidence_namespace import state_key, StateValue, Transition
from regulated_core.evidence_service import EvidenceError, KeySummary, UnhashableIdFlag, verify_head
from regulated_core.merkle import verify_inclusion, EMPTY_ROOT
from assurance_reference.protected_head import FileProtectedHeadStore
from test_evidence_service_formats import case
from test_evidence_service_memory import memory


@pytest.mark.parametrize("behavior", ["true", "false", "raise"])
@pytest.mark.parametrize("position", ["value", "key", "nested", "proof", "namespace"])
def test_foreign_metaclass_equality_never_runs(behavior, position):
    calls = []
    class Meta(type):
        def __eq__(cls, other):
            calls.append(other)
            if behavior == "raise":
                raise AssertionError("foreign hook invoked")
            return behavior == "true"
        __hash__ = type.__hash__
    class Foreign(metaclass=Meta):
        pass
    value = Foreign()
    if position == "proof":
        assert not verify_inclusion(b"x", 0, 1, value, EMPTY_ROOT)
    elif position == "namespace":
        with pytest.raises(EvidenceError):
            state_key("tenant", "t", "budget", "k", value)
    else:
        question = value if position == "value" else {value: 1} if position == "key" else [1.5, value]
        with pytest.raises(QuestionRefused):
            qualify_question(question)
    assert calls == []


@pytest.mark.parametrize("literal", ["0E+4300", "-0E+4300", "0E-10"])
def test_decimal_zero_precedes_magnitude_limit(literal):
    result = qualify_question(Decimal(literal))
    assert result.matchable and result.value == 0


@pytest.mark.parametrize("factory", [int, Decimal, Fraction])
def test_exact_numeric_boundary(factory):
    # Decimal(int) does not format decimal text or alter interpreter guards.
    assert qualify_question(factory(TEN_D - 1)).value == TEN_D - 1
    for value in (TEN_D, -TEN_D):
        with pytest.raises(QuestionRefused):
            qualify_question(factory(value))
    for value in ([1.5, factory(TEN_D)], [factory(TEN_D), 1.5]):
        with pytest.raises(QuestionRefused):
            qualify_question(value)


def test_compact_decimal_extreme_exponent_is_refused_before_expansion():
    q = Decimal("1e2000000000")
    start = perf_counter()
    with pytest.raises(QuestionRefused):
        qualify_question(q)
    assert perf_counter() - start < 0.01


@pytest.mark.parametrize("text", ['abc', '"\\\n\t', "\u0000", "\u007f", "\u0080", "\u2603", "\U0001f642", "\ud800"])
def test_question_string_byte_count_matches_signed_encoding(text):
    assert string_size(text, 65536) == len(legacy_bytes(text))
    assert canonical_bytes({"k": text}) == legacy_bytes({"k": text})


def test_question_size_limit_includes_keys_structure_and_escaping():
    assert qualify_question("x" * 65534).matchable
    assert qualify_question({"x" * 65530: 0}).matchable
    for value in ("x" * 65535, {"x" * 65531: 0}, "\u2603" * 10923):
        with pytest.raises(QuestionRefused):
            qualify_question(value)


@pytest.mark.parametrize("current", [False, True])
def test_deep_publication_latches_and_stays_latched_after_repair(tmp_path, case, current):
    args = dict(tenant="tenant", clock_domain=case[0].domain, trust=case[3],
                existing_heads={}, advancing_heads=case[4])
    store = FileProtectedHeadStore(tmp_path, **args)
    store.directory.mkdir(parents=True)
    raw = b"[" * 2048 + b"0" + b"]" * 2048
    path = store.directory / "00000000000000000001.json"
    path.write_bytes(raw)
    if current:
        (store.directory / "CURRENT").write_bytes(legacy_bytes({"counter": 1, "hash": sha256(raw).hexdigest()}))
    with pytest.raises(EvidenceError):
        store.read()
    assert (store.directory / "LATCH").exists()
    path.write_bytes(b"{}")
    with pytest.raises(EvidenceError, match="latched"):
        FileProtectedHeadStore(tmp_path, **args).read()


def test_json_prescan_counts_only_unquoted_brackets_and_limits_nesting():
    value = {"\\\"[": "[[[}}}\\\""}
    assert loads(legacy_bytes(value)) == value
    assert loads(b"[" * 64 + b"0" + b"]" * 64)
    with pytest.raises(RepresentationError):
        loads(b"[" * 65 + b"0" + b"]" * 65)


@pytest.mark.parametrize("decoder", [lambda raw: KeySummary.decode(raw, 1),
    lambda raw: UnhashableIdFlag.decode(raw, 1), StateValue.from_bytes, Transition.from_bytes])
def test_public_decoders_classify_deep_bytes_as_representation_error(decoder):
    with pytest.raises(EvidenceError):
        decoder(b"[" * 65 + b"0" + b"]" * 65)


def test_memory_append_checks_numeric_domain_before_signatures_and_leaves_state(memory, case):
    service = memory[0]
    bad_record = replace(case[7][0].record, record_id=TEN_D)
    bad = replace(case[7][0], record=bad_record)
    with pytest.raises(EvidenceError):
        service.append(bad)
    assert service.head is None and service._envelopes == {}


def test_retired_head_at_cutoff_verifies_beyond_cutoff_fails(case):
    clock, signer, other, trust, keys, _, heads, _ = case
    args = dict(tenant="tenant", clock_domain=clock.domain, trust=trust,
                allowed_keys=frozenset({other.key_id}),
                historical_keys={signer.key_id: {"retired_after_size": 1}})
    assert verify_head(heads[0], **args)
    assert not verify_head(heads[1], **args)


def test_retired_current_head_can_be_read_but_cannot_advance(tmp_path, case):
    clock, signer, other, trust, keys, tree, heads, _ = case
    original = FileProtectedHeadStore(tmp_path, tenant="tenant", clock_domain=clock.domain,
                                      trust=trust, existing_heads={}, advancing_heads=keys)
    original.advance(None, heads[0], ())
    rotated = FileProtectedHeadStore(tmp_path, tenant="tenant", clock_domain=clock.domain,
        trust=trust, existing_heads={signer.key_id: {"retired_after_size": 1}},
        advancing_heads=frozenset({other.key_id}))
    assert rotated.read() == heads[0]
    with pytest.raises(EvidenceError):
        rotated.advance(heads[0], heads[1], tree.consistency(1, 2))
    assert rotated.read() == heads[0]


def test_retired_beyond_cutoff_rollforward_latches(tmp_path, case):
    clock, signer, other, trust, keys, tree, heads, _ = case
    original = FileProtectedHeadStore(tmp_path, tenant="tenant", clock_domain=clock.domain,
                                      trust=trust, existing_heads={}, advancing_heads=keys)
    original.advance(None, heads[0], ())
    pointer = (original.directory / "CURRENT").read_bytes()
    original.advance(heads[0], heads[1], tree.consistency(1, 2))
    (original.directory / "CURRENT").write_bytes(pointer)
    rotated = FileProtectedHeadStore(tmp_path, tenant="tenant", clock_domain=clock.domain,
        trust=trust, existing_heads={signer.key_id: {"retired_after_size": 1}},
        advancing_heads=frozenset({other.key_id}))
    with pytest.raises(EvidenceError):
        rotated.read()
    assert (rotated.directory / "LATCH").exists()


def test_no_equality_type_membership_in_core_boundaries():
    root = Path(__file__).parents[1] / "src"
    paths = list((root / "regulated_core").glob("evidence*.py"))
    paths += [root / "regulated_core/merkle.py", root / "assurance_reference/protected_head.py"]
    violations = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        type_names = {node.targets[0].id for node in ast.walk(tree)
                      if isinstance(node, ast.Assign) and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name)
                      and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                      and node.value.func.id == "type"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for left, op, right in zip([node.left] + node.comparators, node.ops, node.comparators):
                operands = (left, right)
                typed = any((isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "type")
                            or (isinstance(v, ast.Name) and v.id in type_names) for v in operands)
                if typed and isinstance(op, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)):
                    violations.append((path.name, node.lineno))
    assert violations == []


def test_actual_signed_envelope_bytes_remain_identical(case):
    for envelope in case[7]:
        assert canonical_bytes(envelope) == legacy_bytes(envelope)
    for head in case[6]:
        assert canonical_bytes(head.document()) == legacy_bytes(head.document())


def test_protected_head_latches_decoder_recursion_failure(tmp_path, case, monkeypatch):
    import regulated_core.evidence_encoding as encoding
    store = FileProtectedHeadStore(tmp_path, tenant="tenant", clock_domain=case[0].domain,
        trust=case[3], existing_heads={}, advancing_heads=case[4])
    store.advance(None, case[6][0], ())
    def decoder_failure(*args, **kwargs):
        raise RecursionError("defensive decoder failure fixture")
    monkeypatch.setattr(encoding.json, "loads", decoder_failure)
    with pytest.raises(EvidenceError):
        store.read()
    assert (store.directory / "LATCH").exists()


def test_rotated_signer_extends_retired_head_only_within_cutoff(case):
    from regulated_core.evidence_service import sign_head
    clock, signer, other, trust, keys, tree, heads, envelopes = case
    args = dict(tenant="tenant", tree_size=2, tree_root=bytes.fromhex(heads[1].tree_root),
                map_root=bytes.fromhex(heads[1].map_root), last_entry_hash=envelopes[1].chain_hash(),
                previous=heads[0], signer=other, clock=clock, trust=trust,
                signing_keys=frozenset({other.key_id}),
                historical_keys={signer.key_id: {"retired_after_size": 1}})
    rotated = sign_head(**args)
    assert rotated.key_id == other.key_id
    args["historical_keys"] = {signer.key_id: {"retired_after_size": 0}}
    with pytest.raises(EvidenceError):
        sign_head(**args)


def test_namespace_retirement_cutoff_uses_version():
    from test_evidence_namespace_core import namespace_case
    from regulated_core.evidence_namespace import verify_namespace_head
    from regulated_core.signing import Ed25519Signer
    clock, signer, trust, args, _, empty, head, *_ = namespace_case()
    current = Ed25519Signer("fixture:new-namespace-key")
    trust.register_signer(current)
    args["allowed_keys"] = frozenset({current.key_id})
    args["historical_keys"] = {signer.key_id: {"retired_after_size": 0}}
    assert verify_namespace_head(empty, **args)
    assert not verify_namespace_head(head, **args)


def test_stored_numeric_guard_covers_integer_subclasses_without_comparison_hooks():
    class LegacyInteger(int):
        def __lt__(self, other):
            raise AssertionError("comparison hook")
        def __gt__(self, other):
            raise AssertionError("comparison hook")
        def __int__(self):
            raise AssertionError("conversion hook")
    assert canonical_bytes({"value": LegacyInteger(7)}) == legacy_bytes({"value": 7})
    with pytest.raises(RepresentationError):
        canonical_bytes({"value": LegacyInteger(TEN_D)})
