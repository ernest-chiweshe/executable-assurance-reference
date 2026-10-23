"""Eligible point selection, raw question equality and counted proof work."""
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
from types import SimpleNamespace

import pytest

from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence import GENESIS, ClockedDecisionEnvelope, verify_envelope, DecisionRecorder
from regulated_core.evidence_eligibility import (
    DECISION_ELIGIBLE, OUTCOME_ELIGIBLE, qualify_action_question, stored_action_view,
    decision_question, outcome_question,
)
from regulated_core.evidence_questions import QuestionRefused
from regulated_core.evidence_service import (
    EvidenceError, MemoryEvidenceService, KeySummary, envelope_keys, occurrence_bytes,
    sign_head, lookup_key, verify_lookup,
)
from regulated_core.merkle import MemoryMerkleLog
from regulated_core.models import Action, ActionEffect, Annotation
from regulated_core.persistence_pg import decode_envelope
from regulated_core.projectos_gate import _RegulatedGateBase
from test_evidence_service_formats import case


class ForeignString(str):
    def __eq__(self, other):
        raise AssertionError("foreign equality called")


class ForeignAction(Action):
    def __eq__(self, other):
        raise AssertionError("foreign Action equality called")


@pytest.mark.parametrize("destination,matchable,equals", [
    ("78", True, True), (b"x", False, False), (("x",), False, False),
    (["x"], True, False), (None, True, False), (7, True, False),
])
def test_raw_action_destination_is_not_canonicalized_before_gate(destination, matchable, equals):
    stored = Action("sample", ActionEffect.REVERSIBLE, "78")
    query = Action("sample", ActionEffect.REVERSIBLE, destination)
    result = qualify_action_question(query)
    assert result.matchable is matchable
    assert (stored == query) is equals
    assert (result.matchable and result.value == stored_action_view(stored)) is equals


@pytest.mark.parametrize("effect", [ActionEffect.REVERSIBLE, "reversible", 1, None, Decimal(1)])
def test_effect_string_enum_and_other_exact_types(effect):
    stored = Action("sample", ActionEffect.REVERSIBLE)
    query = Action("sample", effect)
    result = qualify_action_question(query)
    assert (result.matchable and result.value == stored_action_view(stored)) == (stored == query)


@pytest.mark.parametrize("query", [
    Action("sample", ForeignString("reversible")),
    Action("sample", ActionEffect.REVERSIBLE, ForeignString("x")),
    ForeignAction("sample", ActionEffect.REVERSIBLE),
])
def test_action_subclasses_and_foreign_fields_refuse_without_hooks(query):
    with pytest.raises(QuestionRefused):
        qualify_action_question(query)


def test_non_action_identity_and_refusal_priority():
    with pytest.raises(QuestionRefused):
        qualify_action_question(object())
    query = Action("sample", b"nonmatch", ForeignString("refuse"))
    with pytest.raises(QuestionRefused):
        qualify_action_question(query)
    with pytest.raises(QuestionRefused):
        outcome_question(ForeignString("refuse"), "assertion", None, key_id="key", clock_domain="domain")


def test_raw_question_and_decoded_action_equality_property():
    values = ["", "x", "78", None, 0, 1, True, False, [], ["x"], {"a": True}, {"a": 1}]
    stored = [Action("sample", effect, value) for effect in ActionEffect for value in values]
    raw = [Action("sample", effect, value) for effect in [*ActionEffect, "reversible", "external", "unknown", 1]
           for value in [*values, b"x", ("x",), Decimal(1)]]
    for query in raw:
        result = qualify_action_question(query)
        for action in stored:
            assert (action == query) == (result.matchable and stored_action_view(action) == result.value)


def configured(case):
    clock, signer, other, trust, _, _, _, originals = case
    kwargs = dict(tenant="tenant", signer=signer, clock=clock, trust=trust,
        signing_keys=frozenset({signer.key_id}), historical_head_keys={},
        envelope_keys_allowed=frozenset({signer.key_id, other.key_id}),
        envelope_domains=frozenset({clock.domain, "test:other"}))
    return MemoryEvidenceService(**kwargs), originals[0], other


def signed(store, record, seq, previous, signer=None, domain=None):
    signer = store.signer if signer is None else signer
    envelope = ClockedDecisionEnvelope(record, digest_hex(record), previous, seq,
        signer.sign({}), store.clock.domain if domain is None else domain)
    envelope = replace(envelope, signature=signer.sign(envelope.signed_body()))
    return decode_envelope(canonical_bytes(envelope))


def answer(store, kind, question):
    assert question.matchable
    proof = store.lookup(head=store.head, key_type=kind, key=question.value, selection="first")
    result = verify_lookup(proof, expected_head=store.head, tenant=store.tenant,
        key_type=kind, key=question.value, selection="first", clock_domain=store.clock.domain,
        trust=store.trust, allowed_head_keys=store.signing_keys,
        allowed_envelope_keys=store.envelope_keys_allowed, allowed_envelope_domains=store.envelope_domains)
    return result.envelope, proof


def outcome_record(original):
    return replace(original.record, decision=replace(original.record.decision,
        reason_codes=("OUTCOME_COMMITTED",),
        annotations=(Annotation("outcome-of-decision", original.record_hash),)))


def test_exact_h4_selection_and_key_domain_rotation(case):
    store, original, other = configured(case)
    valid = outcome_record(original)
    records = [replace(valid, decision=replace(valid.decision, annotations=valid.decision.annotations * 2)),
               replace(valid, assertion_id="wrong"), valid, valid, valid]
    envelopes = []
    for i, record in enumerate(records):
        env = signed(store, record, i, envelopes[-1].chain_hash() if envelopes else GENESIS,
                     signer=other if i == 2 else None, domain="test:other" if i == 3 else None)
        envelopes.append(env); store.append(env)
    for signer in (store.signer, other):
        for domain in (store.clock.domain, "test:other"):
            recorder = DecisionRecorder(signer, store.trust, clock=SimpleNamespace(domain=domain))
            gate = SimpleNamespace(_engine=SimpleNamespace(_recorder=SimpleNamespace(
                entries=lambda tenant: tuple(envelopes), verify_entry=recorder.verify_entry)))
            expected = _RegulatedGateBase.verified_release_outcome(gate, spec=None, tenant="tenant", decision=original)
            q = outcome_question(original.record_hash, original.record.assertion_id, original.record.action,
                                 key_id=signer.key_id, clock_domain=domain)
            got, _ = answer(store, OUTCOME_ELIGIBLE, q)
            assert got == expected
            q = decision_question(digest_hex(valid), key_id=signer.key_id, clock_domain=domain)
            expected_h3 = next((e for e in envelopes if e.record_hash == digest_hex(valid) and recorder.verify_entry(e)), None)
            assert answer(store, DECISION_ELIGIBLE, q)[0] == expected_h3


def test_valid_signature_with_bad_record_hash_never_enters_indexes(case):
    store, original, _ = configured(case)
    bad = signed(store, original.record, 0, GENESIS)
    bad = replace(bad, record_hash="0" * 64)
    bad = replace(bad, signature=store.signer.sign(bad.signed_body()))
    assert store.trust.verify(bad.signed_body(), bad.signature)
    assert not verify_envelope(bad, store.trust)
    with pytest.raises(EvidenceError):
        store.append(bad)
    assert store.head is None and not store._key_trees


class CountReads(dict):
    def __init__(self, values):
        super().__init__(values); self.reads = 0
    def __getitem__(self, key):
        self.reads += 1
        return super().__getitem__(key)


@pytest.mark.parametrize("decoys", [1000, 10000])
def test_eligible_lookup_work_does_not_walk_decoys(case, decoys, monkeypatch):
    store, original, other = configured(case)
    valid = outcome_record(original)
    variants = [replace(valid, action=replace(valid.action, destination="wrong")),
        replace(valid, assertion_id="wrong"),
        replace(valid, decision=replace(valid.decision, annotations=valid.decision.annotations * 2)),
        replace(valid, decision=replace(valid.decision, reason_codes=("NOT_COMMITTED",))), valid, valid]
    # Bulk immutable qualification fixture: construct actual global/per-key trees
    # and a final authenticated map. This measures lookup, not append scaling or
    # PostgreSQL persistence, and does not bypass any lookup verification guard.
    envelopes = []; kinds = {}
    for seq in range(decoys + 1):
        v = seq % 6
        record = valid if seq == decoys else variants[v]
        env = signed(store, record, seq, envelopes[-1].chain_hash() if envelopes else GENESIS,
                     signer=other if seq < decoys and v == 4 else None,
                     domain="test:other" if seq < decoys and v == 5 else None)
        assert verify_envelope(env, store.trust)
        envelopes.append(env); raw = canonical_bytes(env)
        store._tree.append(raw); store._envelopes[seq] = raw
        for key, kind in envelope_keys(env).items():
            kinds[key] = kind
            tree = store._key_trees.setdefault(key, MemoryMerkleLog())
            ordinal = tree.append(occurrence_bytes(seq)); store._occurrences[key, ordinal] = seq
    for key, tree in store._key_trees.items():
        count = tree.frontier.size
        summary = KeySummary(count, store._occurrences[key, 0], store._occurrences[key, count - 1], tree.root().hex())
        store._map.update(key, summary.bytes())
    # Final fixture head is signed over the authentic full tree and final map.
    base = case[6][-1]
    head = replace(base, tree_size=len(envelopes), tree_root=store._tree.root().hex(),
                   map_root=store._map.root.hex(), last_entry_hash=envelopes[-1].chain_hash())
    head = replace(head, signature=store.signer.sign(head.body()))
    store._head = head; store._heads[head.tree_size] = head
    store._occurrences = CountReads(store._occurrences); store._envelopes = CountReads(store._envelopes)
    reads = []; original_read = store._map._read
    def count_read(*args):
        reads.append(1); return original_read(*args)
    monkeypatch.setattr(store._map, "_read", count_read)
    questions = [(OUTCOME_ELIGIBLE, outcome_question(original.record_hash, original.record.assertion_id,
                  original.record.action, key_id=store.signer.key_id, clock_domain=store.clock.domain)),
                 (DECISION_ELIGIBLE, decision_question(digest_hex(valid), key_id=store.signer.key_id,
                  clock_domain=store.clock.domain))]
    for kind, q in questions:
        reads.clear(); store._occurrences.reads = store._envelopes.reads = 0
        result, proof = answer(store, kind, q)
        assert result == envelopes[-1]
        assert store._occurrences.reads == store._envelopes.reads == 1
        assert 1 <= len(reads) <= 257  # Compact v2: path depth <=256 plus terminal.
        assert len(reads) == len(proof.map_proof.siblings) + 1
        assert len(proof.occurrence.key_path) == 0
        assert len(proof.occurrence.evidence_path) <= head.tree_size.bit_length()
    recorder = DecisionRecorder(store.signer, store.trust, clock=store.clock)
    gate = SimpleNamespace(_engine=SimpleNamespace(_recorder=SimpleNamespace(
        entries=lambda tenant: tuple(envelopes), verify_entry=recorder.verify_entry)))
    assert _RegulatedGateBase.verified_release_outcome(gate, spec=None, tenant="tenant", decision=original) == envelopes[-1]


@pytest.mark.parametrize("kind,key", [
    (DECISION_ELIGIBLE, ["h", "key"]), (DECISION_ELIGIBLE, ["h", "", "domain"]),
    (DECISION_ELIGIBLE, ["h", "key", None]), (DECISION_ELIGIBLE, ("h", "key", "domain")),
    (OUTCOME_ELIGIBLE, ["h", "a", [], "key", "domain"]),
    (OUTCOME_ELIGIBLE, ["h", "a", ["id", "reversible", b"x"], "key", "domain"]),
])
def test_malformed_eligibility_key_shapes_refuse(kind, key):
    with pytest.raises(EvidenceError):
        lookup_key("tenant", kind, key)


@pytest.mark.parametrize("query", [None, True, 1, "x", 1.0, float("nan"), Decimal(1),
    Decimal("NaN"), Decimal("sNaN"), Fraction(1), [], {}, (), b"", bytearray(), set(), frozenset()])
def test_exact_non_action_types_prove_legacy_false(query):
    for stored in (Action("sample", effect) for effect in ActionEffect):
        assert (stored == query) is False
        assert not qualify_action_question(query).matchable


def test_spoofed_class_is_refused_without_reading_the_property():
    reads = []
    class Foreign:
        action_id = "sample"
        effect = ActionEffect.REVERSIBLE
        destination = ""
        @property
        def __class__(self):
            reads.append("class")
            return Action
    query = Foreign()
    assert type(query).__eq__ is object.__eq__
    assert Action("sample", ActionEffect.REVERSIBLE) == query
    assert reads == ["class"]
    reads.clear()
    with pytest.raises(QuestionRefused):
        qualify_action_question(query)
    assert reads == []


def test_foreign_metaclass_and_attribute_hooks_are_not_executed():
    class HostileMeta(type):
        def __getattribute__(self, name):
            raise AssertionError("foreign metaclass attribute hook")
        def __eq__(self, other):
            raise AssertionError("foreign metaclass equality hook")
    class Foreign(metaclass=HostileMeta):
        def __getattribute__(self, name):
            raise AssertionError("foreign object attribute hook")
        def __eq__(self, other):
            raise AssertionError("foreign object equality hook")
    with pytest.raises(QuestionRefused):
        qualify_action_question(Foreign())
