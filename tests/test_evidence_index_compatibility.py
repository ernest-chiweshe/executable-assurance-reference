"""Decoded-JSON index semantics; in-memory recorder callers remain unchanged."""
import json
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.evidence_service import (
    EvidenceError, require_hashable_history, verify_history_flag, lookup_key,
)
from regulated_core.evidence_questions import qualify_question
from regulated_core.persistence_pg import decode_envelope
from regulated_core.projectos_gate import _RegulatedGateBase
from regulated_core.approval import ApprovalCertificate
from test_evidence_service_formats import case
from test_evidence_service_memory import memory, answer


@pytest.mark.parametrize("record_id", ["", 7, True, False, None, ["x"], {"k": True}, ("x",), b"x"])
def test_every_persisted_id_is_indexed_without_changing_signed_bytes(memory, record_id):
    store, append, _, heads, _ = memory
    envelope, head = append(0, record_id=record_id)
    expected = decode_envelope(canonical_bytes(envelope))
    result = answer(memory, "record_id", expected.record.record_id, "first")
    assert canonical_bytes(result.envelope) == canonical_bytes(envelope)
    assert result.envelope.signature == envelope.signature
    assert answer(memory, "record_id_hash", (expected.record.record_id, envelope.record_hash), "latest").envelope == expected
    assert store._envelopes[0] == canonical_bytes(envelope)


@pytest.mark.parametrize("message", ["", "A" * 64, "a" * 63, "a" * 65, "not-hex", "\0", 7, None, ["x"], {"k": True}])
def test_outcome_messages_are_indexed_exactly_and_duplicates_are_one_occurrence(memory, message):
    from regulated_core.models import Annotation
    from regulated_core.evidence import GENESIS, ClockedDecisionEnvelope
    from regulated_core.canonical import digest_hex
    store, _, envs, heads, _ = memory
    clock, signer, _, _, _, _, _, originals = case.__wrapped__()
    original = originals[0]
    record = replace(original.record, decision=replace(original.record.decision,
        annotations=(Annotation("outcome-of-decision", message),) * 2))
    envelope = ClockedDecisionEnvelope(record, digest_hex(record), GENESIS, 0, original.signature, clock.domain)
    envelope = replace(envelope, signature=store.signer.sign(envelope.signed_body()))
    if message == "\0":
        from regulated_core.evidence_encoding import RepresentationError
        before = (store.head, dict(store._envelopes))
        with pytest.raises(EvidenceError, match="invalid appended envelope") as refused:
            store.append(envelope)
        assert isinstance(refused.value.__cause__, RepresentationError)
        assert "NUL" in str(refused.value.__cause__)
        assert (store.head, dict(store._envelopes)) == before
        return
    head = store.append(envelope); envs.append(envelope); heads.append(head)
    result = answer(memory, "outcome_of", message, "first")
    assert result.summary.count == 1
    assert canonical_bytes(result.envelope) == canonical_bytes(envelope)
    # The legacy H4 predicate still rejects the duplicated annotations.
    assert [a.message for a in result.envelope.record.decision.annotations] != [message]


def test_bool_int_equivalence_and_legacy_h2_decimal_and_empty_id(memory):
    _, append, envs, _, _ = memory
    for i, value in enumerate([1, True, "1", 7, ""]):
        append(i, record_id=value)
    assert answer(memory, "record_id", True, "count").summary.count == 2
    assert answer(memory, "record_id", 1, "latest").envelope.seq == 1
    assert answer(memory, "record_id", "1", "count").summary.count == 1
    for index, question in ((3, Decimal(7)), (4, "")):
        env = envs[index]
        cert = ApprovalCertificate("request", "tenant", env.record.assertion_id, question,
            env.record_hash, "a" * 64, ("reviewer",), 100, env.signature)
        gate = SimpleNamespace(_engine=SimpleNamespace(_recorder=SimpleNamespace(entries=lambda tenant: envs)))
        legacy = _RegulatedGateBase._approved_record(gate, cert, "tenant")
        qualified = qualify_question(question)
        assert qualified.matchable
        observed = answer(memory, "record_id_hash", (qualified.value, env.record_hash), "latest").envelope
        assert observed == legacy


def test_hashable_history_flag_monotonic_historical_and_proof_bound(memory):
    store, append, envs, heads, args = memory
    for i, value in enumerate(["first", ["x"], "later", {"k": 1}]):
        append(i, record_id=value)
    verify = {k: args[k] for k in ("tenant", "clock_domain", "trust", "allowed_head_keys")}
    for i, head in enumerate(heads):
        proof = store.history_flag(head=head)
        flag = verify_history_flag(proof, expected_head=head, **verify)
        assert (flag is None) == (i == 0)
        if i == 0:
            require_hashable_history(proof, expected_head=head, **verify)
        else:
            assert flag.first_seq == 1
            with pytest.raises(TypeError):
                require_hashable_history(proof, expected_head=head, **verify)
            with pytest.raises(TypeError):
                {env.record.record_id: env for env in envs[:i + 1]}
    proof = store.history_flag(head=heads[-1])
    forged = replace(proof, map_proof=replace(proof.map_proof, value=None))
    with pytest.raises(EvidenceError):
        require_hashable_history(forged, expected_head=heads[-1], **verify)
    with pytest.raises(EvidenceError):
        verify_history_flag(proof, expected_head=heads[0], **verify)
    absent = store.history_flag(head=heads[0])
    forged_presence = replace(absent, map_proof=replace(absent.map_proof, value=proof.map_proof.value))
    with pytest.raises(EvidenceError):
        verify_history_flag(forged_presence, expected_head=heads[0], **verify)


def test_string_key_digests_are_unchanged_and_nonjson_service_queries_refuse():
    from regulated_core.evidence_map import key_digest
    for kind in ("record_id", "record_hash", "outcome_of"):
        for text in ("", "x", "a" * 64, "\0"):
            assert lookup_key("tenant", kind, text) == key_digest("tenant", kind, text)
    for key in (Decimal(7), ("x",), object()):
        with pytest.raises(EvidenceError):
            lookup_key("tenant", "record_id", key)
