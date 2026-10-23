"""Intact synthetic signed-observation contracts; no effect or host admission."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.identity_provider import CredentialError, CredentialReceipt
from regulated_core.reviewer_sessions import (
    ReviewerSessionBinding, SESSION_RECEIPT_SCHEMA,
    decode_session_credential, issue_session_credential,
)
from regulated_core.signing import Ed25519Signer, TrustDirectory


@pytest.fixture
def scene():
    signer = Ed25519Signer("fictional-reviewer-credential")
    trust = TrustDirectory()
    trust.register_signer(signer)
    signed = []
    def sign(body):
        signed.append(body)
        return signer.sign(body)
    port = SimpleNamespace(key_id=signer.key_id, sign=sign)
    fields = dict(subject_id="teacher", tenant="school", role="teacher",
                  licence_type="fixture", jurisdiction="ZA", status="active",
                  expires_at_us=900, verified_at_us=100, provider="fixture")
    binding = ReviewerSessionBinding("school", "teacher", "teacher.local", "session-1", 700)
    return port, trust, signed, fields, binding


def test_signed_session_observation_roundtrips_and_uses_one_signature(scene):
    signer, trust, calls, fields, binding = scene
    receipt = issue_session_credential(signer, reviewer_session=binding, **fields)
    assert len(calls) == 1
    assert calls[0]["schema"] == SESSION_RECEIPT_SCHEMA
    assert trust.verify(receipt.signed_body(), receipt.signature)
    restored = decode_session_credential(json.loads(canonical_bytes(receipt)))
    assert restored == receipt and restored.digest() == receipt.digest()
    assert restored.reviewer_session.reference == "session-1"


@pytest.mark.parametrize("change", [
    {"tenant": "other"}, {"principal": "other"}, {"username": "another.local"},
    {"reference": "session-2"}, {"expires_at_us": 600},
])
def test_every_binding_field_changes_signed_payload(scene, change):
    signer, trust, calls, fields, binding = scene
    receipt = issue_session_credential(signer, reviewer_session=binding, **fields)
    # Compare independently valid observations; this is not an admission attempt.
    other_binding = replace(binding, **change)
    other_fields = dict(fields, tenant=other_binding.tenant, subject_id=other_binding.principal)
    other = issue_session_credential(signer, reviewer_session=other_binding, **other_fields)
    assert receipt.signed_body() != other.signed_body()
    assert receipt.digest() != other.digest()
    assert trust.verify(other.signed_body(), other.signature)
    assert len(calls) == 2


@pytest.mark.parametrize("binding_change", [
    {"tenant": "other"}, {"principal": "other"}, {"expires_at_us": 100},
])
def test_invalid_binding_refused_before_signing(scene, binding_change):
    signer, _, calls, fields, binding = scene
    with pytest.raises(CredentialError):
        issue_session_credential(signer, reviewer_session=replace(binding, **binding_change), **fields)
    assert calls == []


@pytest.mark.parametrize("expiry", [True, 1.5, "700", 0])
def test_session_expiry_has_exact_type(expiry):
    with pytest.raises(CredentialError):
        ReviewerSessionBinding("school", "teacher", "teacher.local", "session-1", expiry)


def test_parser_requires_exact_fields_and_does_not_sign(scene):
    signer, _, calls, fields, binding = scene
    receipt = issue_session_credential(signer, reviewer_session=binding, **fields)
    raw = json.loads(canonical_bytes(receipt))
    raw["reviewer_session"]["unknown"] = "field"
    with pytest.raises(CredentialError):
        decode_session_credential(raw)
    assert len(calls) == 1


def test_legacy_receipt_signed_body_and_serialized_shape_remain_v1(scene):
    signer, trust, _, fields, _ = scene
    body = dict(schema="regulated/credential-receipt/v1", **fields)
    legacy = CredentialReceipt(signature=signer.sign(body), **fields)
    assert legacy.signed_body() == body
    assert "reviewer_session" not in json.loads(canonical_bytes(legacy))
    assert trust.verify(legacy.signed_body(), legacy.signature)

