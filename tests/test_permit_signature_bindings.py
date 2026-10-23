"""A04 detached v5 signature contracts; no receiver, target, or effect is invoked.

The explicit field list is the reviewed binding surface, not a dynamic list
copied from the implementation. Legacy schema compatibility is a separate claim.
"""

from dataclasses import replace
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import pytest

from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import PERMIT_V5_SCHEMA, TargetPermit


BINDINGS = {
    "tenant_id": "fixture:tenant", "principal": "fixture:human",
    "mission": "fixture:mission", "budget_reservation": "fixture:reservation",
    "budget_units": 1, "policy_version": "fixture:policy/1",
    "decision_record_id": "fixture:decision", "decision_record_hash": "a" * 64,
    "approval_ref": "fixture:approval", "assertion_id": "fixture:assertion",
    "action_id": "fixture:action", "operation": "fixture:operation",
    "target_kind": "fixture:no-receiver", "target_digest": "b" * 64,
    "expected_target_state": "fixture:prior", "output_digest": "c" * 64,
    "qualification_digests": ("d" * 64,), "revocation_epoch": 3,
    "expires_at_us": 200, "nonce": "fixture:nonce", "grant_digest": "e" * 64,
    "chain_digest": "f" * 64, "root_digest": "1" * 64,
    "preparation_digest": "2" * 64, "clock_domain": "fixture:clock", "issued_at_us": 100,
}


def canonical_json(body):
    # Independent standard-library encoding of this simple JSON fixture; do not
    # call the production canonical serializer to establish the expected bytes.
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@pytest.fixture
def signed_fixture():
    signer = Ed25519Signer("fixture:permit-signer")
    trust = TrustDirectory()
    trust.register_signer(signer)
    permit = TargetPermit(**BINDINGS)
    return permit, signer.sign(permit.signed_body()), trust, Ed25519PublicKey.from_public_bytes(signer.public_key_bytes)


def test_v5_binds_the_explicit_complete_surface_and_verifies_with_public_key(signed_fixture):
    permit, signature, trust, key = signed_fixture
    expected = {**BINDINGS, "qualification_digests": list(BINDINGS["qualification_digests"]),
                "schema": PERMIT_V5_SCHEMA}
    assert set(permit.__dataclass_fields__) == set(BINDINGS)
    assert permit.signed_body() == expected
    assert trust.verify(expected, signature)
    key.verify(bytes.fromhex(signature.value), canonical_json(expected))


@pytest.mark.parametrize("field", list(BINDINGS))
def test_each_detached_changed_binding_is_refused_by_signature_verification(signed_fixture, field):
    permit, signature, trust, key = signed_fixture
    old = BINDINGS[field]
    if isinstance(old, tuple):
        value = ("9" * 64,)
    elif type(old) is int:
        value = old + 1
    else:
        value = old + ":different"
    changed = replace(permit, **{field: value}).signed_body()
    assert not trust.verify(changed, signature)
    with pytest.raises(InvalidSignature):
        key.verify(bytes.fromhex(signature.value), canonical_json(changed))


def test_schema_domain_is_bound_even_when_every_payload_field_matches(signed_fixture):
    permit, signature, trust, key = signed_fixture
    other_domain = {**permit.signed_body(), "schema": "fixture:unrelated-evidence/v1"}
    assert not trust.verify(other_domain, signature)
    with pytest.raises(InvalidSignature):
        key.verify(bytes.fromhex(signature.value), canonical_json(other_domain))
