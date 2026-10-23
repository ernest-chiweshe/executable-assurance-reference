"""Verify real projection envelopes with the pinned external DSSE implementation.

Trust is supplied independently of envelope content. This verifies a synthetic
snapshot signature, not application qualification or deployed key custody.
"""

import base64
import copy
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import pytest
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import SSlibKey

from assurance_reference.projections import project
from regulated_core.reporting import verify_dsse_attestation
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_projections import fixture_bundle


def external_key(signer, *, key_id=None):
    return SSlibKey.from_crypto(Ed25519PublicKey.from_public_bytes(signer.public_key_bytes),
                               keyid=signer.key_id if key_id is None else key_id)


def test_external_and_core_verifiers_accept_the_same_unmodified_snapshot():
    signer = Ed25519Signer("fixture:externally-verified-report")
    bundle = fixture_bundle()
    source_before = copy.deepcopy(bundle)
    views = project(bundle, signer)
    envelope = views["attestation"]
    before = copy.deepcopy(envelope)
    trust = TrustDirectory()
    trust.register_signer(signer)
    assert verify_dsse_attestation(trust, envelope)
    key = external_key(signer)
    # securesystemslib 1.4.0 decodes signatures in place in from_dict.
    # Give it a copy so the retained canonical envelope is not rewritten.
    parsed = Envelope.from_dict(copy.deepcopy(envelope))
    assert parsed.verify([key], threshold=1) == {signer.key_id: key}
    statement = json.loads(parsed.payload)
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicate"]["source_bundle"] == bundle
    assert statement["predicate"]["audit"] == views["audit"]
    assert envelope == before and bundle == source_before


@pytest.mark.parametrize("part", ["payload", "payloadType", "signature", "keyid"])
def test_core_and_external_verifiers_refuse_changed_envelope(part):
    signer = Ed25519Signer("fixture:externally-verified-report")
    envelope = project(fixture_bundle(), signer)["attestation"]
    changed = copy.deepcopy(envelope)
    if part == "payload":
        changed["payload"] = base64.b64encode(base64.b64decode(changed["payload"]) + b"\n").decode()
    elif part == "payloadType":
        changed["payloadType"] = "application/other-fixture"
    elif part == "signature":
        signature = bytearray(base64.b64decode(changed["signatures"][0]["sig"]))
        signature[0] ^= 1
        changed["signatures"][0]["sig"] = base64.b64encode(signature).decode()
    else:
        changed["signatures"][0]["keyid"] = "fixture:not-the-trusted-key"
    trust = TrustDirectory()
    trust.register_signer(signer)
    assert not verify_dsse_attestation(trust, changed)
    with pytest.raises(VerificationError):
        Envelope.from_dict(copy.deepcopy(changed)).verify([external_key(signer)], threshold=1)


def test_external_verification_requires_trusted_material_not_just_a_key_label():
    signer = Ed25519Signer("fixture:externally-verified-report")
    envelope = project(fixture_bundle(), signer)["attestation"]
    other = Ed25519Signer("fixture:different-material")
    trust = TrustDirectory()
    trust.register(signer.key_id, other.public_key_bytes)
    assert not verify_dsse_attestation(trust, envelope)
    with pytest.raises(VerificationError):
        Envelope.from_dict(copy.deepcopy(envelope)).verify(
            [external_key(other, key_id=signer.key_id)], threshold=1)
