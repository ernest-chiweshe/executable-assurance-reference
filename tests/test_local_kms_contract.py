"""Offline LocalKms signer and host construction contracts, with no database."""

from dataclasses import replace

import pytest

from local_kms_fixtures import LocalKmsFixtureSigner
from regulated_core.kms import KmsUnavailable
from regulated_core.signing import TrustDirectory
from test_host_contract import compose, contract  # noqa: F401


def unavailable_local_signer(key_id):
    signer = LocalKmsFixtureSigner(key_id)
    signer.unavailable = True
    return signer


@pytest.mark.parametrize("contract", [unavailable_local_signer], indirect=True)
def test_local_kms_host_constructs_without_signing_or_database_io(contract):  # noqa: F811
    host = compose(contract)
    assert host.stores is contract.stores
    assert all(key.custody.provider == "local-mock" for key in contract.keys.values())
    assert all(key.unavailable and key.failed_calls == 0 for key in contract.keys.values())
    assert contract.authorities.trust.distinct_keys(tuple(key.key_id for key in contract.keys.values()))


@pytest.mark.parametrize("contract", [unavailable_local_signer], indirect=True)
def test_reusing_an_authority_key_for_approval_refuses_before_signing(contract):  # noqa: F811
    with pytest.raises(ValueError, match="keys must be separated"):
        compose(contract, authorities=replace(contract.authorities,
                approval_signer=contract.keys["emission"]))
    assert all(key.failed_calls == 0 for key in contract.keys.values())


@pytest.mark.parametrize("role", ["evidence", "approval", "emission"])
def test_local_kms_seam_signs_exact_payload_and_refuses_unavailability(role):
    signer = LocalKmsFixtureSigner("fixture:" + role)
    trust = TrustDirectory()
    trust.register_signer(signer)
    payload = {"fixture": True, "role": role, "artifact_digest": "a" * 64}
    assert trust.verify(payload, signer.sign(payload))
    exact = b"synthetic-byte-exact-evidence\x00\r\n"
    assert trust.verify_bytes(exact, signer.sign_bytes(exact))
    assert signer.custody.provider == "local-mock"
    signer.unavailable = True
    with pytest.raises(KmsUnavailable):
        signer.sign(payload)
    with pytest.raises(KmsUnavailable):
        signer.sign_bytes(exact)
    assert signer.failed_calls == 2
