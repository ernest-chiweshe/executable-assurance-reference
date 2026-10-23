"""Offline I-5 recovery contracts with intact code and synthetic local drivers.

No provider SDK, network, PostgreSQL or production vault is used. These calls
qualify only local construction/first-use behavior, not custody or deployment.
"""
from hashlib import sha256
from types import SimpleNamespace

import pytest

from factory.cryptoledger import EncryptingArtifactStore
from factory.keyprovider import HsmKeyProvider, HsmProviderUnavailable, LocalKeyProvider
from factory.provenance import Ed25519Signer
from factory.tenant import TenantContext
from regulated_core.adapters import FactoryPayloadVault, FactorySignerAdapter, register_factory_identity
from regulated_core.signing import TrustDirectory


BODY = b"Synthetic I-5 payload. No customer content."
TENANT = TenantContext("synthetic-i5", "Synthetic I-5")


def test_factory_signer_adapter_produces_original_verifiable_signature():
    trust = TrustDirectory()
    signer = register_factory_identity(trust, "synthetic:factory", Ed25519Signer())
    payload = {"kind": "synthetic", "digest": sha256(BODY).hexdigest()}
    signature = signer.sign(payload)
    assert signature.key_id == signer.key_id
    assert signature.alg == "ed25519"
    assert trust.verify(payload, signature)


@pytest.mark.parametrize("driver", [object(), None])
def test_signer_without_declared_algorithm_refuses_construction(driver):
    with pytest.raises(ValueError, match="explicitly declare"):
        FactorySignerAdapter("synthetic:unconfigured", driver)


@pytest.mark.parametrize("algorithm", ["", "unsupported"])
def test_signer_with_unsupported_algorithm_refuses_construction(algorithm):
    with pytest.raises(ValueError, match="unsupported factory signer algorithm"):
        FactorySignerAdapter("synthetic:invalid", SimpleNamespace(alg=algorithm))


@pytest.mark.parametrize("operation", ["sign", "sign_bytes"])
def test_unavailable_local_signer_propagates_failure_without_a_signature(operation):
    class UnavailableSigner:
        alg = "ed25519"

        def sign(self, data):
            raise OSError("synthetic signer unavailable")

    signer = FactorySignerAdapter("synthetic:unavailable", UnavailableSigner())
    with pytest.raises(OSError, match="synthetic signer unavailable"):
        getattr(signer, operation)(BODY)


def test_payload_vault_lawful_local_roundtrip_retains_digest(tmp_path):
    provider = LocalKeyProvider()
    vault = FactoryPayloadVault(EncryptingArtifactStore(tmp_path, provider))
    address, digest = vault.put(TENANT, BODY)
    assert address == digest == sha256(BODY).hexdigest()
    assert vault.get(TENANT, address) == BODY
    stored = (tmp_path / TENANT.tenant_id / "objects" / address).read_bytes()
    assert BODY not in stored
    # Reconstruct the store with the same explicit local provider; not a restart
    # or master-key persistence/custody qualification.
    recovered = FactoryPayloadVault(EncryptingArtifactStore(tmp_path, provider))
    assert recovered.get(TENANT, address) == BODY


@pytest.mark.parametrize("operation", ["put", "get"])
def test_missing_vault_store_refuses_first_use(operation):
    vault = FactoryPayloadVault(None)
    args = (TENANT, BODY if operation == "put" else sha256(BODY).hexdigest())
    with pytest.raises(AttributeError):
        getattr(vault, operation)(*args)


def test_unavailable_wrap_driver_publishes_no_artifact(tmp_path):
    class UnavailableWrap:
        def wrap(self, data):
            raise OSError("synthetic wrap unavailable")

        def unwrap(self, data):
            raise AssertionError("first write must not unwrap")

    vault = FactoryPayloadVault(EncryptingArtifactStore(tmp_path, UnavailableWrap()))
    with pytest.raises(OSError, match="synthetic wrap unavailable"):
        vault.put(TENANT, BODY)
    assert not list(tmp_path.rglob("*.*"))  # Only empty tenant directory may remain.
    assert not (tmp_path / TENANT.tenant_id / "objects" / sha256(BODY).hexdigest()).exists()


def test_unavailable_unwrap_driver_refuses_read_and_preserves_retained_bytes(tmp_path):
    provider = LocalKeyProvider()
    vault = FactoryPayloadVault(EncryptingArtifactStore(tmp_path, provider))
    address, _ = vault.put(TENANT, BODY)
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    class UnavailableUnwrap:
        def wrap(self, data):
            raise AssertionError("reading must not wrap")

        def unwrap(self, data):
            raise OSError("synthetic unwrap unavailable")

    unavailable = FactoryPayloadVault(EncryptingArtifactStore(tmp_path, UnavailableUnwrap()))
    with pytest.raises(OSError, match="synthetic unwrap unavailable"):
        unavailable.get(TENANT, address)
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("operation", ["wrap", "unwrap"])
def test_unconfigured_hardware_stub_refuses_first_use_without_backend(operation):
    provider = HsmKeyProvider()
    with pytest.raises(HsmProviderUnavailable, match="interface-only stub"):
        getattr(provider, operation)(b"synthetic")
