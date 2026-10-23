"""Encryption at rest, as a drop-in for the artifact store. The seam absorbs it.

The ledger (Module 18) defined `ArtifactStore` as a Protocol: `put(tenant, data)`
returns a content address, `get(tenant, address)` returns the bytes. Module 29
adds a second implementation of that exact Protocol that encrypts every artifact
per tenant. Because the `Ledger` and every caller depend on the Protocol and not
on `FileArtifactStore`, swapping the plaintext store for this one in the
composition root changes no caller. That is the no-refactor claim, made literal.

The scheme is three-layer envelope encryption, the production pattern:

  SMK   the System Master Key, held by the KeyProvider (Module 29), never read out.
  KEK   a Key Encryption Key per TENANT. Random once, then stored wrapped by the
        SMK. Drop it and that tenant's data is gone (crypto-erase).
  DEK   a Data Encryption Key per ARTIFACT. Random on every put, used once to
        encrypt the bytes, then stored wrapped by the tenant's KEK.

Two properties make it safe across tenants. Every layer is AES-256-GCM, so a
tampered ciphertext fails its authentication tag and refuses to decrypt. And the
associated data binds each artifact to `tenant_id` and its address, so one
tenant's wrapped key can never unwrap another's artifact even at the same address.

The address stays the SHA-256 of the PLAINTEXT, so content-addressing, dedup, and
the ledger's integrity contract are all preserved. What changes is only what sits
on disk: an envelope instead of the raw bytes. Callers never see the difference.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from factory.keyprovider import KeyProvider, LocalKeyProvider
from factory.ledger import IntegrityError, content_address
from factory.tenant import TenantContext

_NONCE_LEN = 12


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


class EncryptingArtifactStore:
    """A content-addressed store that encrypts every artifact per tenant at rest.

    Implements the `ArtifactStore` Protocol from Module 18, so it drops in wherever
    `FileArtifactStore` was wired. The per-tenant KEK is stored wrapped by the
    KeyProvider's SMK; each artifact gets its own DEK wrapped by that KEK.
    """

    def __init__(self, root: str | Path, key_provider: KeyProvider | None = None) -> None:
        self._root = Path(root)
        # Default to the software provider so the store runs with no key
        # infrastructure; production passes an HSM or KMS provider here instead.
        self._kp = key_provider or LocalKeyProvider()

    def _tenant_dir(self, tenant: TenantContext) -> Path:
        directory = self._root / tenant.tenant_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _objects_dir(self, tenant: TenantContext) -> Path:
        directory = self._tenant_dir(tenant) / "objects"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _kek_path(self, tenant: TenantContext) -> Path:
        # The tenant's KEK, stored wrapped by the SMK. Deleting this file is the
        # crypto-erase: the data stays on disk but can never be decrypted again.
        return self._tenant_dir(tenant) / "tenant.kek"

    def _get_or_create_kek(self, tenant: TenantContext) -> bytes:
        path = self._kek_path(tenant)
        if path.exists():
            return self._kp.unwrap(path.read_bytes())
        kek = AESGCM.generate_key(bit_length=256)
        path.write_bytes(self._kp.wrap(kek))  # at rest the KEK is only ever wrapped
        return kek

    def _get_kek(self, tenant: TenantContext) -> bytes:
        path = self._kek_path(tenant)
        if not path.exists():
            # No key for this tenant means either nothing was stored, or the tenant
            # was crypto-erased. Either way there is nothing we can decrypt.
            raise IntegrityError(f"no key for tenant '{tenant.tenant_id}' (crypto-erased?)")
        return self._kp.unwrap(path.read_bytes())

    def put(self, tenant: TenantContext, data: bytes) -> str:
        address = content_address(data)  # address of the PLAINTEXT: contract preserved
        kek = self._get_or_create_kek(tenant)
        dek = AESGCM.generate_key(bit_length=256)  # fresh per artifact
        aad = f"{tenant.tenant_id}:{address}".encode()  # binds tenant + address

        nonce_data, nonce_dek = os.urandom(_NONCE_LEN), os.urandom(_NONCE_LEN)
        sealed_data = AESGCM(dek).encrypt(nonce_data, data, aad)
        sealed_dek = AESGCM(kek).encrypt(nonce_dek, dek, aad)

        envelope = {
            "v": 1,
            "nonce_data": _b64(nonce_data),
            "sealed_data": _b64(sealed_data),
            "nonce_dek": _b64(nonce_dek),
            "sealed_dek": _b64(sealed_dek),
        }
        (self._objects_dir(tenant) / address).write_text(json.dumps(envelope))
        return address

    def get(self, tenant: TenantContext, address: str) -> bytes:
        envelope = json.loads((self._objects_dir(tenant) / address).read_text())
        kek = self._get_kek(tenant)
        aad = f"{tenant.tenant_id}:{address}".encode()

        # Unwrap the DEK with the tenant's KEK, then the data with the DEK. A wrong
        # tenant, a wrong key, or a tampered byte all fail the GCM tag and raise.
        dek = AESGCM(kek).decrypt(_unb64(envelope["nonce_dek"]), _unb64(envelope["sealed_dek"]), aad)
        data = AESGCM(dek).decrypt(_unb64(envelope["nonce_data"]), _unb64(envelope["sealed_data"]), aad)

        if content_address(data) != address:
            raise IntegrityError(f"artifact {address} failed integrity check")
        return data

    def crypto_erase(self, tenant: TenantContext) -> None:
        """Make every one of a tenant's artifacts permanently undecryptable by
        dropping their KEK. Constant-time and tenant-scoped: the data bytes remain
        but no key can ever read them again. This is how you honor a deletion
        request without a re-encryption sweep across object storage.
        """
        self._kek_path(tenant).unlink(missing_ok=True)
