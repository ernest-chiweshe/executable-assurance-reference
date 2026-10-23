"""The key provider seam: where a master key lives, and how it wraps other keys.

Phase 3 encrypts tenant data at rest (Module 29). Envelope encryption needs a root
of trust, a System Master Key (SMK), and the one rule that makes the whole scheme
safe is that the SMK never leaves its keeper. So callers never touch the SMK
directly. They ask this seam to WRAP a small key (encrypt it) or UNWRAP one
(decrypt it), and the SMK stays where it belongs.

That indirection is the entire portability story for key management. The same
caller code runs whether the SMK is a byte string in this process (development), a
key in a cloud KMS (AWS KMS, GCP KMS, Vault Transit), or a key sealed inside a
hardware security module it can never read out. You change which provider the
composition root constructs. You change nothing else.

Two providers ship here, and the gap between them is deliberate and honest:

  LocalKeyProvider   real AES-256-GCM, but the master key lives in process memory.
                     Correct for development and for the free tests. It is the
                     floor, not FIPS-grade: a memory-resident key is readable by
                     anything that can read this process.
  HsmKeyProvider     the hardware path, quarantined as an unimplemented stub. A
                     real PKCS#11 binding is isolated behind this one class and
                     shipped only when a customer's compliance actually requires
                     it. The interface is the asset; the HSM is a swap. (This
                     mirrors the production posture: ship the seam, defer the
                     silicon until a FIPS 140-3 requirement pays for it.)
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Associated data bound into every wrap. It is not secret; it ties a wrapped blob
# to its purpose so a ciphertext meant as a wrapped key cannot be replayed as
# something else under the same master key.
_WRAP_AAD = b"agent-factory/kek-wrap/v1"
_NONCE_LEN = 12
_SMK_LEN = 32  # AES-256


def load_or_create_master_key(path: str) -> bytes:
    """Load a 32-byte AES-256 System Master Key from `path`, creating and persisting
    one on first use. This is what makes software encryption DURABLE: without it the
    SMK is regenerated every process, so anything wrapped yesterday cannot be unwrapped
    today. With it, the root of trust survives a restart.

    The file is written atomically (temp + os.replace) and restricted to owner
    read/write (mode 0600), the same discipline as the .env: a master key on disk is
    only as safe as its permissions. A wrong-sized file is an error, not a silent
    re-key, because silently minting a new SMK would orphan all existing ciphertext.

    Honest scope: this is the durable SOFTWARE floor, not an HSM. The key still lives
    on disk readable by its owner; a compliance deployment swaps in a KMS/HSM provider
    behind the same seam. A naive create has a write-write race (two fresh processes
    could mint different keys); for a single operator that does not arise, and a real
    multi-writer deployment would use the KMS provider, not this file.
    """
    target = Path(path)
    if target.exists():
        key = target.read_bytes()
        if len(key) != _SMK_LEN:
            raise ValueError(f"master key at {path} is {len(key)} bytes, expected {_SMK_LEN}")
        return key

    key = AESGCM.generate_key(bit_length=256)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Create the temp file with 0600 from the start (mkstemp does), write, replace.
    handle, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".smk-")
    try:
        os.write(handle, key)
        os.close(handle)
        os.chmod(tmp, 0o600)          # owner-only (no-op semantics on Windows, enforced on POSIX)
        os.replace(tmp, target)        # atomic publish
    except BaseException:
        os.close(handle) if not _is_closed(handle) else None
        Path(tmp).unlink(missing_ok=True)
        raise
    return key


def _is_closed(fd: int) -> bool:
    """Whether a file descriptor is already closed, so cleanup does not double-close."""
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True


@runtime_checkable
class KeyProvider(Protocol):
    """Wrap and unwrap small keys against a master key that never leaves the keeper."""

    name: str

    def wrap(self, plaintext: bytes) -> bytes: ...
    def unwrap(self, ciphertext: bytes) -> bytes: ...


class LocalKeyProvider:
    """Phase-1 software SMK: a master key held in this process. Real crypto, but
    the key is memory-resident, so this is the development and test provider, never
    the production root of trust. Swap it for a KMS or HSM provider in the
    composition root and no caller changes."""

    name = "local"

    def __init__(self, master_key: bytes | None = None) -> None:
        # A 32-byte AES-256 key. Generated when absent so tests and local runs work
        # with zero setup; in production the SMK lives in a KMS or HSM and this
        # class is replaced, not configured.
        self._key = master_key or AESGCM.generate_key(bit_length=256)

    def wrap(self, plaintext: bytes) -> bytes:
        # Fresh nonce per wrap, prepended to the ciphertext. GCM with a reused nonce
        # under the same key is catastrophic, so the nonce is never derived or fixed.
        nonce = os.urandom(_NONCE_LEN)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, _WRAP_AAD)

    def unwrap(self, ciphertext: bytes) -> bytes:
        # A tampered or truncated blob fails the GCM tag check and raises, which is
        # the behavior we want: an unverifiable wrapped key must not be returned.
        nonce, sealed = ciphertext[:_NONCE_LEN], ciphertext[_NONCE_LEN:]
        return AESGCM(self._key).decrypt(nonce, sealed, _WRAP_AAD)


class HsmProviderUnavailable(RuntimeError):
    """Raised when the HSM provider is selected but no PKCS#11 backend is wired."""


class HsmKeyProvider:
    """The hardware path, quarantined. Implements `KeyProvider` so the type checks
    and the composition root can name it, but it ships unimplemented on purpose.

    A real binding would open a PKCS#11 session against the HSM, find the SMK by
    label, and call the device to wrap/unwrap so the key never leaves the silicon
    (C_WrapKey / C_UnwrapKey, or C_Encrypt / C_Decrypt against a non-extractable
    key object). That binding is the single version-sensitive, hardware-specific
    surface in the factory, and it lands when a customer's FIPS 140-3 requirement
    pays for it. Until then this fails loud rather than pretending.
    """

    name = "hsm"

    def __init__(self, module_path: str | None = None, token_label: str | None = None) -> None:
        # The PKCS#11 module path and token label a real binding would need. Stored
        # so the shape is visible, unused until the binding exists.
        self._module_path = module_path
        self._token_label = token_label

    def _unavailable(self) -> HsmProviderUnavailable:
        return HsmProviderUnavailable(
            "HsmKeyProvider is an interface-only stub. Wire a PKCS#11 binding "
            "(non-extractable SMK, wrap/unwrap on the device) before selecting it."
        )

    def wrap(self, plaintext: bytes) -> bytes:
        raise self._unavailable()

    def unwrap(self, ciphertext: bytes) -> bytes:
        raise self._unavailable()


class KmsKeyProvider:
    """The production master-key provider: a cloud KMS holds the master key, this only asks the KMS to wrap
    and unwrap small keys (the per-tenant KEKs). The master key never leaves the KMS, so a host compromise
    cannot exfiltrate it, which is the property the software LocalKeyProvider cannot offer.

    Default backend is AWS KMS via boto3 (`kms:Encrypt` / `kms:Decrypt` against a customer-managed key).
    The 32-byte KEK is well under KMS's 4KB direct-encrypt limit, so the KEK is wrapped by the KMS key
    directly, no extra data-key dance. GCP KMS, Azure Key Vault, or Vault Transit drop in behind this same
    class: each exposes an encrypt/decrypt against a non-exportable key, which is exactly what wrap/unwrap
    need. The rest of the factory does not change; only the composition root names this instead of Local.

    EncryptionContext is KMS's AAD: it binds each wrapped blob to a purpose, so a ciphertext minted here
    cannot be replayed under the same KMS key for a different use. It is set to a fixed factory context by
    default and is verified on decrypt by the KMS itself."""

    name = "kms"

    def __init__(self, key_id: str, *, region: str | None = None, client: Any | None = None,
                 encryption_context: dict[str, str] | None = None) -> None:
        if not key_id:
            raise ValueError("KmsKeyProvider needs a key id (a KMS key ARN, id, or alias)")
        self._key_id = key_id
        # The client is injected in tests (a fake KMS); in production it is a real boto3 KMS client. We
        # import boto3 lazily so the dependency is only required when the KMS provider is actually selected.
        if client is None:
            import boto3  # optional 'kms' extra; the pyproject override keeps the gate env-independent
            client = boto3.client("kms", region_name=region)
        self._client: Any = client
        self._ec = encryption_context or {"factory": "kek-wrap/v1"}

    def wrap(self, plaintext: bytes) -> bytes:
        # The KMS encrypts the KEK under its master key and returns an opaque ciphertext blob. The master
        # key never enters this process.
        resp = self._client.encrypt(KeyId=self._key_id, Plaintext=plaintext, EncryptionContext=self._ec)
        return bytes(resp["CiphertextBlob"])

    def unwrap(self, ciphertext: bytes) -> bytes:
        # The KMS verifies the EncryptionContext (AAD) and decrypts. A blob from a different context or key
        # fails at the KMS, which is the behavior we want: an unverifiable wrapped key is never returned.
        resp = self._client.decrypt(CiphertextBlob=ciphertext, EncryptionContext=self._ec)
        return bytes(resp["Plaintext"])


def pick_key_provider(
    name: str | None = None, *, master_key: bytes | None = None, smk_path: str | None = None
) -> KeyProvider:
    """Composition-root selector. Reads FACTORY_KEY_PROVIDER when name is absent.

    Defaults to the local software provider so the factory runs with no key
    infrastructure. For the local provider, an SMK PATH (the `smk_path` argument or
    FACTORY_SMK_PATH) makes the master key DURABLE across restarts; with neither, the
    key is ephemeral (regenerated per process), which is correct for tests but means
    nothing wrapped survives a restart. A production composition passes "hsm" (or a
    KMS provider added later) here, and only this one call site changes.
    """
    chosen = (name or os.environ.get("FACTORY_KEY_PROVIDER") or "local").lower()
    if chosen == "local":
        if master_key is None:
            path = smk_path or os.environ.get("FACTORY_SMK_PATH")
            if path:
                master_key = load_or_create_master_key(path)  # durable across restarts
        return LocalKeyProvider(master_key)
    if chosen == "kms":
        # The production posture: the master key lives in a cloud KMS. Configured by env so the composition
        # root stays declarative: FACTORY_KMS_KEY_ID (a key ARN/id/alias) and optionally FACTORY_AWS_REGION.
        key_id = os.environ.get("FACTORY_KMS_KEY_ID")
        if not key_id:
            raise ValueError("FACTORY_KEY_PROVIDER=kms needs FACTORY_KMS_KEY_ID (a KMS key ARN, id, or alias)")
        return KmsKeyProvider(key_id, region=os.environ.get("FACTORY_AWS_REGION"))
    if chosen == "hsm":
        return HsmKeyProvider()
    raise ValueError(f"unknown key provider: {chosen!r} (known: local, kms, hsm)")
