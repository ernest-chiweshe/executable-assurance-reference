"""AWS provider adapters for the controlled operational test environment (paper §6, planned v0.4).

Fills two seams with real providers, behind the SAME frozen protocols the local mocks implement:

  - `CloudHsmPkcs11Backend` -> `SigningBackend` (kms.py): ECDSA P-384 signing inside AWS CloudHSM
    via PKCS#11 (Client SDK 5, CKM_ECDSA_SHA384), inside the FIPS-mode validated boundary.
  - `AwsKmsBackend` -> `SigningBackend` (kms.py): managed ECDSA P-384 signing through AWS KMS.
  - `S3ObjectLockWormStore` -> `WormStore` (worm.py): write-once retention via S3 Object Lock.
    GOVERNANCE mode by default for test environments — COMPLIANCE-mode locks cannot be deleted by
    anyone, including the account root, until expiry, and must never be used in a test window.

Opt-in module (like kms.py/adapters.py): NOT imported by `regulated_core/__init__`, and the heavy
dependencies (python-pkcs11, boto3) are imported lazily, so `import regulated_core` stays
standalone and this module itself imports cleanly without them. Both adapters accept injected
session/client objects, so their logic is fully testable offline (tests/test_aws_adapters.py) —
no AWS account is touched until the runbook's paid window.

Fail-closed discipline matches the local adapters: any provider error surfaces as KmsUnavailable /
WormUnavailable, and the drills' guarantees (no unsigned evidence; no receipt, no release) apply
unchanged.
"""
from __future__ import annotations

import datetime as _dt
import os
from hashlib import sha256, sha384
from typing import Any, Literal, Mapping, cast

from .kms import KeyCustody, KmsUnavailable
from .signing import ALG_ECDSA_P384, ALG_ED25519
from .worm import WormError, WormReceipt, WormUnavailable

SigningProfile = Literal["managed", "strict"]
_SIGNING_PROFILES = frozenset(("managed", "strict"))


def resolve_signing_profile(
    cli_profile: str | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> SigningProfile:
    """Resolve the custody profile without a silent default.

    ``--profile`` is the highest-precedence explicit source and
    ``SIGNING_PROFILE`` is the environment source. Repeating the same value is
    accepted; disagreement is an error instead of silently overriding either
    operator instruction. Absence and unknown values also fail before any
    provider client is constructed.
    """
    env_profile = (environ if environ is not None else os.environ).get("SIGNING_PROFILE")
    for source, value in (("--profile", cli_profile), ("SIGNING_PROFILE", env_profile)):
        if value is not None and value not in _SIGNING_PROFILES:
            raise ValueError(
                f"{source} must be one of {sorted(_SIGNING_PROFILES)}, got {value!r}"
            )
    if cli_profile is not None and env_profile is not None and cli_profile != env_profile:
        raise ValueError(
            f"conflicting signing profiles: --profile={cli_profile!r} "
            f"but SIGNING_PROFILE={env_profile!r}"
        )
    selected = cli_profile or env_profile
    if selected is None:
        raise ValueError(
            "signing profile is required: pass --profile {managed,strict} "
            "or set SIGNING_PROFILE"
        )
    return cast(SigningProfile, selected)


class CloudHsmPkcs11Backend:
    """`SigningBackend` over an AWS CloudHSM cluster via PKCS#11 (Client SDK 5).

    Production path: pass `lib_path` (the CloudHSM PKCS#11 library), `pin` ("CU_user:password"),
    and the key `label`; the backend opens a session lazily and signs by reference — the private
    key never leaves the HSM. Test path: inject a `session` object exposing
    `get_key(label)->key`, `key.sign(data, mechanism)->bytes`, and `public_key_bytes(label)->bytes`.

    Algorithm note (verified against AWS docs, see docs/regulated-architecture/16-*): CloudHSM's
    PKCS#11 interface signs RSA and ECDSA only — EdDSA/Ed25519 is NOT available through PKCS#11.
    The production algorithm for this backend is therefore ECDSA P-384 (`alg=ALG_ECDSA_P384`,
    CKM_ECDSA_SHA384), which is also inside the module's FIPS-mode validated boundary. The
    Ed25519 setting remains for injected-session tests only.
    """

    def __init__(self, key_reference: str, *, lib_path: str | None = None, pin: str | None = None,
                 label: str = "regulated-evidence", key_version: str = "1",
                 created_at_us: int = 0, session: object | None = None,
                 alg: str = ALG_ECDSA_P384) -> None:
        if alg not in (ALG_ECDSA_P384, ALG_ED25519):
            raise ValueError(f"unsupported CloudHSM signing algorithm: {alg}")
        if alg == ALG_ED25519 and session is None:
            raise ValueError(
                "CloudHSM PKCS#11 does not support Ed25519; "
                "ALG_ED25519 is permitted only with an injected test session"
            )
        self._lib_path = lib_path
        self._pin = pin
        self._label = label
        self._session = session                     # injected in tests; opened lazily in production
        self.alg = alg
        self._custody = KeyCustody(
            "aws-cloudhsm", key_reference, key_version, created_at_us, algorithm=self.alg
        )

    @property
    def custody(self) -> KeyCustody:
        return self._custody

    def _open(self) -> Any:
        if self._session is not None:
            return self._session
        try:
            import pkcs11  # type: ignore[import-not-found]          # lazy: SDK box only
            lib = pkcs11.lib(self._lib_path)
            token = lib.get_tokens().__iter__().__next__()
            self._session = _Pkcs11Session(token.open(user_pin=self._pin), self._label, self.alg)
            return self._session
        except Exception as exc:                                     # any HSM trouble -> fail closed
            raise KmsUnavailable(f"CloudHSM unavailable: {exc}") from exc

    def sign(self, payload: bytes) -> bytes:
        try:
            return bytes(self._open().sign(self._label, payload))
        except KmsUnavailable:
            raise
        except Exception as exc:
            raise KmsUnavailable(f"CloudHSM signing failed: {exc}") from exc

    @property
    def public_key(self) -> bytes:
        try:
            return bytes(self._open().public_key_bytes(self._label))
        except KmsUnavailable:
            raise
        except Exception as exc:
            raise KmsUnavailable(f"CloudHSM public-key read failed: {exc}") from exc


class _Pkcs11Session:
    """Thin real-PKCS#11 session wrapper (exercised only on the SDK box, in the paid window)."""

    def __init__(
        self, session: Any, label: str, alg: str = ALG_ECDSA_P384
    ) -> None:
        if alg != ALG_ECDSA_P384:
            raise ValueError("the real CloudHSM PKCS#11 session supports only ECDSA P-384")
        self._s = session
        self._label = label
        self._alg = alg

    def sign(self, label: str, data: bytes) -> bytes:
        import pkcs11
        key = self._s.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, label=label)
        # PKCS#11 ECDSA returns raw r||s (2 x 48 bytes for P-384); the trust fabric verifies
        # DER-encoded (r,s) — the format cryptography and external verifiers expect.
        raw = key.sign(data, mechanism=pkcs11.Mechanism.ECDSA_SHA384)
        return _raw_rs_to_der(bytes(raw))

    def public_key_bytes(self, label: str) -> bytes:
        import pkcs11
        from pkcs11 import Attribute
        pub = self._s.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY, label=label)
        point = bytes(pub[Attribute.EC_POINT])
        # EC_POINT is a DER OCTET STRING wrapping the X9.62 uncompressed point
        # (0x04 || X || Y = 97 bytes for P-384); strip the DER header.
        if len(point) < 97 or point[-97] != 0x04:
            raise ValueError(f"unexpected P-384 EC_POINT encoding ({len(point)} bytes)")
        return point[-97:]


def _raw_rs_to_der(raw: bytes) -> bytes:
    """Convert a PKCS#11 raw r||s ECDSA signature to the DER (r,s) encoding."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(raw) != 96:
        raise ValueError(
            f"malformed P-384 signature: expected 96 raw r||s bytes, got {len(raw)}"
        )
    half = len(raw) // 2
    return encode_dss_signature(int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big"))


class AwsKmsBackend:
    """`SigningBackend` over an AWS KMS asymmetric key (sign-by-reference; the private key never
    leaves KMS). The MANAGED profile defaults to ECDSA P-384 (`ECC_NIST_P384` /
    `ECDSA_SHA_384`), an approved service in AWS KMS HSM security policy 140sp4884.
    Ed25519 remains an explicit compatibility option, but is not claimed as operating
    inside that validated boundary. Test path injects a boto3-shaped client.

    RAW mode keeps the KMS 4096-byte message limit. Explicit DIGEST mode is
    supported for ECDSA P-384 only: SHA384 hashes the original bytes once, then
    KMS signs that digest without hashing again. The existing public-key
    verifier still verifies the original bytes with ECDSA/SHA384. Mode never
    changes after a failure, and Ed25519 does not implicitly become Ed25519ph.
    """

    _SIGNING_ALGORITHM = {ALG_ED25519: "ED25519_SHA_512", ALG_ECDSA_P384: "ECDSA_SHA_384"}

    def __init__(self, key_reference: str, *, alg: str = ALG_ECDSA_P384, key_version: str = "1",
                 created_at_us: int = 0, region: str | None = None, client: object | None = None,
                 message_type: Literal["RAW", "DIGEST"] = "RAW") -> None:
        if message_type not in ("RAW", "DIGEST") or (
            message_type == "DIGEST" and alg != ALG_ECDSA_P384
        ):
            raise ValueError("KMS digest mode requires explicit ECDSA P-384")
        self._message_type = message_type
        if alg not in self._SIGNING_ALGORITHM:
            raise ValueError(f"unsupported KMS signing algorithm: {alg}")
        self._client = client                       # injected in tests; opened lazily in production
        self._key_ref = key_reference
        # Derive the region from the key ARN when not given, so the backend does not depend on
        # ambient AWS_DEFAULT_REGION (which is unset in bare SSM shells on the client box).
        self._region = region or self._region_from_arn(key_reference)
        self.alg = alg
        self._custody = KeyCustody(
            "aws-kms", key_reference, key_version, created_at_us, algorithm=self.alg
        )

    @staticmethod
    def _region_from_arn(key_reference: str) -> str | None:
        # arn:aws:kms:<region>:<account>:key/<id>
        parts = key_reference.split(":")
        return parts[3] if key_reference.startswith("arn:aws:kms:") and len(parts) > 3 else None

    @property
    def custody(self) -> KeyCustody:
        return self._custody

    def _c(self) -> Any:
        if self._client is None:
            try:
                import boto3                                         # lazy
                self._client = boto3.client("kms", region_name=self._region)
            except Exception as exc:
                raise KmsUnavailable(f"KMS client unavailable: {exc}") from exc
        return self._client

    def sign(self, payload: bytes) -> bytes:
        if self._message_type == "RAW" and len(payload) > 4096:
            raise KmsUnavailable(
                f"payload is {len(payload)} bytes; KMS MessageType=RAW accepts at most 4096")
        message = sha384(payload).digest() if self._message_type == "DIGEST" else payload
        try:
            resp = self._c().sign(KeyId=self._key_ref, Message=message,
                                  MessageType=self._message_type,
                                  SigningAlgorithm=self._SIGNING_ALGORITHM[self.alg])
            # Ed25519 -> raw 64-byte signature; ECDSA -> DER (r,s): both are exactly what the
            # trust fabric's verifier expects for the respective algorithm.
            return bytes(resp["Signature"])
        except KmsUnavailable:
            raise
        except Exception as exc:                                     # throttle, outage, denied -> fail closed
            raise KmsUnavailable(f"KMS signing failed: {exc}") from exc

    @property
    def public_key(self) -> bytes:
        try:
            der = self._c().get_public_key(KeyId=self._key_ref)["PublicKey"]
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            pub = load_der_public_key(der)
            if self.alg == ALG_ED25519:
                return bytes(
                    pub.public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                )
            return bytes(
                pub.public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
            )
        except KmsUnavailable:
            raise
        except Exception as exc:
            raise KmsUnavailable(f"KMS public-key read failed: {exc}") from exc


class S3ObjectLockWormStore:
    """`WormStore` over an S3 bucket with Object Lock enabled.

    GOVERNANCE retention by default (deletable with special permission after the window — correct
    for tests). Set `compliance=True` ONLY for real production retention: those locks are
    undeletable by anyone until expiry. The object key is content-addressed (sha256), so re-anchor
    of identical bytes is idempotent, mirroring LocalWormStore.

    Write-once is VERIFIED, not named (Paper A 4.3, claims row A12). Requesting a lock proves nothing: a bucket
    without Object Lock, or a policy that rewrites the mode, would accept the write and retain nothing. So after
    every write the store reads the stored version's own retention back, and the anchor fails closed unless that
    version carries exactly the requested mode until at least the requested date. `verify` rechecks the exact
    version a receipt names, its bytes and its retention. A write that returns no version is refused, because
    Object Lock requires versioning.
    """

    def __init__(self, bucket: str, *, prefix: str = "evidence", compliance: bool = False,
                 client: object | None = None) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._mode = "COMPLIANCE" if compliance else "GOVERNANCE"
        self._client = client                                        # injected in tests

    def _c(self) -> Any:
        if self._client is None:
            try:
                import boto3                                         # lazy
                self._client = boto3.client("s3")
            except Exception as exc:
                raise WormUnavailable(f"S3 client unavailable: {exc}") from exc
        return self._client

    def _key(self, tenant: str, digest: str) -> str:
        return f"{self._prefix}/{tenant}/{digest}"

    def anchor(self, tenant: str, data: bytes, *, retain_us: int, now_us: int) -> WormReceipt:
        digest = sha256(data).hexdigest()
        key = self._key(tenant, digest)
        # Object Lock responses may have whole-second precision. Round UP so
        # serialization cannot shorten the required retention by a fraction.
        if type(retain_us) is not int or retain_us <= 0 or type(now_us) is not int:
            raise WormUnavailable("retention requires positive integer microseconds and an integer timestamp")
        try:
            retained_seconds = (now_us + retain_us + 999_999) // 1_000_000
            retain_until = _dt.datetime.fromtimestamp(retained_seconds, tz=_dt.timezone.utc)
            resp = self._c().put_object(
                Bucket=self._bucket, Key=key, Body=data,
                ObjectLockMode=self._mode, ObjectLockRetainUntilDate=retain_until)
        except WormUnavailable:
            raise
        except Exception as exc:                                     # throttle, outage, denied -> fail closed
            raise WormUnavailable(f"S3 Object Lock anchor failed: {exc}") from exc
        version = resp.get("VersionId")
        if not isinstance(version, str) or not version:
            raise WormUnavailable("the bucket returned no object version: Object Lock requires versioning, "
                                  "so nothing is retained")
        problem = self._retention_problem(key, version, retain_until)
        if problem is not None:
            raise WormUnavailable(f"the stored object is not write-once as requested: {problem}")
        try:
            stored = bytes(self._c().get_object(Bucket=self._bucket, Key=key, VersionId=version)["Body"].read())
        except Exception as exc:
            raise WormUnavailable(f"the stored object cannot be read back: {type(exc).__name__}") from exc
        if sha256(stored).hexdigest() != digest:
            # The lock is only worth something over the right bytes (source review 3071).
            raise WormUnavailable("the stored object's bytes differ from the evidence written")
        return WormReceipt(provider="s3-object-lock", object_ref=f"s3://{self._bucket}/{key}",
                           content_digest=digest, retained_until_us=now_us + retain_us,
                           receipt_id=version, stored_at_us=now_us)

    def qualify(self) -> None:
        """Raise `WormUnavailable` unless the bucket itself is versioned with Object Lock enabled.

        A host calls this before it serves: a bucket that cannot lock would fail every anchor, and the operator
        should learn that at startup, from a stated reason, rather than at a clinician's first release."""
        try:
            versioning = self._c().get_bucket_versioning(Bucket=self._bucket).get("Status")
            lock = self._c().get_object_lock_configuration(Bucket=self._bucket)["ObjectLockConfiguration"]
        except WormUnavailable:
            raise
        except Exception as exc:
            raise WormUnavailable(f"evidence bucket cannot be qualified: {type(exc).__name__}") from exc
        if versioning != "Enabled" or lock.get("ObjectLockEnabled") != "Enabled":
            raise WormUnavailable("evidence bucket is not versioned with Object Lock enabled")

    def _retention_problem(self, key: str, version: str, at_least: _dt.datetime) -> str | None:
        """None if this exact stored version is locked in this store's mode until at least `at_least`."""
        try:
            retention = self._c().get_object_retention(Bucket=self._bucket, Key=key, VersionId=version)["Retention"]
            mode, until = retention["Mode"], retention["RetainUntilDate"]
        except Exception as exc:                                     # no lock, denied or unreadable: unproven
            return f"its retention cannot be read: {type(exc).__name__}"
        if mode != self._mode:
            return f"stored mode {mode!r}, requested {self._mode!r}"
        if not isinstance(until, _dt.datetime) or until.tzinfo is None or until < at_least:
            return f"retained until {until!r}, requested at least {at_least.isoformat()}"
        return None

    def fetch(self, tenant: str, object_ref: str) -> bytes:
        key = object_ref.split(f"s3://{self._bucket}/", 1)[-1]
        try:
            return bytes(
                self._c().get_object(Bucket=self._bucket, Key=key)["Body"].read()
            )
        except WormUnavailable:
            raise
        except Exception as exc:
            raise WormError(f"no WORM object {object_ref!r}: {exc}") from exc

    def verify(self, receipt: WormReceipt) -> bool:
        """True only if the exact version the receipt names still holds its bytes under the retention it claims."""
        key = receipt.object_ref.split(f"s3://{self._bucket}/", 1)[-1]
        try:
            body = self._c().get_object(Bucket=self._bucket, Key=key, VersionId=receipt.receipt_id)["Body"].read()
        except Exception:
            return False
        if sha256(bytes(body)).hexdigest() != receipt.content_digest:
            return False
        claimed = _dt.datetime.fromtimestamp(receipt.retained_until_us / 1_000_000, tz=_dt.timezone.utc)
        return self._retention_problem(key, receipt.receipt_id, claimed) is None


__all__ = [
    "AwsKmsBackend",
    "CloudHsmPkcs11Backend",
    "S3ObjectLockWormStore",
    "SigningProfile",
    "resolve_signing_profile",
]
