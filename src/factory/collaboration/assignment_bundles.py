"""Durable content-addressed assignment bundles and their execution pointers.

The byte store and metadata authority are deliberately separate: bundle bytes
are immutable objects, while PostgreSQL owns the small mutable lease head. The
directory materializer reconstructs objects from either local files or S3;
both runtime compositions use PostgreSQL metadata.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ROLE = frozenset({"author", "reviewer"})
_ACTIVE_STATES = frozenset({"claimed", "acknowledged"})
_ALL_STATES = _ACTIVE_STATES | {"completed", "stranded"}


class AssignmentBundleError(RuntimeError):
    """Bundle integrity, identity, or lease authority failed closed."""


def _text(name: str, value: str, maximum: int = 500) -> str:
    value = str(value).strip()
    if not value or len(value) > maximum:
        raise AssignmentBundleError(f"invalid {name}")
    return value


def _digest(value: str) -> str:
    if _DIGEST.fullmatch(str(value)) is None:
        raise AssignmentBundleError("invalid bundle digest")
    return str(value)


def _tenant_ref(tenant_id: str) -> str:
    return hashlib.sha256(_text("tenant_id", tenant_id).encode()).hexdigest()


def _transition_allowed(current: str, requested: str) -> bool:
    return requested in {
        "claimed": frozenset({"acknowledged", "stranded"}),
        "acknowledged": frozenset({"acknowledged", "completed", "stranded"}),
    }.get(current, frozenset())


@dataclass(frozen=True, slots=True)
class AssignmentBundleRef:
    digest: str
    size: int

    def __post_init__(self) -> None:
        _digest(self.digest)
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise AssignmentBundleError("invalid bundle size")


class AssignmentBundleStore(Protocol):
    def put(self, tenant_id: str, content: bytes) -> AssignmentBundleRef: ...

    def get(self, tenant_id: str, digest: str) -> bytes: ...


class FileAssignmentBundleStore:
    """Content-addressed local byte store; the default for local and EC2."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _path(self, tenant_id: str, digest: str) -> Path:
        return self._root / _tenant_ref(tenant_id) / "objects" / _digest(digest)

    def put(self, tenant_id: str, content: bytes) -> AssignmentBundleRef:
        if not isinstance(content, bytes):
            raise AssignmentBundleError("bundle content must be bytes")
        digest = hashlib.sha256(content).hexdigest()
        path = self._path(tenant_id, digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != content:
                raise AssignmentBundleError("bundle digest collision")
            return AssignmentBundleRef(digest, len(content))
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_bytes(content)
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != content:
                    raise AssignmentBundleError("bundle digest collision") from None
        finally:
            temporary.unlink(missing_ok=True)
        return AssignmentBundleRef(digest, len(content))

    def get(self, tenant_id: str, digest: str) -> bytes:
        try:
            content = self._path(tenant_id, digest).read_bytes()
        except OSError as exc:
            raise AssignmentBundleError("assignment bundle is unavailable") from exc
        if hashlib.sha256(content).hexdigest() != digest:
            raise AssignmentBundleError("assignment bundle failed integrity verification")
        return content


def _is_missing(exc: Exception) -> bool:
    response = getattr(exc, "response", {})
    if not isinstance(response, Mapping):
        return False
    error = response.get("Error", {})
    metadata = response.get("ResponseMetadata", {})
    code = error.get("Code") if isinstance(error, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return code in {"404", "NoSuchKey", "NotFound"} or status == 404


class S3AssignmentBundleStore:
    """Private encrypted S3 implementation with verified content identity."""

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "factory/collaboration-bundles",
        kms_key_id: str = "",
        region: str = "",
        client: Any = None,
    ) -> None:
        self._bucket = _text("bucket", bucket)
        self._prefix = prefix.strip(" /")
        self._kms_key_id = kms_key_id.strip()
        if client is None:
            import boto3

            client = boto3.client("s3", **({"region_name": region} if region else {}))
        self._client = client

    def _key(self, tenant_id: str, digest: str) -> str:
        return f"{self._prefix}/{_tenant_ref(tenant_id)}/sha256/{_digest(digest)}"

    def put(self, tenant_id: str, content: bytes) -> AssignmentBundleRef:
        if not isinstance(content, bytes):
            raise AssignmentBundleError("bundle content must be bytes")
        digest = hashlib.sha256(content).hexdigest()
        key = self._key(tenant_id, digest)
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            if not _is_missing(exc):
                raise AssignmentBundleError("assignment bundle lookup failed") from exc
        else:
            existing = self.get(tenant_id, digest)
            if existing != content:
                raise AssignmentBundleError("bundle digest collision")
            return AssignmentBundleRef(digest, len(content))
        encryption: dict[str, str] = {"ServerSideEncryption": "AES256"}
        if self._kms_key_id:
            encryption = {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": self._kms_key_id,
            }
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=content,
                IfNoneMatch="*",
                ChecksumSHA256=base64.b64encode(hashlib.sha256(content).digest()).decode(),
                Metadata={"sha256": digest},
                **encryption,
            )
        except Exception as exc:
            # A concurrent exact writer may win the conditional write.
            try:
                if self.get(tenant_id, digest) == content:
                    return AssignmentBundleRef(digest, len(content))
            except AssignmentBundleError:
                pass
            raise AssignmentBundleError("assignment bundle write failed") from exc
        return AssignmentBundleRef(digest, len(content))

    def get(self, tenant_id: str, digest: str) -> bytes:
        digest = _digest(digest)
        try:
            body = self._client.get_object(
                Bucket=self._bucket, Key=self._key(tenant_id, digest)
            )["Body"]
            content = bytes(body.read()) if hasattr(body, "read") else bytes(body)
        except Exception as exc:
            raise AssignmentBundleError("assignment bundle is unavailable") from exc
        finally:
            close = getattr(locals().get("body"), "close", None)
            if callable(close):
                close()
        if hashlib.sha256(content).hexdigest() != digest:
            raise AssignmentBundleError("assignment bundle failed integrity verification")
        return content

    def qualify(self) -> None:
        """Read-only proof of the managed bucket's durability and privacy floor."""

        versioning = self._client.get_bucket_versioning(Bucket=self._bucket)
        if versioning.get("Status") != "Enabled":
            raise AssignmentBundleError("assignment bundle bucket versioning is unavailable")
        encryption = self._client.get_bucket_encryption(Bucket=self._bucket)
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        algorithms = {
            rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            for rule in rules
        }
        if not algorithms.intersection({"AES256", "aws:kms"}):
            raise AssignmentBundleError("assignment bundle bucket encryption is unavailable")
        public = self._client.get_public_access_block(Bucket=self._bucket).get(
            "PublicAccessBlockConfiguration", {}
        )
        if not all(
            public.get(name) is True
            for name in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        ):
            raise AssignmentBundleError("assignment bundle bucket privacy is unavailable")


def encode_assignment_bundle(
    workspace: str | Path, *, max_files: int = 500, max_total_bytes: int = 20_000_000
) -> bytes:
    """Encode a deterministic, bounded, symlink-free assignment directory."""

    root = Path(workspace).resolve(strict=True)
    files: list[dict[str, str]] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AssignmentBundleError("assignment bundle contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in {".git", ".hg", ".svn"} for part in Path(relative).parts):
            raise AssignmentBundleError("assignment bundle contains VCS metadata")
        content = path.read_bytes()
        total += len(content)
        if len(files) >= max_files or total > max_total_bytes:
            raise AssignmentBundleError("assignment bundle exceeds its bound")
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "content": base64.b64encode(content).decode("ascii"),
            }
        )
    return json.dumps(
        {"version": 1, "files": files}, sort_keys=True, separators=(",", ":")
    ).encode()


def materialize_assignment_bundle(
    content: bytes,
    destination: str | Path,
    *,
    expected_digest: str,
    max_files: int = 500,
    max_total_bytes: int = 20_000_000,
) -> Path:
    """Verify and atomically recreate one assignment directory."""

    expected_digest = _digest(expected_digest)
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise AssignmentBundleError("assignment bundle failed integrity verification")
    try:
        raw = json.loads(content)
        entries = raw["files"]
        if raw.get("version") != 1 or not isinstance(entries, list):
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AssignmentBundleError("assignment bundle format is invalid") from exc
    if len(entries) > max_files:
        raise AssignmentBundleError("assignment bundle exceeds its bound")
    target = Path(destination).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_dir() and encode_assignment_bundle(
            target, max_files=max_files, max_total_bytes=max_total_bytes
        ) == content:
            return target
        raise AssignmentBundleError("assignment destination already has different content")
    stage = target.parent / f".{target.name}.{uuid.uuid4().hex}.staging"
    total = 0
    seen: set[str] = set()
    try:
        stage.mkdir()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "content"}:
                raise AssignmentBundleError("assignment bundle entry is invalid")
            relative = str(entry["path"])
            parts = Path(relative).parts
            if (
                not relative
                or Path(relative).is_absolute()
                or ".." in parts
                or any(part in {".git", ".hg", ".svn"} for part in parts)
                or relative in seen
            ):
                raise AssignmentBundleError("assignment bundle path is unsafe")
            seen.add(relative)
            try:
                payload = base64.b64decode(str(entry["content"]), validate=True)
            except (ValueError, binascii.Error) as exc:
                raise AssignmentBundleError("assignment bundle entry is invalid") from exc
            total += len(payload)
            if total > max_total_bytes or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
                raise AssignmentBundleError("assignment bundle entry failed integrity verification")
            output = stage.joinpath(*parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
        os.replace(stage, target)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return target


@dataclass(frozen=True, slots=True)
class AssignmentPointer:
    tenant_id: str
    run_id: str
    ticket_id: str
    role: str
    subject_digest: str
    bundle_digest: str
    created_at: float

    def __post_init__(self) -> None:
        for name in ("tenant_id", "run_id", "ticket_id"):
            _text(name, getattr(self, name))
        if self.role not in _SAFE_ROLE:
            raise AssignmentBundleError("invalid assignment role")
        _digest(self.subject_digest)
        _digest(self.bundle_digest)


@dataclass(frozen=True, slots=True)
class AssignmentAttempt:
    tenant_id: str
    run_id: str
    ticket_id: str
    attempt_id: str
    participant_id: str
    role: str
    bundle_digest: str
    attempt_number: int
    ack_deadline_at: float
    lease_expires_at: float
    state: str = "claimed"
    revision: int = 1

    def __post_init__(self) -> None:
        for name in ("tenant_id", "run_id", "ticket_id", "attempt_id", "participant_id"):
            _text(name, getattr(self, name))
        if self.role not in _SAFE_ROLE or self.state not in _ALL_STATES:
            raise AssignmentBundleError("invalid assignment attempt")
        _digest(self.bundle_digest)
        if self.attempt_number < 1 or self.revision < 1:
            raise AssignmentBundleError("invalid assignment attempt revision")
        if self.ack_deadline_at <= 0 or self.lease_expires_at <= self.ack_deadline_at:
            raise AssignmentBundleError("invalid assignment attempt lease")


class AssignmentBundleAuthority(Protocol):
    def publish(self, pointer: AssignmentPointer) -> AssignmentPointer: ...

    def pointer(
        self, tenant_id: str, run_id: str, ticket_id: str, role: str, subject_digest: str
    ) -> AssignmentPointer | None: ...

    def claim(self, attempt: AssignmentAttempt) -> AssignmentAttempt: ...

    def attempt(self, tenant_id: str, attempt_id: str) -> AssignmentAttempt | None: ...

    def transition(
        self, tenant_id: str, attempt_id: str, *, expected_revision: int,
        state: str, lease_expires_at: float | None = None,
    ) -> AssignmentAttempt: ...


def build_assignment_bundle_store(
    root: str | Path, *, env: Mapping[str, str] = os.environ, client: Any = None
) -> AssignmentBundleStore:
    mode = env.get("FACTORY_COLLABORATION_BUNDLE_STORE", "file").strip().lower()
    if mode in {"", "file"}:
        return FileAssignmentBundleStore(Path(root) / "objects")
    if mode != "s3":
        raise RuntimeError("FACTORY_COLLABORATION_BUNDLE_STORE must be file or s3")
    bucket = env.get("FACTORY_COLLABORATION_BUNDLES_BUCKET", "").strip()
    if not bucket:
        raise RuntimeError("S3 collaboration bundles require FACTORY_COLLABORATION_BUNDLES_BUCKET")
    return S3AssignmentBundleStore(
        bucket,
        prefix=env.get("FACTORY_COLLABORATION_BUNDLES_PREFIX", "factory/collaboration-bundles"),
        kms_key_id=env.get("FACTORY_ARTIFACTS_KMS_KEY_ID", ""),
        region=(env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "").strip(),
        client=client,
    )


#: One pool per DSN for this package's metadata authority. Before 2026-09-22 every build opened a fresh
#: pool that nothing could close, so each composed Hub left up to four connections open for the idle
#: window; a test run composing many Hubs exhausted PostgreSQL's 100 clients ("too many clients already").
_OWN_POOLS: dict[str, Any] = {}
_OWN_POOLS_LOCK = threading.Lock()


def _bundle_pool(dsn: str) -> Any:
    """The shared pool for ``dsn``, opened on first use and reopened if it was closed."""
    with _OWN_POOLS_LOCK:
        pool = _OWN_POOLS.get(dsn)
        if pool is None or getattr(pool, "closed", False):
            from psycopg_pool import ConnectionPool

            # Laws 12+17 admit only factory.tenant here, so this package cannot use
            # factory.pg_pool; it states the same footprint contract inline (min_size=0,
            # bounded idle) and the tree-scan test in tests/test_pg_pool.py holds it to that.
            pool = ConnectionPool(
                dsn, min_size=0, max_size=4, open=True, max_idle=120.0,
                kwargs={"autocommit": True},
            )
            _OWN_POOLS[dsn] = pool
        return pool


def close_bundle_pools_for(dsn: str, *, timeout: float = 5.0) -> int:
    """Close this package's pool for exactly ``dsn``; returns how many were closed (0 or 1).

    For a caller that owns a disposable database, such as a per-test schema, and must leave the server's
    connections as it found them - the counterpart of factory.pg_pool.close_pools_for."""
    with _OWN_POOLS_LOCK:
        pool = _OWN_POOLS.pop(dsn, None)
    if pool is None:
        return 0
    pool.close(timeout=timeout)
    return 1


def build_assignment_bundle_authority(
    root: str | Path, *, env: Mapping[str, str] = os.environ, pool: Any = None
) -> AssignmentBundleAuthority:
    """Require PostgreSQL metadata in every runtime environment."""

    mode = env.get("FACTORY_COLLABORATION_BUNDLE_METADATA", "").strip().lower()
    if mode != "pg":
        raise RuntimeError("FACTORY_COLLABORATION_BUNDLE_METADATA must be pg")
    schema_mode = env.get("FACTORY_PRODUCT_SCHEMA_MODE", "").strip()
    if schema_mode not in {"bootstrap-on-start", "external-migration-task"}:
        raise RuntimeError(
            "PostgreSQL collaboration bundle metadata requires "
            "FACTORY_PRODUCT_SCHEMA_MODE=bootstrap-on-start or external-migration-task"
        )
    if pool is None:
        dsn = env.get("FACTORY_DB_URL", "").strip()
        if not dsn:
            raise RuntimeError("PostgreSQL collaboration bundle metadata requires FACTORY_DB_URL")
        pool = _bundle_pool(dsn)
    from factory.collaboration.assignment_bundles_pg import (
        PostgresAssignmentBundleAuthority,
    )

    if schema_mode == "bootstrap-on-start":
        from factory.collaboration.assignment_bundles_pg import apply_assignment_bundle_migration

        apply_assignment_bundle_migration(pool=pool)
    return PostgresAssignmentBundleAuthority(pool)
