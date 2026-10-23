"""Transactional Postgres activation authority using the memory transition engine.

One row per pack contains history, revocations, tenant pins and retry receipts. Every
operation takes a transaction advisory lock BEFORE reading the row (including first
insert): shared for reads, exclusive for writes. No process cache can outlive a revocation.
Different packs do not share a lock. A checksum and structural validation detect corruption; they do not
claim to resist a privileged database writer who can recompute the checksum.

Call migrate only from the managed migration task. Inject this ledger into PackRegistry.
Supply idempotency_key for retryable writes, especially rollback: a replay returns the
original response even if later operations changed the active version. Keys are scoped
to pack and retained with its history; reusing a key for different arguments is refused.
"""
from __future__ import annotations

import atexit
import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, cast

from regulated_core.governance_guard import GovernanceGuard

from factory.pg_pool import open_pool
from factory.pg_session import SessionBoundPool

from .lifecycle import (STATES, ActivationLedger, ActivationRecord, DependencyRequirements, LifecycleError,
                        GovernanceReceipt, dependency_requirements, governance_receipt_key)

SCHEMA_VERSION = 1
SCHEMA_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS pack_lifecycle_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""
SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS pack_lifecycle (
    pack_id TEXT PRIMARY KEY,
    revision BIGINT NOT NULL CHECK (revision > 0),
    payload JSONB NOT NULL,
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 64)
);
"""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(pack_id: str, revision: int, payload: Any) -> str:
    return hashlib.sha256(_canonical([pack_id, revision, payload]).encode()).hexdigest()


def _snapshot(ledger: ActivationLedger, pack_id: str, requests: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": 1,
        "records": [asdict(r) for r in ledger.history(pack_id)],
        "active": ledger._active.get(pack_id),
        "revoked": sorted(ledger._revoked),
        "pins": {tenant: version for (tenant, pack), version in ledger._pins.items() if pack == pack_id},
        "requests": requests,
        "governance_receipts": sorted(ledger._governance_receipts.get(pack_id, set())),
    }


def _restore(pack_id: str, raw: Any) -> ActivationLedger:
    """Refuse inconsistent authority even when a checksum was recomputed."""
    ledger = ActivationLedger()
    try:
        required = {"format", "records", "active", "revoked", "pins", "requests"}
        if not isinstance(raw, dict) or not required <= set(raw) or set(raw) - required - {"governance_receipts"}:
            raise ValueError("invalid snapshot fields")
        if raw["format"] != 1 or not isinstance(raw["records"], list):
            raise ValueError("unsupported snapshot format")
        if not isinstance(raw["revoked"], list) or not isinstance(raw["pins"], dict) or not isinstance(raw["requests"], dict):
            raise ValueError("invalid authority maps")
        known: set[str] = set()
        versions: dict[str, str] = {}
        active_ids = []
        for ordinal, value in enumerate(raw["records"]):
            record = ActivationRecord(**value)
            if any(not isinstance(v, str) for v in asdict(record).values()):
                raise ValueError("non-string record")
            expected = hashlib.sha256(
                f"{pack_id}#{record.version}|{record.pack_digest}|{record.previous_activation_id}|{ordinal}".encode()
            ).hexdigest()[:24]
            if record.pack_id != pack_id or record.activation_id != expected or record.activation_id in known:
                raise ValueError("record identity mismatch")
            if record.state not in STATES or (record.previous_activation_id and record.previous_activation_id not in known):
                raise ValueError("invalid state or predecessor")
            if record.version in versions and versions[record.version] != record.pack_digest:
                raise ValueError("version digest changed")
            versions[record.version] = record.pack_digest
            known.add(record.activation_id)
            ledger._records[record.activation_id] = record
            ledger._history.setdefault(pack_id, []).append(record.activation_id)
            if record.state == "active":
                active_ids.append(record.activation_id)
        if any(not isinstance(v, str) or not v.startswith(pack_id + "#") for v in raw["revoked"]):
            raise ValueError("invalid revocation scope")
        ledger._revoked = set(raw["revoked"])
        if any(r.state == "revoked" and not ledger.is_revoked(pack_id, r.version) for r in ledger.history(pack_id)):
            raise ValueError("revoked record missing its version revocation")
        if active_ids != ([] if raw["active"] is None else [raw["active"]]):
            raise ValueError("active pointer mismatch")
        if raw["active"] is not None:
            active = ledger._records[raw["active"]]
            if ledger._history[pack_id][-1] != active.activation_id:
                raise ValueError("active record is not the latest activation")
            if ledger.is_revoked(pack_id, active.version):
                raise ValueError("revoked active version")
            ledger._active[pack_id] = active.activation_id
        for tenant, version in raw["pins"].items():
            if not isinstance(tenant, str) or not tenant or not isinstance(version, str) or not version:
                raise ValueError("invalid tenant pin")
            ledger._pins[(tenant, pack_id)] = version
        receipts = raw.get("governance_receipts", [])
        if not isinstance(receipts, list):
            raise ValueError("invalid governance receipts")
        keys = [governance_receipt_key(item) for item in receipts]
        if len({key[:3] for key in keys}) != len(keys):
            raise ValueError("duplicate governance operation")
        ledger._governance_receipts[pack_id] = set(keys)
        for key, receipt in raw["requests"].items():
            if not isinstance(key, str) or not key or set(receipt) != {"request", "result"}:
                raise ValueError("invalid retry receipt")
            _decode(receipt["result"])
        return ledger
    except (TypeError, KeyError, ValueError, AttributeError) as exc:
        raise LifecycleError(f"{pack_id}: stored lifecycle failed integrity: {exc}") from exc


def _encode(value: Any) -> Any:
    if isinstance(value, ActivationRecord):
        return {"record": asdict(value)}
    if isinstance(value, tuple):
        return {"tuple": [_encode(v) for v in value]}
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"record"}:
            return ActivationRecord(**value["record"])
        if set(value) == {"tuple"}:
            return tuple(_decode(v) for v in value["tuple"])
        raise ValueError("invalid retry result")
    return value


class PostgresActivationLedger(ActivationLedger):
    durable = True
    migration_transactional = True
    migration_idempotent = True

    def __init__(self, dsn: str, *, max_size: int = 2, pool: Any = None,
                 guard: GovernanceGuard | None = None) -> None:
        self._governance_guard = guard
        self._closed = False
        self._owns_pool = pool is None
        self._pool = pool if pool is not None else open_pool(dsn, max_size=max_size, autocommit=True, name="pack-lifecycle")
        if self._owns_pool:
            atexit.register(self.close)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._owns_pool:
                self._pool.close()

    def migrate(self) -> None:
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("pack-lifecycle-schema",))
            conn.execute(SCHEMA_BOOTSTRAP)
            row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM pack_lifecycle_schema_migrations").fetchone()
            current = 0 if row is None else int(row[0])
            if current > SCHEMA_VERSION:
                raise LifecycleError("database pack-lifecycle schema is newer than this application")
            if current < 1:
                conn.execute(SCHEMA_V1)
                conn.execute("INSERT INTO pack_lifecycle_schema_migrations(version) VALUES (%s)", (1,))

    def _invoke(self, pack_id: str, method: str, args: tuple[Any, ...], kwargs: dict[str, Any],
                *, write: bool = False, idempotency_key: str | None = None,
                before_commit: Callable[[], None] | None = None) -> Any:
        if write:
            self._require_governance(pack_id)
        # Preserve pre-CAS durable idempotency request fingerprints when guards are not supplied.
        kwargs = {key: value for key, value in kwargs.items() if value is not None}
        if not isinstance(pack_id, str) or not pack_id or "#" in pack_id:
            raise LifecycleError("pack_id must be nonempty and cannot contain '#'")
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 200):
            raise LifecycleError("idempotency_key must be a nonempty string of at most 200 characters")
        dependencies = dependency_requirements(pack_id, kwargs.get("required_dependencies", ()))
        if dependencies:
            kwargs["required_dependencies"] = dependencies
        with self._pool.connection() as conn, conn.transaction():
            lock_sql = ("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))" if write
                        else "SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))")
            base_reference = kwargs.get("required_base_reference")
            base_id = base_reference.partition("#")[0] if base_reference else pack_id
            for lock_id in sorted({pack_id, base_id} | {ref.partition("#")[0] for ref, _ in dependencies}):
                conn.execute(lock_sql, ("pack-lifecycle:" + lock_id,))
            if base_reference and not self._stored_base_matches(conn, base_reference):
                raise LifecycleError("required base is not active")
            if not self._stored_dependencies_match(conn, dependencies):
                raise LifecycleError("required dependency is not active at its pinned digest")
            row = conn.execute("SELECT revision, payload, state_digest FROM pack_lifecycle WHERE pack_id = %s", (pack_id,)).fetchone()
            revision = 0
            requests: dict[str, Any] = {}
            ledger = ActivationLedger()
            if row is not None:
                revision, payload, digest = row
                try:
                    payload = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
                    if type(revision) is not int or revision < 1 or _digest(pack_id, revision, payload) != digest:
                        raise ValueError("checksum mismatch")
                except (ValueError, TypeError) as exc:
                    raise LifecycleError(f"{pack_id}: stored lifecycle failed integrity") from exc
                ledger = _restore(pack_id, payload)
                requests = payload["requests"]
            request = _canonical([method, args, kwargs])
            if idempotency_key in requests:
                receipt = requests[idempotency_key]
                if receipt["request"] != request:
                    raise LifecycleError("idempotency key reused with different lifecycle arguments")
                return _decode(receipt["result"])
            # The cross-pack base was verified above while both transaction locks are held.
            call_kwargs = {key: value for key, value in kwargs.items()
                           if key not in {"required_base_reference", "required_dependencies"}}
            # This temporary transition validates prior state without touching durable state.
            # The real authority callback must run after serialization, at the SQL write.
            result = getattr(ledger, method)(*args, **call_kwargs)
            if write:
                if idempotency_key is not None:
                    requests[idempotency_key] = {"request": request, "result": _encode(result)}
                payload = _snapshot(ledger, pack_id, requests)
                revision += 1
                encoded = _canonical(payload)
                digest = _digest(pack_id, revision, payload)
                if before_commit is not None:
                    before_commit()
                conn.execute(
                    "INSERT INTO pack_lifecycle(pack_id, revision, payload, state_digest) VALUES (%s, %s, %s::jsonb, %s)"
                    " ON CONFLICT (pack_id) DO UPDATE SET revision = EXCLUDED.revision, payload = EXCLUDED.payload,"
                    " state_digest = EXCLUDED.state_digest",
                    (pack_id, revision, encoded, digest),
                )
            return result

    def governance_receipt(self, pack_id: str, receipt: GovernanceReceipt) -> bool:
        key = governance_receipt_key(receipt)
        return bool(self._invoke(pack_id, "governance_receipt", (pack_id, key), {}))

    def active(self, pack_id: str) -> ActivationRecord | None:
        return cast(ActivationRecord | None, self._invoke(pack_id, "active", (pack_id,), {}))

    @contextmanager
    def resolution_guard(self, tenant_id: str, pack_id: str, *, required_base_reference: str | None = None,
                         required_dependencies: DependencyRequirements = ()) -> Iterator[ActivationRecord | None]:
        """Serialize revocation against a local decision.

        An explicitly composed SessionBoundPool keeps session advisory locks
        across independently committed store operations on ONE connection.
        The legacy injected-pool path keeps its transaction guard; it alone does
        not qualify nested store operations under a bounded shared pool.
        """
        dependencies = dependency_requirements(pack_id, required_dependencies)
        base_id = required_base_reference.partition("#")[0] if required_base_reference else pack_id
        lock_ids = sorted({pack_id, base_id} | {ref.partition("#")[0] for ref, _ in dependencies})
        if isinstance(self._pool, SessionBoundPool):
            with self._pool.session() as conn:
                locked: list[str] = []
                try:
                    for lock_id in lock_ids:
                        try:
                            conn.execute("SELECT pg_advisory_lock_shared(hashtextextended(%s, 0))", ("pack-lifecycle:" + lock_id,))
                        except BaseException:
                            # A cancelled/failed response can leave acquisition
                            # uncertain. Discard the session, never pool its lock.
                            conn.close()
                            raise
                        locked.append(lock_id)
                    with conn.transaction():
                        record = self._guard_record(conn, tenant_id, pack_id, required_base_reference, dependencies)
                    yield record
                finally:
                    # Session locks survive transaction commit/rollback. Return
                    # the connection only after every acquired lock is released.
                    try:
                        if not conn.closed:
                            conn.rollback()
                            for lock_id in reversed(locked):
                                unlocked = conn.execute("SELECT pg_advisory_unlock_shared(hashtextextended(%s, 0))",
                                                        ("pack-lifecycle:" + lock_id,)).fetchone()
                                if unlocked != (True,):
                                    raise LifecycleError("pack lifecycle session lock was lost")
                    except BaseException:
                        conn.close()
                        raise
            return
        with self._pool.connection() as conn, conn.transaction():
            for lock_id in lock_ids:
                conn.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))", ("pack-lifecycle:" + lock_id,))
            yield self._guard_record(conn, tenant_id, pack_id, required_base_reference, dependencies)

    def _guard_record(self, conn: Any, tenant_id: str, pack_id: str,
                      required_base_reference: str | None,
                      dependencies: DependencyRequirements = ()) -> ActivationRecord | None:
        if required_base_reference and not self._stored_base_matches(conn, required_base_reference):
            return None
        if not self._stored_dependencies_match(conn, dependencies, tenant_id):
            return None
        row = conn.execute("SELECT revision, payload, state_digest FROM pack_lifecycle WHERE pack_id = %s", (pack_id,)).fetchone()
        if row is None:
            return None
        revision, payload, digest = row
        payload = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
        if _digest(pack_id, revision, payload) != digest:
            raise LifecycleError(f"{pack_id}: stored lifecycle failed integrity")
        return _restore(pack_id, payload).resolve_record(tenant_id, pack_id)

    @staticmethod
    def _stored_dependencies_match(conn: Any, dependencies: DependencyRequirements,
                                   tenant_id: str | None = None) -> bool:
        for reference, expected_digest in dependencies:
            ident = reference.partition("#")[0]
            row = conn.execute("SELECT revision, payload, state_digest FROM pack_lifecycle WHERE pack_id = %s",
                               (ident,)).fetchone()
            if row is None:
                return False
            revision, payload, digest = row
            payload = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
            if _digest(ident, revision, payload) != digest:
                raise LifecycleError("dependency lifecycle failed integrity")
            ledger = _restore(ident, payload)
            record = ledger.active(ident) if tenant_id is None else ledger.resolve_record(tenant_id, ident)
            if record is None or record.reference != reference or record.pack_digest != expected_digest:
                return False
        return True

    @staticmethod
    def _stored_base_matches(conn: Any, reference: str) -> bool:
        base_id = reference.partition("#")[0]
        row = conn.execute("SELECT revision, payload, state_digest FROM pack_lifecycle WHERE pack_id = %s", (base_id,)).fetchone()
        if row is None:
            return False
        revision, payload, digest = row
        payload = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
        if _digest(base_id, revision, payload) != digest:
            raise LifecycleError("base lifecycle failed integrity")
        current = _restore(base_id, payload).active(base_id)
        return current is not None and current.reference == reference

    def pack_ids(self) -> tuple[str, ...]:
        """Every pack with a durable lifecycle row, whether or not it is still in the deployment catalog."""
        with self._pool.connection() as conn:
            rows = conn.execute("SELECT pack_id FROM pack_lifecycle ORDER BY pack_id").fetchall()
        return tuple(str(row[0]) for row in rows)

    def history(self, pack_id: str) -> tuple[ActivationRecord, ...]:
        return cast(tuple[ActivationRecord, ...], self._invoke(pack_id, "history", (pack_id,), {}))

    def is_revoked(self, pack_id: str, version: str) -> bool:
        return bool(self._invoke(pack_id, "is_revoked", (pack_id, version), {}))

    def pinned(self, tenant_id: str, pack_id: str) -> str | None:
        return cast(str | None, self._invoke(pack_id, "pinned", (tenant_id, pack_id), {}))

    def resolve(self, tenant_id: str, pack_id: str) -> str | None:
        return cast(str | None, self._invoke(pack_id, "resolve", (tenant_id, pack_id), {}))

    def resolve_record(self, tenant_id: str, pack_id: str) -> ActivationRecord | None:
        return cast(ActivationRecord | None, self._invoke(pack_id, "resolve_record", (tenant_id, pack_id), {}))

    def activate(self, pack_id: str, version: str, pack_digest: str, *, at: str, reason: str = "",
                 idempotency_key: str | None = None, expected_activation_id: str | None = None,
                 required_base_reference: str | None = None,
                 required_dependencies: DependencyRequirements = (), approved_prior: str | None = None,
                 before_commit: Callable[[], None] | None = None,
                 receipt: GovernanceReceipt | None = None, first_state_only: bool = False) -> ActivationRecord:
        dependencies = dependency_requirements(pack_id, required_dependencies)
        # Replayed on the durable snapshot inside this transaction, so the first-ever check reads committed history.
        return cast(ActivationRecord, self._invoke(pack_id, "activate", (pack_id, version, pack_digest),
                    {"at": at, "reason": reason, "expected_activation_id": expected_activation_id,
                     "required_base_reference": required_base_reference, "approved_prior": approved_prior, "receipt": receipt,
                     **({"required_dependencies": dependencies} if dependencies else {}),
                     **({"first_state_only": True} if first_state_only else {})},
                    write=True, idempotency_key=idempotency_key, before_commit=before_commit))

    def rollback(self, pack_id: str, *, at: str, reason: str, idempotency_key: str | None = None,
                 expected_activation_id: str | None = None, expected_target_reference: str | None = None,
                 approved_prior: str | None = None, before_commit: Callable[[], None] | None = None,
                 receipt: GovernanceReceipt | None = None) -> ActivationRecord:
        return cast(ActivationRecord, self._invoke(pack_id, "rollback", (pack_id,),
                    {"at": at, "reason": reason, "expected_activation_id": expected_activation_id,
                     "expected_target_reference": expected_target_reference,
                     "approved_prior": approved_prior, "receipt": receipt},
                    write=True, idempotency_key=idempotency_key, before_commit=before_commit))

    def revoke(self, pack_id: str, version: str, *, at: str, reason: str,
               idempotency_key: str | None = None, fallback_reference: str | None = None,
               expected_activation_id: str | None = None, approved_prior: str | None = None,
               before_commit: Callable[[], None] | None = None, receipt: GovernanceReceipt | None = None
               ) -> tuple[ActivationRecord | None, ActivationRecord | None]:
        return cast(tuple[ActivationRecord | None, ActivationRecord | None], self._invoke(
            pack_id, "revoke", (pack_id, version), {"at": at, "reason": reason, "fallback_reference": fallback_reference,
                                                  "expected_activation_id": expected_activation_id,
                                                  "approved_prior": approved_prior, "receipt": receipt},
            write=True, idempotency_key=idempotency_key, before_commit=before_commit))

    def pin(self, tenant_id: str, pack_id: str, version: str, *, idempotency_key: str | None = None,
            expected_activation_id: str | None = None, approved_prior: str | None = None,
            before_commit: Callable[[], None] | None = None, receipt: GovernanceReceipt | None = None) -> None:
        self._invoke(pack_id, "pin", (tenant_id, pack_id, version),
                     {"expected_activation_id": expected_activation_id, "approved_prior": approved_prior, "receipt": receipt},
                     write=True, idempotency_key=idempotency_key, before_commit=before_commit)

    def unpin(self, tenant_id: str, pack_id: str, *, idempotency_key: str | None = None) -> None:
        self._invoke(pack_id, "unpin", (tenant_id, pack_id), {}, write=True, idempotency_key=idempotency_key)
