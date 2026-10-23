"""Tenant-partitioned reference adapter; the only qualified lifecycle store since candidate 060 (B-F7b).

The original memory transition validator, public API and session resolution
guard are reused. Installation authority stays shared. Private state is loaded
only for the named governance tenant and, for pins, the explicit target tenant.
No migration is performed by construction or by a runtime method.
"""
from __future__ import annotations

import json
from copy import deepcopy

from assurance_reference.lifecycle_migration import _scope, private_digest
from assurance_reference.lifecycle_partition import (
    _empty_scope, _hash, partition_snapshot, request_tenant, restore_partition,
)
from factory.packs.lifecycle import ActivationLedger, LifecycleError, dependency_requirements, governance_receipt_key
from factory.packs.lifecycle_pg import PostgresActivationLedger, _canonical, _decode, _digest, _encode, _restore, _snapshot
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.governance_transaction import run_governance_check


def _key_digest(pack: str, key: str) -> str:
    return _hash(["reference/lifecycle-retry-key/v1", pack, key])


def _json(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else deepcopy(value)


def _checked_row(pack, row, *, tenant=None, private=False):
    revision, raw, checksum = row
    try:
        payload = _json(raw)
        expected = private_digest(pack, tenant, revision, payload) if private else _digest(pack, revision, payload)
        if type(revision) is not int or revision < 1 or checksum != expected:
            raise ValueError("checksum or revision mismatch")
        return revision, payload
    except (TypeError, ValueError) as exc:
        raise LifecycleError(f"{pack}: partitioned lifecycle failed integrity") from exc


def _load(conn, pack, tenant, *, installation_retries=False):
    """Read shared authority and at most one tenant, inside the caller's lock."""
    # First insertion also needs an explicit scope, before any receiving write.
    if tenant is not None:
        _scope(conn, tenant)
    row = conn.execute("SELECT revision,payload,state_digest FROM reference_pack_shared_v1 WHERE pack_id=%s",
                       (pack,)).fetchone()
    if row is None:
        return 0, _snapshot(ActivationLedger(), pack, {})
    revision, shared = _checked_row(pack, row)
    scopes = {}
    if tenant is not None:
        private = conn.execute("SELECT revision,payload,state_digest FROM reference_pack_tenants_v1 "
                               "WHERE pack_id=%s AND tenant_id=%s", (pack, tenant)).fetchone()
        if private is not None:
            private_revision, scope = _checked_row(pack, private, tenant=tenant, private=True)
            if private_revision > revision:
                raise LifecycleError("private lifecycle revision is ahead of shared authority")
            scopes[tenant] = scope
    elif installation_retries:
        private = conn.execute("SELECT revision,requests,state_digest FROM reference_pack_installation_retries_v1 "
                               "WHERE pack_id=%s", (pack,)).fetchone()
        if private is not None:
            private_revision, requests = _checked_row(pack, private, private=True)
            if private_revision > revision:
                raise LifecycleError("installation retry revision is ahead of shared authority")
            scopes[None] = {**_empty_scope(), "requests": requests}
    try:
        local_index = {
            _key_digest(pack, key): _hash(receipt["request"])
            for scope in scopes.values() for key, receipt in scope["requests"].items()
        }
        payload = restore_partition(pack, {"shared": shared, "scopes": scopes, "retry_index": local_index})
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise LifecycleError(f"{pack}: malformed partitioned lifecycle") from exc
    return revision, payload


def _merge_scoped_views(pack, first, second):
    """Combine two explicitly named scopes for an original cross-tenant pin.

    This is a governed write helper, not a tenant read API. Independent shared
    reads must agree under the caller's pack lock; private maps cannot overlap.
    """
    left, right = partition_snapshot(pack, first), partition_snapshot(pack, second)
    if _canonical(left["shared"]) != _canonical(right["shared"]):
        raise LifecycleError("shared lifecycle changed inside its locked transition")
    if set(left["scopes"]) & set(right["scopes"]) or set(left["retry_index"]) & set(right["retry_index"]):
        raise LifecycleError("overlapping private lifecycle scopes or pack-wide retry keys")
    return restore_partition(pack, {"shared": left["shared"],
        "scopes": {**left["scopes"], **right["scopes"]},
        "retry_index": {**left["retry_index"], **right["retry_index"]}})


class _LegacyReadView:
    """Supply validated scoped rows to the unchanged cross-pack validators.

    This accepts one exact read statement; it is not a general SQL translator.
    The synthetic checksum describes only the in-memory view, never a DB row.
    """
    def __init__(self, connection, tenant):
        self.connection = connection
        self.tenant = tenant

    def execute(self, query, params):
        if query != "SELECT revision, payload, state_digest FROM pack_lifecycle WHERE pack_id = %s":
            raise LifecycleError("unexpected legacy validator query")
        pack, = params
        revision, payload = _load(self.connection, pack, self.tenant)
        row = None if revision == 0 else (revision, payload, _digest(pack, revision, payload))

        class Result:
            def fetchone(self):
                return row

        return Result()


class PartitionedActivationLedger(PostgresActivationLedger):
    """Reference storage replacement. Requires the explicit owner migration."""

    def __init__(self, dsn, *, guard: GovernanceGuard, max_size=2, pool=None):
        if not isinstance(guard, GovernanceGuard):
            raise TypeError("partitioned reference lifecycle requires GovernanceGuard")
        super().__init__(dsn, guard=guard, max_size=max_size, pool=pool)

    def migrate(self):
        raise LifecycleError("partitioned lifecycle requires explicit owner migration")

    @staticmethod
    def _stored_base_matches(conn, reference):
        return PostgresActivationLedger._stored_base_matches(_LegacyReadView(conn, None), reference)

    @staticmethod
    def _stored_dependencies_match(conn, dependencies, tenant_id=None):
        return PostgresActivationLedger._stored_dependencies_match(
            _LegacyReadView(conn, tenant_id), dependencies, tenant_id)

    def _guard_record(self, conn, tenant_id, pack_id, required_base_reference, dependencies=()):
        if required_base_reference and not self._stored_base_matches(conn, required_base_reference):
            return None
        if not self._stored_dependencies_match(conn, dependencies, tenant_id):
            return None
        _, payload = _load(conn, pack_id, tenant_id)
        return _restore(pack_id, payload).resolve_record(tenant_id, pack_id)

    def pack_ids(self):
        with self._pool.connection() as conn:
            rows = conn.execute("SELECT pack_id FROM reference_pack_shared_v1 ORDER BY pack_id").fetchall()
        return tuple(str(row[0]) for row in rows)

    def _invoke(self, pack_id, method, args, kwargs, *, write=False, idempotency_key=None, before_commit=None):
        if write:
            self._require_governance(pack_id)
        kwargs = {key: value for key, value in kwargs.items() if value is not None}
        if not isinstance(pack_id, str) or not pack_id or "#" in pack_id:
            raise LifecycleError("pack_id must be nonempty and cannot contain '#'")
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key
                                             or len(idempotency_key) > 200):
            raise LifecycleError("idempotency_key must be a nonempty string of at most 200 characters")
        dependencies = dependency_requirements(pack_id, kwargs.get("required_dependencies", ()))
        if dependencies:
            kwargs["required_dependencies"] = dependencies
        request = _canonical([method, args, kwargs])
        if write:
            tenant = request_tenant(pack_id, request)
        elif method in {"pinned", "resolve", "resolve_record"}:
            tenant = args[0]
            if not isinstance(tenant, str) or not tenant:
                raise LifecycleError("explicit lifecycle tenant required")
        elif method == "governance_receipt":
            tenant = governance_receipt_key(args[1])[0]
        else:
            tenant = None
        selected_scopes = (tenant,)
        if write and method == "pin" and args[0] != tenant:
            selected_scopes = tuple(sorted({tenant, args[0]}))
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
            revision, payload = _load(conn, pack_id, tenant, installation_retries=write and tenant is None)
            if len(selected_scopes) == 2:
                target_revision, target_payload = _load(conn, pack_id, args[0])
                if target_revision != revision:
                    raise LifecycleError("shared lifecycle revision changed inside its locked transition")
                payload = _merge_scoped_views(pack_id, payload, target_payload)
            ledger = _restore(pack_id, payload)
            requests = payload["requests"]
            if write:
                # Shared digests preserve the ORIGINAL pack-wide retry namespace.
                # A foreign request/result is never loaded to resolve a collision.
                index = dict(conn.execute("SELECT key_digest,request_digest FROM reference_pack_retry_index_v1 "
                                          "WHERE pack_id=%s", (pack_id,)))
                for key, receipt in requests.items():
                    if index.get(_key_digest(pack_id, key)) != _hash(receipt["request"]):
                        raise LifecycleError("retained lifecycle retry is missing its exact shared index")
                if idempotency_key is not None and _key_digest(pack_id, idempotency_key) in index:
                    if index[_key_digest(pack_id, idempotency_key)] != _hash(request):
                        raise LifecycleError("idempotency key reused with different lifecycle arguments")
                    if idempotency_key not in requests:
                        raise LifecycleError("lifecycle retry index has no visible matching receipt")
            if idempotency_key in requests:
                receipt = requests[idempotency_key]
                if receipt["request"] != request:
                    raise LifecycleError("idempotency key reused with different lifecycle arguments")
                return _decode(receipt["result"])
            call_kwargs = {key: value for key, value in kwargs.items()
                           if key not in {"required_base_reference", "required_dependencies"}}
            result = getattr(ledger, method)(*args, **call_kwargs)
            if write:
                if idempotency_key is not None:
                    requests[idempotency_key] = {"request": request, "result": _encode(result)}
                partition = partition_snapshot(pack_id, _snapshot(ledger, pack_id, requests))
                if set(partition["scopes"]) - set(selected_scopes):
                    raise LifecycleError("transition produced foreign private lifecycle state")
                revision += 1
                shared = partition["shared"]
                shared_args = (pack_id, revision, _canonical(shared), _digest(pack_id, revision, shared))
                private_writes = []
                for selected in selected_scopes:
                    scope = partition["scopes"].get(selected, _empty_scope())
                    private = scope if selected is not None else scope["requests"]
                    private_writes.append((selected, (pack_id, revision, _canonical(private),
                        private_digest(pack_id, selected, revision, private))))
                retry_args = (pack_id, _key_digest(pack_id, idempotency_key), _hash(request)) if idempotency_key else None
                # All checks and serialization precede the original authority callback.
                # Receiving writes are one transaction; failure cannot leave a partial index.
                run_governance_check(before_commit, conn)
                conn.execute("INSERT INTO reference_pack_shared_v1 VALUES (%s,%s,%s::jsonb,%s) "
                             "ON CONFLICT(pack_id) DO UPDATE SET revision=EXCLUDED.revision, "
                             "payload=EXCLUDED.payload,state_digest=EXCLUDED.state_digest", shared_args)
                for selected, private_args in private_writes:
                    if selected is not None:
                        _scope(conn, selected)
                        conn.execute("INSERT INTO reference_pack_tenants_v1 VALUES (%s,%s,%s,%s::jsonb,%s) "
                                     "ON CONFLICT(pack_id,tenant_id) DO UPDATE SET revision=EXCLUDED.revision, "
                                     "payload=EXCLUDED.payload,state_digest=EXCLUDED.state_digest",
                                     (pack_id, selected, *private_args[1:]))
                    else:
                        conn.execute("INSERT INTO reference_pack_installation_retries_v1 VALUES (%s,%s,%s::jsonb,%s) "
                                     "ON CONFLICT(pack_id) DO UPDATE SET revision=EXCLUDED.revision, "
                                     "requests=EXCLUDED.requests,state_digest=EXCLUDED.state_digest", private_args)
                if retry_args:
                    conn.execute("INSERT INTO reference_pack_retry_index_v1 VALUES (%s,%s,%s)", retry_args)
            return result
