"""Durable data a pack owns, declared like custom resources, stored in one generic tenant-scoped table.

A learner, a roster entry, a mastery signal over time: a pack must keep them for months, per tenant,
and no pack may add a table to the platform. So a pack DECLARES its collections (name, key fields,
a field schema, a version, and the MIGRATIONS between versions), the way an operator declares a
custom resource definition, and the platform stores every pack's documents in one table
(``pack_documents``) migrated once. Documents are versioned by compare-and-swap, digest-bound, and
read back verified. The field types are the schema's (string, long, bool, decimal, set, record,
timestamp); a document that does not fit its collection's schema is refused at the store, not
discovered later. Research gate 8: "durable collection schemas and forward/backward migration
compatibility before storing learner data" — a new pack version may activate only when every
collection it changed declares the migration chain from the version tenants already hold.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Protocol

from factory.pg_pool import open_pool

from .schema import Attribute, _is_decimal

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_TYPES = {"string", "long", "bool", "decimal", "set", "record", "timestamp"}


class CollectionError(ValueError):
    """A collection declaration or a document is invalid."""


class CollectionConflict(RuntimeError):
    """A write contradicts the stored version or an identical-key document exists differently."""


@dataclass(frozen=True, slots=True)
class Migration:
    """How a document at ``from_version`` becomes one at ``to_version``: renames, defaults for new fields, drops."""

    from_version: int
    to_version: int
    renames: Mapping[str, str]
    defaults: Mapping[str, Any]
    drops: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"from_version": self.from_version, "to_version": self.to_version, "renames": dict(self.renames),
                "defaults": dict(self.defaults), "drops": list(self.drops)}


@dataclass(frozen=True, slots=True)
class CollectionSpec:
    name: str
    version: int
    key: tuple[str, ...]
    fields: Mapping[str, Attribute]
    description: str = ""
    vocabulary: str = ""                     # the external standard this collection mirrors, e.g. oneroster@1.2 User
    migrations: tuple[Migration, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "key": list(self.key),
                "fields": {n: {"type": a.type, "required": a.required} for n, a in self.fields.items()},
                "description": self.description, "vocabulary": self.vocabulary,
                "migrations": [m.to_dict() for m in self.migrations]}

    def migration_chain(self, from_version: int) -> tuple[Migration, ...] | None:
        """The migrations that take ``from_version`` to this version, or None when the chain is broken."""
        if from_version < 1 or from_version > self.version:
            return None
        steps: list[Migration] = []
        current = from_version
        by_from = {m.from_version: m for m in self.migrations}
        while current < self.version:
            step = by_from.get(current)
            if step is None or step.to_version != current + 1:
                return None
            steps.append(step)
            current = step.to_version
        return tuple(steps)


def validate_collections(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return ["collections must be a list"]
    p: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or not _NAME.fullmatch(str(entry.get("name", ""))):
            p.append(f"collection {entry!r}: name must be a lowercase identifier")
            continue
        name = str(entry["name"])
        if name in seen:
            p.append(f"collection {name}: declared twice")
        seen.add(name)
        version = entry.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            p.append(f"collection {name}: version must be an integer >= 1")
            version = 1
        fields = entry.get("fields")
        if not isinstance(fields, dict) or not fields:
            p.append(f"collection {name}: fields must declare at least one field")
            fields = {}
        for fname, spec in fields.items():
            if not _FIELD.fullmatch(str(fname)) or not isinstance(spec, dict) or spec.get("type") not in _TYPES:
                p.append(f"collection {name}.{fname}: needs a type ({'|'.join(sorted(_TYPES))})")
        key = entry.get("key")
        if not isinstance(key, list) or not key or any(not isinstance(k, str) or k not in fields for k in key):
            p.append(f"collection {name}: key must name one or more declared fields")
        elif len(set(key)) != len(key) or any(not isinstance(fields[k], dict) or fields[k].get("type") not in
                                             {"string", "timestamp", "long", "bool", "decimal"} or
                                             fields[k].get("required", True) is not True for k in key):
            p.append(f"collection {name}: key fields must be distinct required scalars")
        migrations = entry.get("migrations", []) or []
        if not isinstance(migrations, list):
            p.append(f"collection {name}: migrations must be a list")
            migrations = []
        froms: set[int] = set()
        for m in migrations:
            if not isinstance(m, dict) or type(m.get("from_version")) is not int or type(m.get("to_version")) is not int \
                    or m["to_version"] != m["from_version"] + 1 or m["from_version"] < 1 or m["to_version"] > version:
                p.append(f"collection {name}: every migration goes from_version N to to_version N+1")
                continue
            if m["from_version"] in froms:
                p.append(f"collection {name}: duplicate migration from version {m['from_version']}")
            froms.add(int(m["from_version"]))
            if not isinstance(m.get("renames", {}), dict) or not isinstance(m.get("defaults", {}), dict) \
                    or not isinstance(m.get("drops", []), list):
                p.append(f"collection {name}: migration renames/defaults must be objects and drops a list")
                continue
            final_step = m["to_version"] == version
            for source, target in (m.get("renames") or {}).items():
                if not isinstance(source, str) or not _FIELD.fullmatch(source) or not isinstance(target, str) or not _FIELD.fullmatch(target):
                    p.append(f"collection {name}: migration rename fields must be identifiers")
                    continue
                # Intermediate schemas may contain fields renamed or dropped later.
                # Only the final transition is constrained by this version's fields.
                if final_step and target not in fields:
                    p.append(f"collection {name}: migration renames to undeclared field {target!r}")
            for fname in m.get("defaults") or {}:
                if not isinstance(fname, str) or not _FIELD.fullmatch(fname):
                    p.append(f"collection {name}: migration default fields must be identifiers")
                elif final_step and fname not in fields:
                    p.append(f"collection {name}: migration defaults undeclared field {fname!r}")
            if any(not isinstance(fname, str) or not _FIELD.fullmatch(fname) for fname in m.get("drops", [])):
                p.append(f"collection {name}: migration dropped fields must be identifiers")
        if version > 1 and any(v not in froms for v in range(1, version)):
            p.append(f"collection {name}: version {version} needs the migration chain 1 -> {version} (a tenant may hold any earlier version)")
    return p


def collections_from_list(raw: list[Any]) -> tuple[CollectionSpec, ...]:
    problems = validate_collections(raw)
    if problems:
        raise CollectionError("; ".join(problems))
    return tuple(
        CollectionSpec(str(e["name"]), int(e["version"]), tuple(str(k) for k in e["key"]),
                       {str(n): Attribute(str(s["type"]), bool(s.get("required", True))) for n, s in e["fields"].items()},
                       str(e.get("description", "")), str(e.get("vocabulary", "")),
                       tuple(Migration(int(m["from_version"]), int(m["to_version"]), dict(m.get("renames") or {}),
                                       dict(m.get("defaults") or {}), tuple(str(d) for d in m.get("drops") or ()))
                             for m in (e.get("migrations") or [])))
        for e in raw)


def compatible(previous: CollectionSpec, current: CollectionSpec) -> list[str]:
    """Why a tenant holding ``previous`` documents cannot move to ``current``, or nothing."""
    p: list[str] = []
    if previous.name != current.name:
        return [f"{previous.name} and {current.name} are different collections"]
    if current.version < previous.version:
        p.append(f"{current.name}: version {current.version} is older than the {previous.version} tenants hold")
    if previous.key != current.key:
        p.append(f"{current.name}: the key changed ({list(previous.key)} -> {list(current.key)}); a new key is a new collection")
    if current.version == previous.version and current.fields != previous.fields:
        p.append(f"{current.name}: fields changed without a new schema version")
    if current.version > previous.version and current.migration_chain(previous.version) is None:
        p.append(f"{current.name}: no migration chain from version {previous.version} to {current.version}")
    return p


def migrate_payload(spec: CollectionSpec, payload: Mapping[str, Any], from_version: int) -> dict[str, Any]:
    chain = spec.migration_chain(from_version)
    if chain is None:
        raise CollectionError(f"{spec.name}: no migration chain from version {from_version} to {spec.version}")
    result = dict(payload)
    for step in chain:
        for old, new in step.renames.items():
            if old in result:
                if old != new and new in result:
                    raise CollectionError(f"{spec.name}: migration rename would overwrite field {new!r}")
                result[new] = result.pop(old)
        for name, value in step.defaults.items():
            result.setdefault(name, value)
        for name in step.drops:
            result.pop(name, None)
    problems = validate_document(spec, result)
    if problems:
        raise CollectionError("migrated document is invalid: " + "; ".join(problems))
    return result


def _typed(value: Any, attr: Attribute) -> bool:
    return {
        "string": isinstance(value, str), "long": isinstance(value, int) and not isinstance(value, bool),
        "bool": isinstance(value, bool), "decimal": isinstance(value, str) and _is_decimal(value),
        "set": isinstance(value, list), "record": isinstance(value, dict), "timestamp": isinstance(value, str),
    }[attr.type]


def validate_document(spec: CollectionSpec, payload: Mapping[str, Any]) -> list[str]:
    p: list[str] = []
    for name, attr in spec.fields.items():
        if name not in payload:
            if attr.required:
                p.append(f"{spec.name}: field {name!r} is required")
            continue
        if not _typed(payload[name], attr):
            p.append(f"{spec.name}: field {name!r} must be {attr.type}")
    for name in payload:
        if name not in spec.fields:
            p.append(f"{spec.name}: field {name!r} is not declared")
    return p


def document_key(spec: CollectionSpec, payload: Mapping[str, Any]) -> str:
    # Preserve ordinary existing keys while escaping both the separator and escape
    # character. Escaping '%' first makes the encoding injective for string keys.
    return "|".join(str(payload[k]).replace("%", "%25").replace("|", "%7C") for k in spec.key)


def rekeyed_documents(spec: CollectionSpec, documents: tuple[PackDocument, ...]) -> tuple[PackDocument, ...]:
    """Plan a lossless legacy-key upgrade using payload fields, never delimiter parsing.

    A historical collision may already have prevented a second insert; this cannot
    recover data that was never stored. It refuses any collision among stored rows.
    """
    result = []
    seen: set[tuple[str, str]] = set()
    for document in documents:
        key = document_key(spec, document.payload)
        identity = (document.tenant_id, key)
        if identity in seen:
            raise CollectionConflict("legacy keys converge; operator reconciliation is required")
        seen.add(identity)
        result.append(document if key == document.key else replace(document, key=key, version=document.version + 1))
    return tuple(result)


def _digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class PackDocument:
    pack_id: str
    collection: str
    tenant_id: str
    key: str
    version: int
    payload: Mapping[str, Any]
    updated_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        for value, name in ((self.pack_id, "pack_id"), (self.collection, "collection"), (self.tenant_id, "tenant_id")):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise CollectionError(f"{name} must be a bounded identifier")
        if not isinstance(self.key, str) or not self.key or len(self.key) > 512:
            raise CollectionError("key must be a non-empty bounded string")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise CollectionError("version must be a positive integer")
        if self.updated_at.tzinfo is None:
            raise CollectionError("updated_at must be timezone-aware")
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise CollectionError("schema_version must be a positive integer")

    def canonical(self) -> dict[str, Any]:
        result = {"pack_id": self.pack_id, "collection": self.collection, "tenant_id": self.tenant_id, "key": self.key,
                "version": self.version, "payload": dict(self.payload),
                "updated_at": self.updated_at.astimezone(timezone.utc).isoformat()}
        # Preserve the digest of legacy v1 records. Later schemas are explicit.
        if self.schema_version != 1:
            result["schema_version"] = self.schema_version
        return result

    @property
    def digest(self) -> str:
        return _digest(self.canonical())

    def to_dict(self) -> dict[str, Any]:
        return {**self.canonical(), "digest": self.digest}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PackDocument":
        return cls(str(raw["pack_id"]), str(raw["collection"]), str(raw["tenant_id"]), str(raw["key"]),
                   int(raw["version"]), dict(raw["payload"]), datetime.fromisoformat(str(raw["updated_at"])),
                   int(raw.get("schema_version", 1)))


class PackCollectionStore(Protocol):
    durable: bool

    def put(self, spec: CollectionSpec, document: PackDocument, *, expected_version: int | None) -> PackDocument:
        """Insert (expected_version None) or compare-and-swap. The payload is validated against the spec."""
        ...

    def get(self, pack_id: str, collection: str, tenant_id: str, key: str) -> PackDocument | None: ...

    def list(self, pack_id: str, collection: str, tenant_id: str, *, limit: int = 200, after_key: str | None = None) -> tuple[PackDocument, ...]: ...


def _check_put(spec: CollectionSpec, document: PackDocument, expected_version: int | None) -> None:
    if document.schema_version != spec.version:
        raise CollectionError("document schema_version does not match the active collection schema")
    if document.collection != spec.name:
        raise CollectionError(f"document collection {document.collection!r} is not {spec.name!r}")
    problems = validate_document(spec, document.payload)
    if problems:
        raise CollectionError("; ".join(problems))
    if document_key(spec, document.payload) != document.key:
        raise CollectionError("document key does not match its key fields")
    if expected_version is None and document.version != 1:
        raise CollectionConflict("a new document starts at version 1")
    if expected_version is not None and document.version != expected_version + 1:
        raise CollectionConflict("an update advances the version by one")


class InMemoryPackCollectionStore:
    durable = False

    def __init__(self) -> None:
        self._lock = RLock()
        self._rows: dict[tuple[str, str, str, str], PackDocument] = {}

    def put(self, spec: CollectionSpec, document: PackDocument, *, expected_version: int | None) -> PackDocument:
        _check_put(spec, document, expected_version)
        ident = (document.pack_id, document.collection, document.tenant_id, document.key)
        with self._lock:
            prior = self._rows.get(ident)
            if prior is not None and prior.schema_version > document.schema_version:
                raise CollectionConflict("stored schema is newer; an older pinned pack cannot downgrade a document")
            if expected_version is None and prior is not None:
                if prior.digest == document.digest:
                    return prior
                raise CollectionConflict("document exists; pass its version to update it")
            if expected_version is not None and (prior is None or prior.version != expected_version):
                raise CollectionConflict("document changed underneath; re-read and retry")
            self._rows[ident] = document
            return document

    def get(self, pack_id: str, collection: str, tenant_id: str, key: str) -> PackDocument | None:
        with self._lock:
            return self._rows.get((pack_id, collection, tenant_id, key))

    def list(self, pack_id: str, collection: str, tenant_id: str, *, limit: int = 200, after_key: str | None = None) -> tuple[PackDocument, ...]:
        with self._lock:
            rows = [d for (p, c, t, _k), d in self._rows.items() if (p, c, t) == (pack_id, collection, tenant_id)]
        return tuple(sorted((d for d in rows if after_key is None or d.key > after_key), key=lambda d: d.key)[:limit])

    def rekey_collection(self, pack_id: str, spec: CollectionSpec) -> int:
        """Explicit maintenance operation; atomic and repeatable, never a request side effect."""
        with self._lock:
            old = tuple(d for (p, c, _, _), d in self._rows.items() if p == pack_id and c == spec.name)
            new = rekeyed_documents(spec, old)
            replacement = {ident: d for ident, d in self._rows.items() if ident[:2] != (pack_id, spec.name)}
            replacement.update({(d.pack_id, d.collection, d.tenant_id, d.key): d for d in new})
            self._rows = replacement
            return sum(a.key != b.key for a, b in zip(old, new))


SCHEMA_VERSION = 2
SCHEMA_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS pack_collections_schema_migrations (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""
SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS pack_documents (
    pack_id        TEXT NOT NULL,
    collection     TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    doc_key        TEXT NOT NULL,
    version        BIGINT NOT NULL CHECK (version > 0),
    payload        JSONB NOT NULL,
    record_digest  TEXT NOT NULL CHECK (length(record_digest) = 64),
    updated_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (pack_id, collection, tenant_id, doc_key)
);
CREATE INDEX IF NOT EXISTS pack_documents_tenant_lookup ON pack_documents(tenant_id, pack_id, collection, doc_key);
"""


class PostgresPackCollectionStore:
    durable = True
    migration_transactional = True
    migration_idempotent = True

    def __init__(self, dsn: str, *, max_size: int = 2, pool: Any = None) -> None:
        self._closed = False
        if pool is not None:
            self._pool = pool
            return
        self._pool = open_pool(dsn, max_size=max_size, autocommit=True, name="pack-collections")
        atexit.register(self.close)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._pool, "close", None)
        if close is not None:
            close()

    def migrate(self) -> None:
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("pack-collections-schema",))
            conn.execute(SCHEMA_BOOTSTRAP)
            row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM pack_collections_schema_migrations").fetchone()
            current = 0 if row is None else int(row[0])
            if current > SCHEMA_VERSION:
                raise CollectionError("database pack-collections schema is newer than this application")
            if current < 1:
                conn.execute(SCHEMA_V1)
                conn.execute("INSERT INTO pack_collections_schema_migrations(version) VALUES (%s)", (1,))
            if current < 2:
                conn.execute("ALTER TABLE pack_documents ADD COLUMN IF NOT EXISTS schema_version INTEGER NOT NULL"
                             " DEFAULT 1 CHECK (schema_version > 0)")
                conn.execute("INSERT INTO pack_collections_schema_migrations(version) VALUES (%s)", (2,))

    @staticmethod
    def _row(row: Any) -> PackDocument:
        pack_id, collection, tenant_id, key, version, payload, digest, updated_at, schema_version = row
        document = PackDocument(str(pack_id), str(collection), str(tenant_id), str(key), int(version),
                                dict(json.loads(payload) if isinstance(payload, (str, bytes)) else payload),
                                updated_at if isinstance(updated_at, datetime) else datetime.fromisoformat(str(updated_at)),
                                int(schema_version))
        if document.digest != str(digest):
            raise CollectionConflict(f"stored document {pack_id}/{collection}/{key} failed integrity")
        return document

    _SELECT = ("SELECT pack_id, collection, tenant_id, doc_key, version, payload, record_digest, updated_at, schema_version"
               " FROM pack_documents")

    def put(self, spec: CollectionSpec, document: PackDocument, *, expected_version: int | None) -> PackDocument:
        _check_put(spec, document, expected_version)
        payload = json.dumps(dict(document.payload), sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
                         (f"pack-rekey:{document.pack_id}:{spec.name}",))
            if expected_version is None:
                inserted = conn.execute(
                    "INSERT INTO pack_documents (pack_id, collection, tenant_id, doc_key, version, payload, record_digest,"
                    " updated_at, schema_version) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)"
                    " ON CONFLICT (pack_id, collection, tenant_id, doc_key) DO NOTHING RETURNING doc_key",
                    (document.pack_id, document.collection, document.tenant_id, document.key, document.version, payload,
                     document.digest, document.updated_at, document.schema_version)).fetchone()
                if inserted is not None:
                    return document
                prior = conn.execute(self._SELECT + " WHERE pack_id = %s AND collection = %s AND tenant_id = %s AND doc_key = %s",
                                     (document.pack_id, document.collection, document.tenant_id, document.key)).fetchone()
                if prior is not None and self._row(prior).digest == document.digest:
                    return document
                raise CollectionConflict("document exists; pass its version to update it")
            updated = conn.execute(
                "UPDATE pack_documents SET version = %s, payload = %s::jsonb, record_digest = %s, updated_at = %s, schema_version = %s"
                " WHERE pack_id = %s AND collection = %s AND tenant_id = %s AND doc_key = %s AND version = %s"
                " AND schema_version <= %s RETURNING doc_key",
                (document.version, payload, document.digest, document.updated_at, document.schema_version, document.pack_id, document.collection,
                 document.tenant_id, document.key, expected_version, document.schema_version)).fetchone()
            if updated is None:
                raise CollectionConflict("document changed underneath or stored schema is newer; re-read with a compatible pack")
        return document

    def get(self, pack_id: str, collection: str, tenant_id: str, key: str) -> PackDocument | None:
        with self._pool.connection() as conn:
            row = conn.execute(self._SELECT + " WHERE pack_id = %s AND collection = %s AND tenant_id = %s AND doc_key = %s",
                               (pack_id, collection, tenant_id, key)).fetchone()
        return None if row is None else self._row(row)

    def list(self, pack_id: str, collection: str, tenant_id: str, *, limit: int = 200, after_key: str | None = None) -> tuple[PackDocument, ...]:
        with self._pool.connection() as conn:
            rows = conn.execute(self._SELECT + " WHERE pack_id = %s AND collection = %s AND tenant_id = %s"
                                " AND (%s::text IS NULL OR doc_key COLLATE \"C\" > %s) ORDER BY doc_key COLLATE \"C\" LIMIT %s",
                                (pack_id, collection, tenant_id, after_key, after_key, limit)).fetchall()
        return tuple(self._row(r) for r in rows)

    def rekey_collection(self, pack_id: str, spec: CollectionSpec) -> int:
        """Upgrade legacy keys under an exclusive maintenance lock, without dropping rows.

        Two-phase temporary keys avoid collisions with an old key that happens to
        equal another row's newly encoded key. Both phases share one transaction.
        """
        import uuid
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"pack-rekey:{pack_id}:{spec.name}",))
            rows = conn.execute(self._SELECT + " WHERE pack_id = %s AND collection = %s FOR UPDATE",
                                (pack_id, spec.name)).fetchall()
            old = tuple(self._row(row) for row in rows)
            new = rekeyed_documents(spec, old)
            changes = [(before, after) for before, after in zip(old, new) if before.key != after.key]
            staged = []
            for before, after in changes:
                temporary = "rekey:" + uuid.uuid4().hex
                conn.execute("UPDATE pack_documents SET doc_key = %s WHERE pack_id = %s AND collection = %s"
                             " AND tenant_id = %s AND doc_key = %s",
                             (temporary, pack_id, spec.name, before.tenant_id, before.key))
                staged.append((temporary, after))
            for temporary, after in staged:
                conn.execute("UPDATE pack_documents SET doc_key = %s, version = %s, record_digest = %s"
                             " WHERE pack_id = %s AND collection = %s AND tenant_id = %s AND doc_key = %s",
                             (after.key, after.version, after.digest, pack_id, spec.name, after.tenant_id, temporary))
            return len(changes)


__all__ = ["SCHEMA_BOOTSTRAP", "SCHEMA_V1", "SCHEMA_VERSION", "CollectionConflict", "CollectionError", "CollectionSpec",
           "InMemoryPackCollectionStore", "Migration", "PackCollectionStore", "PackDocument", "PostgresPackCollectionStore",
           "collections_from_list", "compatible", "document_key", "migrate_payload", "validate_collections",
           "validate_document"]
