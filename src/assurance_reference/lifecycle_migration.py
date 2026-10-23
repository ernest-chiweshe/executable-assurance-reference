"""Explicit, transactional migration for an owned reference test schema.

This is not called by runtime construction or current application provisioning.
The original table is retained as migration evidence, with runtime access revoked.
The partitioned runtime adapter must be installed before using a migrated schema.
No production schema or environment-selected connection is accepted here.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from psycopg import sql

from assurance_reference.lifecycle_partition import plan_legacy_row, restore_partition
from factory.packs.lifecycle import LifecycleError
from factory.packs.lifecycle_pg import _canonical, _digest


TABLES = (
    "reference_pack_shared_v1", "reference_pack_tenants_v1",
    "reference_pack_installation_retries_v1", "reference_pack_retry_index_v1",
    "reference_pack_migrations_v1",
)

SCHEMA = """
CREATE TABLE reference_pack_shared_v1 (
    pack_id text PRIMARY KEY,
    revision bigint NOT NULL CHECK(revision > 0),
    payload jsonb NOT NULL,
    state_digest text NOT NULL CHECK(length(state_digest)=64),
    CHECK ((jsonb_typeof(payload)='object' AND payload->'pins'='{}'::jsonb
        AND payload->'requests'='{}'::jsonb
        AND payload->'governance_receipts'='[]'::jsonb) IS TRUE)
);
CREATE TABLE reference_pack_tenants_v1 (
    pack_id text NOT NULL REFERENCES reference_pack_shared_v1(pack_id),
    tenant_id text NOT NULL CHECK(length(tenant_id)>0),
    revision bigint NOT NULL CHECK(revision > 0),
    payload jsonb NOT NULL,
    state_digest text NOT NULL CHECK(length(state_digest)=64),
    PRIMARY KEY(pack_id,tenant_id)
);
ALTER TABLE reference_pack_tenants_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE reference_pack_tenants_v1 FORCE ROW LEVEL SECURITY;
CREATE POLICY pack_tenant_scope ON reference_pack_tenants_v1
    USING (tenant_id=current_setting('app.pack_tenant',true))
    WITH CHECK (tenant_id=current_setting('app.pack_tenant',true));
CREATE TABLE reference_pack_installation_retries_v1 (
    pack_id text PRIMARY KEY REFERENCES reference_pack_shared_v1(pack_id),
    revision bigint NOT NULL CHECK(revision > 0),
    requests jsonb NOT NULL CHECK(jsonb_typeof(requests)='object'),
    state_digest text NOT NULL CHECK(length(state_digest)=64)
);
CREATE TABLE reference_pack_retry_index_v1 (
    pack_id text NOT NULL REFERENCES reference_pack_shared_v1(pack_id),
    key_digest text NOT NULL CHECK(length(key_digest)=64),
    request_digest text NOT NULL CHECK(length(request_digest)=64),
    PRIMARY KEY(pack_id,key_digest)
);
"""


def private_digest(pack_id: str, tenant: str | None, revision: int, payload: Any) -> str:
    """Bind private bytes to their exact scope and revision, including installation scope."""
    return hashlib.sha256(_canonical([
        "reference/pack-private-state/v1", pack_id, tenant, revision, payload,
    ]).encode()).hexdigest()


def _scope(connection, tenant: str) -> None:
    if not isinstance(tenant, str) or not tenant:
        raise LifecycleError("explicit lifecycle tenant required")
    connection.execute("SELECT set_config('app.pack_tenant',%s,true)", (tenant,))


def migrate_reference_lifecycle(owner, *, runtime_roles: dict[str, str]) -> dict[str, Any]:
    """Retain and partition a complete local legacy table in one transaction.

    Call only in a maintenance window with all runtime consumers stopped. Locks
    protect the source during migration; runtime consumers must not retain table
    ownership or migration credentials. Grants are explicit and part of commit.
    """
    from assurance_reference.role_contract import ROLES

    if (set(runtime_roles) != set(ROLES)
            or len(set(runtime_roles.values())) != len(ROLES)
            or any(not isinstance(name, str) or not name for name in runtime_roles.values())):
        raise ValueError("exact distinct reference runtime roles required")
    with owner.connection() as conn, conn.transaction():
        database, address, schema = conn.execute(
            "SELECT current_database(),host(inet_server_addr()),current_schema()"
        ).fetchone()
        if (database != "factory_test" or address not in {"127.0.0.1", "::1"}
                or not re.fullmatch(r"test_reference_roles_[0-9a-f]{32}", schema or "")):
            raise ValueError("migration requires an owned local reference test schema")
        conn.execute("SET LOCAL lock_timeout='5s'")
        conn.execute("SET LOCAL statement_timeout='30s'")
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                     ("reference-pack-partition-migration",))
        conn.execute("LOCK TABLE pack_lifecycle IN ACCESS EXCLUSIVE MODE")
        # A marker is written last. Creating targets without IF NOT EXISTS makes
        # an unexpected partial/preexisting layout refuse instead of adopting it.
        conn.execute("""CREATE TABLE IF NOT EXISTS reference_pack_migrations_v1 (
            version integer PRIMARY KEY CHECK(version > 0),
            source_rows bigint NOT NULL CHECK(source_rows >= 0),
            source_inventory_digest text NOT NULL CHECK(length(source_inventory_digest)=64))""")
        previous = conn.execute(
            "SELECT version,source_rows,source_inventory_digest FROM reference_pack_migrations_v1"
        ).fetchall()
        if previous and (len(previous) != 1 or previous[0][0] != 1):
            raise LifecycleError("unsupported reference lifecycle migration version")
        names = list(runtime_roles.values())
        role_rows = conn.execute("SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolinherit,rolreplication "
                                 "FROM pg_roles WHERE rolname=ANY(%s)", (names,)).fetchall()
        if (len(role_rows) != len(names) or any(any(row[1:]) for row in role_rows)
                or conn.execute("SELECT current_user").fetchone()[0] in names):
            raise LifecycleError("runtime roles must exist and remain restricted")
        if conn.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
                        "WHERE r.rolname=ANY(%s)", (names,)).fetchone()[0]:
            raise LifecycleError("runtime roles must have no inherited or assumable memberships")
        source_owner, grantees = conn.execute("""SELECT pg_get_userbyid(c.relowner),
            ARRAY(SELECT pg_get_userbyid(a.grantee) FROM aclexplode(c.relacl) a WHERE a.grantee<>0)
            FROM pg_class c WHERE c.oid='pack_lifecycle'::regclass""").fetchone()
        if source_owner in names or set(grantees) - set(names) - {source_owner}:
            raise LifecycleError("legacy lifecycle has unexpected owners or runtime grantees")
        column_grantees = {row[0] for row in conn.execute("""SELECT pg_get_userbyid(acl.grantee)
            FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
            WHERE a.attrelid='pack_lifecycle'::regclass AND acl.grantee<>0""")}
        if column_grantees - set(names) - {source_owner}:
            raise LifecycleError("legacy lifecycle has unexpected column grantees")
        rows = conn.execute("SELECT pack_id,revision,payload,state_digest FROM pack_lifecycle "
                            "ORDER BY pack_id").fetchall()
        plans = [plan_legacy_row(*row) for row in rows]
        inventory = hashlib.sha256(_canonical([
            [plan["pack_id"], plan["source_revision"], plan["source_digest"]] for plan in plans
        ]).encode()).hexdigest()
        if previous:
            if previous[0][1:] != (len(rows), inventory):
                raise LifecycleError("retained migration source no longer matches its marker")
            # A marker alone is not a working migration. Replays also verify
            # the restricted runtime grant boundary and private RLS flags.
            _verify_runtime_grants(conn, runtime_roles)
            return {"version": 1, "source_rows": len(rows),
                    "source_inventory_digest": inventory, "already_migrated": True}
        conn.execute(SCHEMA)
        for plan in plans:
            pack, revision, partition = plan["pack_id"], plan["source_revision"], plan["partition"]
            shared = partition["shared"]
            conn.execute("INSERT INTO reference_pack_shared_v1 VALUES (%s,%s,%s::jsonb,%s)",
                         (pack, revision, _canonical(shared), _digest(pack, revision, shared)))
            for tenant, scope in partition["scopes"].items():
                if tenant is None:
                    requests = scope["requests"]
                    conn.execute("INSERT INTO reference_pack_installation_retries_v1 "
                                 "VALUES (%s,%s,%s::jsonb,%s)",
                                 (pack, revision, _canonical(requests),
                                  private_digest(pack, None, revision, requests)))
                else:
                    _scope(conn, tenant)
                    conn.execute("INSERT INTO reference_pack_tenants_v1 VALUES (%s,%s,%s,%s::jsonb,%s)",
                                 (pack, tenant, revision, _canonical(scope),
                                  private_digest(pack, tenant, revision, scope)))
            for key, fingerprint in partition["retry_index"].items():
                conn.execute("INSERT INTO reference_pack_retry_index_v1 VALUES (%s,%s,%s)",
                             (pack, key, fingerprint))
            # Read back the exact stored partitions before committing or retiring
            # legacy access. No source row is deleted or overwritten.
            found_shared, found_digest = conn.execute(
                "SELECT payload,state_digest FROM reference_pack_shared_v1 WHERE pack_id=%s",
                (pack,)).fetchone()
            if _digest(pack, revision, found_shared) != found_digest:
                raise LifecycleError("migrated shared state failed read-back")
            found_scopes = {}
            for tenant in partition["scopes"]:
                if tenant is None:
                    data, checksum = conn.execute("SELECT requests,state_digest FROM "
                        "reference_pack_installation_retries_v1 WHERE pack_id=%s", (pack,)).fetchone()
                    found_scopes[None] = {"pin": None, "requests": data, "governance_receipts": []}
                else:
                    _scope(conn, tenant)
                    data, checksum = conn.execute("SELECT payload,state_digest FROM "
                        "reference_pack_tenants_v1 WHERE pack_id=%s AND tenant_id=%s", (pack, tenant)).fetchone()
                    found_scopes[tenant] = data
                if private_digest(pack, tenant, revision, data) != checksum:
                    raise LifecycleError("migrated private state failed read-back")
            found_index = dict(conn.execute("SELECT key_digest,request_digest FROM "
                                           "reference_pack_retry_index_v1 WHERE pack_id=%s", (pack,)))
            found = {"shared": found_shared, "scopes": found_scopes, "retry_index": found_index}
            if _canonical(restore_partition(pack, found)) != _canonical(restore_partition(pack, partition)):
                raise LifecycleError("migration read-back changed source authority or retry evidence")
        for table in (*TABLES, "pack_lifecycle"):
            conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(sql.Identifier(table)))
            columns = [row[0] for row in conn.execute("SELECT attname FROM pg_attribute "
                "WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum", (table,))]
            column_list = sql.SQL(",").join(map(sql.Identifier, columns))
            # Table REVOKE does not retire separately granted column privileges.
            for role in [None, *names]:
                grantee = sql.SQL("PUBLIC") if role is None else sql.Identifier(role)
                conn.execute(sql.SQL("REVOKE SELECT({c}),INSERT({c}),UPDATE({c}),REFERENCES({c}) "
                                     "ON {t} FROM {r}").format(c=column_list, t=sql.Identifier(table), r=grantee))
            for name in names:
                conn.execute(sql.SQL("REVOKE ALL ON {} FROM {}").format(
                    sql.Identifier(table), sql.Identifier(name)))
        for kind in ("receiver", "governor"):
            conn.execute(sql.SQL("GRANT SELECT ON reference_pack_shared_v1,reference_pack_tenants_v1 TO {}")
                         .format(sql.Identifier(runtime_roles[kind])))
        governor = sql.Identifier(runtime_roles["governor"])
        conn.execute(sql.SQL("GRANT INSERT,UPDATE ON reference_pack_shared_v1,reference_pack_tenants_v1 TO {}")
                     .format(governor))
        conn.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE ON reference_pack_installation_retries_v1 TO {}")
                     .format(governor))
        conn.execute(sql.SQL("GRANT SELECT,INSERT ON reference_pack_retry_index_v1 TO {}").format(governor))
        _verify_runtime_grants(conn, runtime_roles)
        conn.execute("INSERT INTO reference_pack_migrations_v1 VALUES (1,%s,%s)", (len(rows), inventory))
        return {"version": 1, "source_rows": len(rows), "source_inventory_digest": inventory,
                "already_migrated": False, "legacy_rows_retained": True}


def _verify_runtime_grants(conn, runtime_roles):
    """Check the intended duties without running disallowed operations."""
    allowed = {
        "reference_pack_shared_v1": {"receiver": {"SELECT"}, "governor": {"SELECT", "INSERT", "UPDATE"}},
        "reference_pack_tenants_v1": {"receiver": {"SELECT"}, "governor": {"SELECT", "INSERT", "UPDATE"}},
        "reference_pack_installation_retries_v1": {"governor": {"SELECT", "INSERT", "UPDATE"}},
        "reference_pack_retry_index_v1": {"governor": {"SELECT", "INSERT"}},
        "reference_pack_migrations_v1": {}, "pack_lifecycle": {},
    }
    for table, duties in allowed.items():
        owner = conn.execute("SELECT pg_get_userbyid(relowner) FROM pg_class "
                             "WHERE oid=to_regclass(%s)", (table,)).fetchone()
        if owner is None or owner[0] in runtime_roles.values():
            raise LifecycleError("partitioned lifecycle table missing or owned by runtime role")
        for kind, role in runtime_roles.items():
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                granted = conn.execute("SELECT has_table_privilege(%s,%s,%s)", (role, table, privilege)).fetchone()[0]
                if granted != (privilege in duties.get(kind, set())):
                    raise LifecycleError("partitioned lifecycle runtime duties do not match migration")
                if privilege in {"SELECT", "INSERT", "UPDATE", "REFERENCES"} and not granted:
                    if conn.execute("SELECT has_any_column_privilege(%s,%s,%s)",
                                    (role, table, privilege)).fetchone()[0]:
                        raise LifecycleError("partitioned lifecycle retains an out-of-duty column grant")
    flags = conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                         "WHERE oid='reference_pack_tenants_v1'::regclass").fetchone()
    if flags != (True, True):
        raise LifecycleError("partitioned lifecycle requires enabled and forced tenant RLS")


def provision_partitioned_local_roles(dsn):
    """Explicitly create and migrate a fresh owned local reference schema.

    Only restricted role pools escape this provisioning boundary. Runtime hosts
    must explicitly select the matching adapter; nothing inspects environment
    variables or activates a migration during host construction.
    """
    from assurance_reference.local_roles import provision_local_roles

    # Since candidate 060 every provisioned schema is partitioned; this name is kept for existing callers.
    return provision_local_roles(dsn)
