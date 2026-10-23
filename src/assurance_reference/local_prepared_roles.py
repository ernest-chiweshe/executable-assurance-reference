"""Fresh local prepared-authority profile; not an installed-schema migration.

The default local profile is unchanged. Provisioning alone receives the owner
credential. Returned pools use disjoint restricted logins; keys still belong to
trusted host code, and app.tenant still requires authenticated host context.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import secrets
import uuid

from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from assurance_reference.local_roles import LocalAuthorityRoles, LocalPool, provision_local_roles


@dataclass(frozen=True)
class LocalPreparedRoles(LocalAuthorityRoles):
    issuer: LocalPool
    reviewer: LocalPool


# Read closure of retained preparation/issuance verification. Explicit lists
# prevent a newly migrated table from acquiring implicit runtime authority.
_AUTHORITY_READS = (
    "regulated_decision_evidence_v1",
    "regulated_decision_inputs_v1",
    "regulated_evidence_checkpoints_v1",
    "regulated_decision_uses_v1",
    "regulated_preparations_v1",
    "regulated_reviews_v1",
    "regulated_mission_budget_events_v1",
    "regulated_revocation_events_v1",
    "regulated_delegation_grants_v1",
    "regulated_delegation_revocations_v1",
)
_RECEIVER_APPENDS = (
    "regulated_decision_uses_v1",
    "regulated_database_attempts_v1",
    "regulated_database_receipts_v1",
)
_RECORDER_APPENDS = (
    "regulated_decision_inputs_v1",
    "regulated_evidence_checkpoints_v1",
)


def provision_local_prepared_roles(dsn: str) -> LocalPreparedRoles:
    """Provision one new isolated local schema and its prepared-runtime roles.

    No existing schema or role can be supplied. The base provisioner validates
    explicit loopback factory_test and installs the original writer maps,
    forced row policies, immutable stores, clock floor and recovery guards.
    On failure retain created objects for diagnosis; never delete evidence.
    """
    base = provision_local_roles(dsn)
    owner = LocalPool(dsn, base.schema, "migration-owner")
    suffix = uuid.uuid4().hex
    credentials = {
        kind: ("ref_prepared_" + kind + "_" + suffix, secrets.token_urlsafe(32))
        for kind in ("issuer", "reviewer")
    }
    try:
        with owner.connection() as conn, conn.transaction():
            for name, password in credentials.values():
                conn.execute(sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(sql.Identifier(name), sql.Literal(password)))
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(base.schema), sql.Identifier(name)))
                conn.execute(sql.SQL("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}").format(
                    sql.Identifier(name)))
            issuer = credentials["issuer"][0]
            reviewer = credentials["reviewer"][0]
            for role in (base.recorder.role, base.receiver.role, issuer):
                for table in _AUTHORITY_READS:
                    conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(
                        sql.Identifier(table), sql.Identifier(role)))
            for role, tables in ((base.receiver.role, _RECEIVER_APPENDS),
                                 (base.recorder.role, _RECORDER_APPENDS)):
                for table in tables:
                    conn.execute(sql.SQL("GRANT INSERT ON {} TO {}").format(
                        sql.Identifier(table), sql.Identifier(role)))
            conn.execute(sql.SQL("REVOKE INSERT ON regulated_reviews_v1 FROM {}").format(
                sql.Identifier(base.receiver.role)))
            conn.execute(sql.SQL("GRANT SELECT,INSERT ON regulated_reviews_v1 TO {}").format(
                sql.Identifier(reviewer)))
            # No INSERT on writer maps, no broad UPDATE/DELETE/TRUNCATE,
            # no membership, no ownership and no bypass or definer wrapper.
        parameters = conninfo_to_dict(dsn)
        pools = {}
        for kind, (name, password) in credentials.items():
            login = {**parameters, "user": name, "password": password}
            for key in ("options", "passfile", "service", "role"):
                login.pop(key, None)
            pools[kind] = LocalPool(make_conninfo(**login), base.schema, name)
        return LocalPreparedRoles(**{f.name: getattr(base, f.name) for f in fields(base)}, **pools)
    finally:
        owner.close()
