"""R-2b: resume authority after a recovery hold, only by a signed ceremony and only when nothing witnessed was lost.

The ceremony is accepted only when:
- it is signed by the pinned ceremony key and binds this domain and this exact hold (``hold_at_us``);
- the local evidence log holds exactly every head a witness quorum acknowledged, for every scope (a lost or forked
  tail stays on hold) and those checkpoints are the ones the ceremony names;
- the clock has a maximum permit lifetime and the quarantine has passed: now >= hold_at + lifetime + margin, so every
  permit issued before the hold has expired at every receiver that enforces the bound;
- its nonce was never used (replay refused).

It is applied in one transaction by the dedicated recovery login, the only login the hold guard exempts:
- every tenant found in any tenant column (tenant, tenant_id, workspace_id) has its revocation epoch moved to its
  maximum plus 2^32 (assumes fewer than 2^32 revocations were lost); a tenant all of whose rows were lost is not
  found, and is covered only by the quarantine (its permits have expired);
- every delegation grant, every session and every API key is revoked;
- the floor is raised to the ceremony reading and the hold is cleared.

Not restored (stated limits): pack lifecycle revocations, governance rosters, tenant owners and fences, egress
scope, monitor clearances, governance fences, issuer recognitions, qualification reports, clinician certificates,
generation-floor states, clinical removals and tombstones, collaboration withdrawals, release links and goals. A
changed clock domain (a new cluster) is not resumed here.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Callable

import psycopg
from psycopg import sql

from regulated_core.clock import ClockError
from regulated_core.signing import Signature, Signer, TrustDirectory

from assurance_reference.clock_floor import DurableClock, install_recovery_guard
from assurance_reference.local_roles import LocalPool

CEREMONY_SCHEMA = "reference/resume-ceremony/v1"
EPOCH_JUMP = 2 ** 32
TABLE = "reference_resume_ceremonies_v1"
# Every column that names a tenant in this reference; the ceremony refuses if a tenant-bearing table exists that
# its login cannot read, so a table created after provisioning is never skipped silently.
TENANT_COLUMNS = ("tenant", "tenant_id", "workspace_id")
_TENANT_TABLES = ("SELECT c.relname, a.attname FROM pg_catalog.pg_attribute a"
                  " JOIN pg_catalog.pg_class c ON c.oid = a.attrelid"
                  " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                  " WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
                  " AND a.attnum > 0 AND NOT a.attisdropped AND a.attname = ANY(%s) ORDER BY 1, 2")


class CeremonyRefused(ClockError):
    """The resumption ceremony is not accepted; the hold stays."""


def provision_recovery_login(owner: Any, dsn: str) -> LocalPool:
    """Create the dedicated recovery login and its exact duties; re-install the guards with it exempt."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    name, password = "ref_recovery_" + secrets.token_hex(8), secrets.token_urlsafe(32)
    with owner.connection() as connection, connection.transaction():
        schema = connection.execute("SELECT current_schema()").fetchone()[0]
        connection.execute(sql.SQL(
            "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS NOINHERIT"
        ).format(sql.Identifier(name), sql.Literal(password)))
        connection.execute(sql.SQL(
            "CREATE TABLE IF NOT EXISTS {} (nonce text PRIMARY KEY, domain text NOT NULL, hold_at_us bigint NOT NULL,"
            " body jsonb NOT NULL, signature jsonb NOT NULL, applied_at_us bigint NOT NULL)").format(sql.Identifier(TABLE)))
        login = sql.Identifier(name)
        for statement in (
            "GRANT USAGE ON SCHEMA {schema} TO {login}",
            "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {login}",
            "GRANT SELECT, INSERT ON {schema}.reference_resume_ceremonies_v1 TO {login}",
            "GRANT SELECT, UPDATE(highwater_us, hold_at_us, hold_reason) ON {schema}.reference_clock_floor_v1 TO {login}",
            "GRANT SELECT, INSERT ON {schema}.regulated_revocation_events_v1 TO {login}",
            "GRANT SELECT ON {schema}.regulated_delegation_grants_v1 TO {login}",
            "GRANT SELECT, INSERT ON {schema}.regulated_delegation_revocations_v1 TO {login}",
            "GRANT SELECT, UPDATE(revoked) ON {schema}.reference_sessions_v1 TO {login}",
            "GRANT SELECT, UPDATE(revoked_at_us) ON {schema}.reference_api_keys_v1 TO {login}",
        ):
            connection.execute(sql.SQL(statement).format(schema=sql.Identifier(schema), login=login))
        for table, column in connection.execute(_TENANT_TABLES, (list(TENANT_COLUMNS),)).fetchall():
            connection.execute(sql.SQL("GRANT SELECT({}) ON {} TO {}").format(
                sql.Identifier(column), sql.Identifier(table), login))
    install_recovery_guard(owner, recovery_login=name)
    parameters = {**conninfo_to_dict(dsn), "user": name, "password": password}
    for key in ("options", "passfile", "service", "role"):
        parameters.pop(key, None)
    return LocalPool(make_conninfo(**parameters), schema, name)


@dataclass(frozen=True)
class SignedCeremony:
    body: dict
    signature: Signature


def sign_ceremony(signer: Signer, *, domain: str, hold_at_us: int, witnessed: list, issued_at_us: int) -> SignedCeremony:
    body = {"schema": CEREMONY_SCHEMA, "domain": domain, "hold_at_us": hold_at_us, "nonce": secrets.token_hex(16),
            "witnessed": sorted([list(point) for point in witnessed]), "issued_at_us": issued_at_us}
    return SignedCeremony(body, signer.sign(body))


class ResumptionAuthority:
    def __init__(self, *, recovery_pool: Any, clock: DurableClock, trust: TrustDirectory, ceremony_key_id: str,
                 arming: Any, head_at: Callable[[str, int], Any], effect_margin_us: int = 0) -> None:
        if not isinstance(clock, DurableClock):
            raise TypeError("resumption needs the recovery-capable durable clock")
        if type(effect_margin_us) is not int or effect_margin_us < 0:
            raise ValueError("a non-negative effect margin is required")
        self._pool, self._clock, self._trust, self._key = recovery_pool, clock, trust, ceremony_key_id
        self._arming, self._head_at, self._margin = arming, head_at, effect_margin_us

    def _hold(self) -> int | None:
        with self._pool.connection() as connection:
            row = connection.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s",
                                     (self._clock.domain,)).fetchone()
        if row is None:
            raise CeremonyRefused("clock floor has not been provisioned")
        return row[0]

    def resume(self, signed: SignedCeremony) -> dict:
        body, signature = signed.body, signed.signature
        if (type(signature) is not Signature or signature.key_id != self._key
                or not self._trust.verify(body, signature)):
            raise CeremonyRefused("ceremony signature invalid or not the pinned ceremony key")
        if body.get("schema") != CEREMONY_SCHEMA or body.get("domain") != self._clock.domain:
            raise CeremonyRefused("ceremony is not for this clock domain")
        hold_at = self._hold()
        if hold_at is None or body.get("hold_at_us") != hold_at:
            raise CeremonyRefused("ceremony does not name the current hold")
        matched = sorted([list(point) for point in self._arming.require_local_matches(self._clock.domain,
                                                                                    self._head_at)])
        if matched != body.get("witnessed"):
            raise CeremonyRefused("witnessed checkpoints differ from the ceremony")
        bound = self._clock.max_permit_lifetime_us
        if bound is None:
            raise CeremonyRefused("no maximum permit lifetime: the quarantine cannot be bounded")
        now = self._clock._read_for_ceremony().now_us
        if now < hold_at + bound + self._margin:
            raise CeremonyRefused("quarantine has not passed: a permit issued before the hold may still be live")
        try:
            return self._apply(body, signature, hold_at, now)
        except psycopg.errors.UniqueViolation as replayed:
            raise CeremonyRefused("ceremony nonce already used") from replayed

    def _apply(self, body: dict, signature: Signature, hold_at: int, now: int) -> dict:
        reason = "resume ceremony " + body["nonce"]
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute("SELECT hold_at_us FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE",
                                     (self._clock.domain,)).fetchone()
            if row is None or row[0] != hold_at:
                raise CeremonyRefused("the hold changed during the ceremony")
            connection.execute(f"INSERT INTO {TABLE} (nonce, domain, hold_at_us, body, signature, applied_at_us)"
                               " VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s)",
                               (body["nonce"], body["domain"], hold_at, json.dumps(body),
                                json.dumps({"key_id": signature.key_id, "alg": signature.alg,
                                            "value": signature.value}), now))
            columns = connection.execute(_TENANT_TABLES, (list(TENANT_COLUMNS),)).fetchall()
            unreadable = [f"{table}.{column}" for table, column in columns if not connection.execute(
                "SELECT has_column_privilege(session_user, %s::regclass, %s, 'SELECT')",
                (table, column)).fetchone()[0]]
            if unreadable:
                raise CeremonyRefused("the recovery login cannot see every tenant column: " + ", ".join(unreadable))
            tenants = sorted({value for table, column in columns for (value,) in connection.execute(
                sql.SQL("SELECT DISTINCT {} FROM {}").format(sql.Identifier(column), sql.Identifier(table))).fetchall()
                if isinstance(value, str) and value})
            for tenant in tenants:
                current = connection.execute("SELECT COALESCE(MAX(epoch), 0) FROM regulated_revocation_events_v1"
                                             " WHERE tenant = %s", (tenant,)).fetchone()[0]
                connection.execute("INSERT INTO regulated_revocation_events_v1"
                                   " (tenant, epoch, actor, reason, revoked_at_us) VALUES (%s, %s, %s, %s, %s)",
                                   (tenant, int(current) + EPOCH_JUMP, "recovery-ceremony", reason, now))
            grants = connection.execute(
                "INSERT INTO regulated_delegation_revocations_v1 (tenant, grant_digest, actor, reason, revoked_at_us)"
                " SELECT tenant, grant_digest, 'recovery-ceremony', %s, %s FROM regulated_delegation_grants_v1"
                " ON CONFLICT (tenant, grant_digest) DO NOTHING", (reason, now)).rowcount
            sessions = connection.execute("UPDATE reference_sessions_v1 SET revoked = true WHERE NOT revoked").rowcount
            keys = connection.execute("UPDATE reference_api_keys_v1 SET revoked_at_us = %s"
                                      " WHERE revoked_at_us IS NULL", (now,)).rowcount
            connection.execute("UPDATE reference_clock_floor_v1 SET highwater_us = GREATEST(highwater_us, %s),"
                               " hold_at_us = NULL, hold_reason = NULL WHERE domain = %s", (now, self._clock.domain))
        return {"tenants": tenants, "epoch_jump": EPOCH_JUMP, "delegation_revocations": grants,
                "sessions_revoked": sessions, "api_keys_revoked": keys, "resumed_at_us": now}
