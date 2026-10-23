"""Signed application-generation floors over committed login retirement facts.

Schema installation and floor publication belong to an external release task.
This module never alters logins, terminates sessions or calls a cloud provider.
Readers retain a shared transaction lock until their protected work ends.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Any

from psycopg import sql
from psycopg.pq import TransactionStatus

from regulated_core.canonical import canonical_bytes
from regulated_core.identity_provider import CredentialError
from regulated_core.signing import Signature, Signer, TrustDirectory

_COMPONENT = "authentication"
_LOCK = "application-generation-floor:" + _COMPONENT
_SCHEMA = "factory/application-generation-floor/v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_EVENTS = 1000


def migrate_generation_floor(connection: Any, *, schema: str, writer_logins: tuple[str, ...]) -> None:
    """Install the append-only record store; never create or change login roles."""
    if not schema or not writer_logins or len(set(writer_logins)) != len(writer_logins):
        raise ValueError("generation-floor migration requires a schema and explicit writer logins")
    if any(not isinstance(name, str) or not name or name != name.strip() for name in writer_logins):
        raise ValueError("invalid generation-floor writer login")
    owner = sql.Identifier(schema)
    with connection.transaction():
        connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))", (_LOCK,))
        for name in writer_logins:
            if connection.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s", (name,)).fetchone() != (1,):
                raise ValueError("generation-floor writer login is not installed")
        connection.execute(sql.SQL("""
            CREATE TABLE IF NOT EXISTS {}.application_generation_floor_writers_v1 (
                login_name TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS {}.application_generation_floor_v1 (
                component TEXT NOT NULL CHECK (component='authentication'),
                ordinal BIGINT NOT NULL CHECK (ordinal>0),
                previous_digest TEXT NOT NULL,
                origin_xid xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
                record_digest TEXT NOT NULL CHECK (record_digest ~ '^[0-9a-f]{{64}}$'),
                payload JSONB NOT NULL,
                signature JSONB NOT NULL,
                PRIMARY KEY(component,ordinal), UNIQUE(component,record_digest)
            );
            REVOKE ALL ON {}.application_generation_floor_writers_v1 FROM PUBLIC;
            REVOKE ALL ON {}.application_generation_floor_v1 FROM PUBLIC;
        """).format(owner, owner, owner, owner))
        existing = connection.execute(sql.SQL("SELECT login_name FROM {}.application_generation_floor_writers_v1 ORDER BY login_name")
                                      .format(owner)).fetchall()
        if existing and tuple(row[0] for row in existing) != tuple(sorted(writer_logins)):
            raise ValueError("installed generation-floor writer policy differs; explicit reviewed migration required")
        for name in writer_logins:
            connection.execute(sql.SQL("INSERT INTO {}.application_generation_floor_writers_v1 VALUES (%s) ON CONFLICT DO NOTHING")
                               .format(owner), (name,))
        connection.execute(sql.SQL("""
            CREATE OR REPLACE FUNCTION {}.application_generation_floor_guard_v1()
            RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, {}, pg_temp AS $body$
            DECLARE prior_ordinal BIGINT; prior_digest TEXT;
            BEGIN
                IF TG_OP <> 'INSERT' THEN
                    RAISE EXCEPTION 'generation-floor records are immutable';
                END IF;
                PERFORM pg_catalog.pg_advisory_xact_lock(
                    pg_catalog.hashtextextended('application-generation-floor:' || NEW.component,0));
                IF NOT EXISTS (SELECT 1 FROM {}.application_generation_floor_writers_v1
                               WHERE login_name=session_user) THEN
                    RAISE EXCEPTION 'generation-floor writer login is not authorised';
                END IF;
                SELECT ordinal,record_digest INTO prior_ordinal,prior_digest
                    FROM {}.application_generation_floor_v1
                    WHERE component=NEW.component ORDER BY ordinal DESC LIMIT 1;
                IF NEW.ordinal <> COALESCE(prior_ordinal,0)+1
                   OR NEW.previous_digest <> COALESCE(prior_digest,'') THEN
                    RAISE EXCEPTION 'generation-floor history must append at its current head';
                END IF;
                NEW.origin_xid := pg_catalog.pg_current_xact_id();
                RETURN NEW;
            END $body$;
            DROP TRIGGER IF EXISTS application_generation_floor_guard_v1 ON {}.application_generation_floor_v1;
            CREATE TRIGGER application_generation_floor_guard_v1 BEFORE INSERT OR UPDATE OR DELETE
                ON {}.application_generation_floor_v1 FOR EACH ROW
                EXECUTE FUNCTION {}.application_generation_floor_guard_v1();
            DROP TRIGGER IF EXISTS application_generation_floor_truncate_v1 ON {}.application_generation_floor_v1;
            CREATE TRIGGER application_generation_floor_truncate_v1 BEFORE TRUNCATE
                ON {}.application_generation_floor_v1 FOR EACH STATEMENT
                EXECUTE FUNCTION {}.application_generation_floor_guard_v1();
        """).format(*([owner] * 10)))


@dataclass(frozen=True)
class GenerationFloor:
    """A verified record, including its immutable chain position."""

    ordinal: int
    digest: str
    generation: int
    state: str
    retired_logins: tuple[str, ...]
    deployment_evidence_digest: str
    observed_at_us: int


class GenerationFloorVerifier:
    """Trust a configured release key and installation, never request inputs."""

    def __init__(self, *, trust: TrustDirectory, issuer_key_id: str, installation_id: str,
                 schema: str, minimum_generation: int = 2) -> None:
        if (not issuer_key_id or not trust.is_known(issuer_key_id)
                or not installation_id or installation_id != installation_id.strip()
                or not schema or type(minimum_generation) is not int or minimum_generation < 1):
            raise ValueError("generation floor requires explicit release trust and installation bindings")
        self.trust, self.issuer_key_id = trust, issuer_key_id
        self.installation_id, self.schema = installation_id, schema
        self.minimum_generation = minimum_generation

    @staticmethod
    def _transaction(connection: Any) -> None:
        if (connection.info.transaction_status != TransactionStatus.INTRANS
                or connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",)):
            raise CredentialError("generation-floor verification requires an active READ COMMITTED transaction")

    def _lock(self, connection: Any, *, exclusive: bool) -> None:
        self._transaction(connection)
        fn = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
        connection.execute(sql.SQL("SELECT pg_catalog.{}(pg_catalog.hashtextextended(%s,0))")
                           .format(sql.Identifier(fn)), (_LOCK,))

    def _history(self, connection: Any) -> list[GenerationFloor]:
        rows = connection.execute(sql.SQL("SELECT ordinal,previous_digest,record_digest,payload,signature "
                                          "FROM {}.application_generation_floor_v1 WHERE component=%s "
                                          "ORDER BY ordinal LIMIT %s").format(sql.Identifier(self.schema)),
                                  (_COMPONENT, _MAX_EVENTS + 1)).fetchall()
        if len(rows) > _MAX_EVENTS:
            raise CredentialError("generation-floor history requires reviewed checkpoint qualification")
        history: list[GenerationFloor] = []
        previous = ""
        for index, row in enumerate(rows, 1):
            ordinal, prior, digest, body, raw_signature = row
            try:
                body = json.loads(body) if isinstance(body, str) else body
                raw_signature = json.loads(raw_signature) if isinstance(raw_signature, str) else raw_signature
                signature = Signature(**raw_signature)
                keys = {"schema", "component", "installation_id", "ordinal", "previous_digest",
                        "generation", "state", "retired_logins", "deployment_evidence_digest", "observed_at_us"}
                if (not isinstance(body, dict) or set(body) != keys
                        or signature.key_id != self.issuer_key_id
                        or not self.trust.verify(body, signature)
                        or digest != sha256(canonical_bytes({"body": body, "signature": raw_signature})).hexdigest()
                        or ordinal != index or prior != previous
                        or body["ordinal"] != ordinal or body["previous_digest"] != prior
                        or body["schema"] != _SCHEMA or body["component"] != _COMPONENT
                        or body["installation_id"] != self.installation_id):
                    raise ValueError("record binding differs")
                self._terms(body["generation"], body["state"], body["retired_logins"],
                            body["deployment_evidence_digest"])
                if type(body["observed_at_us"]) is not int or body["observed_at_us"] <= 0:
                    raise ValueError("invalid observation time")
                event = GenerationFloor(ordinal, digest, body["generation"], body["state"],
                                        tuple(body["retired_logins"]), body["deployment_evidence_digest"],
                                        body["observed_at_us"])
                self._transition(history[-1] if history else None, event)
            except (TypeError, ValueError, KeyError) as error:
                raise CredentialError("generation-floor evidence is invalid") from error
            history.append(event)
            previous = digest
        return history

    @staticmethod
    def _terms(generation: int, state: str, logins: Any, evidence_digest: str) -> None:
        if (type(generation) is not int or generation < 1 or state not in ("retiring", "retired", "restored")
                or not isinstance(logins, (list, tuple)) or not logins
                or any(not isinstance(name, str) or not name or name != name.strip() for name in logins)
                or list(logins) != sorted(set(logins))
                or not isinstance(evidence_digest, str) or not _HEX.fullmatch(evidence_digest)):
            raise ValueError("generation-floor terms are invalid")

    @staticmethod
    def _transition(previous: GenerationFloor | None, event: GenerationFloor) -> None:
        if previous is None:
            if event.state != "retiring":
                raise ValueError("generation retirement must begin by disabling authority")
            return
        if event.observed_at_us < previous.observed_at_us:
            raise ValueError("generation-floor database clock moved backwards")
        if not set(previous.retired_logins).issubset(event.retired_logins):
            raise ValueError("generation-floor history cannot omit an earlier retired login")
        if event.state == "retired":
            if (previous.state != "retiring" or event.generation != previous.generation
                    or event.retired_logins != previous.retired_logins
                    or event.deployment_evidence_digest != previous.deployment_evidence_digest):
                raise ValueError("retired evidence must complete its exact retirement proposal")
        elif event.state == "retiring":
            if previous.state == "retiring" or event.generation < previous.generation:
                raise ValueError("retirement must advance an enabled or restored generation")
        elif previous.state == "restored" or event.generation > previous.generation:
            raise ValueError("restoration must disable the previously recorded floor")

    def _require_committed_head(self, connection: Any) -> None:
        own = connection.execute(sql.SQL(
            "SELECT origin_xid=pg_catalog.pg_current_xact_id_if_assigned() "
            "FROM {}.application_generation_floor_v1 WHERE component=%s ORDER BY ordinal DESC LIMIT 1"
        ).format(sql.Identifier(self.schema)), (_COMPONENT,)).fetchone()
        if own == (True,):
            raise CredentialError("generation-floor phases must be committed separately")

    @staticmethod
    def _retired_on(connection: Any, logins: tuple[str, ...]) -> None:
        rows = connection.execute("SELECT rolname,rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=ANY(%s)",
                                  (list(logins),)).fetchall()
        if set(name for name, _ in rows) != set(logins) or any(enabled for _, enabled in rows):
            raise CredentialError("a generation login is missing or still enabled")
        if connection.execute("""
            WITH RECURSIVE grantees(roleid, member) AS (
                SELECT m.roleid,m.member FROM pg_catalog.pg_auth_members m
                JOIN pg_catalog.pg_roles r ON r.oid=m.roleid WHERE r.rolname=ANY(%s)
                UNION
                SELECT g.roleid,m.member FROM grantees g
                JOIN pg_catalog.pg_auth_members m ON m.roleid=g.member
            )
            SELECT 1 FROM grantees g JOIN pg_catalog.pg_roles r ON r.oid=g.member
            WHERE r.rolcanlogin LIMIT 1
        """, (list(logins),)).fetchone() is not None:
            raise CredentialError("a retired generation role is granted to a live login")
        if connection.execute("SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename=ANY(%s) LIMIT 1",
                              (list(logins),)).fetchone() is not None:
            raise CredentialError("a retired generation still has a database session")

    def require_on(self, connection: Any) -> GenerationFloor:
        """Hold the floor lock through the caller's effect; inspect live role facts."""
        self._lock(connection, exclusive=False)
        history = self._history(connection)
        if not history or history[-1].state != "retired" or history[-1].generation < self.minimum_generation:
            raise CredentialError("the required application generation is not retired and qualified")
        self._require_committed_head(connection)
        roles = connection.execute("SELECT rolsuper,rolcreaterole,rolbypassrls FROM pg_catalog.pg_roles "
                                   "WHERE rolname IN (current_user,session_user)").fetchall()
        if not roles or any(role != (False, False, False) for role in roles):
            raise CredentialError("owner authority requires a restricted application login")
        current = history[-1]
        self._retired_on(connection, current.retired_logins)
        now = connection.execute("SELECT (extract(epoch FROM pg_catalog.clock_timestamp())*1000000)::bigint").fetchone()[0]
        if current.observed_at_us > now:
            raise CredentialError("generation-floor observation is ahead of the database clock")
        return current

    def append_on(self, connection: Any, *, signer: Signer, generation: int, state: str,
                  retired_logins: tuple[str, ...], deployment_evidence_digest: str,
                  expected_head: str, observation_pool: Any = None) -> GenerationFloor:
        """Append a signed phase under the exclusive lock, never modify login state.

        P0 records retiring; external committed role retirement and drain follow;
        P3 records retired only after observing disabled logins and no sessions.
        Restoration records restored before any external role re-enablement.
        """
        if signer.key_id != self.issuer_key_id:
            raise ValueError("generation-floor writer must use its configured release-evidence key")
        self._terms(generation, state, retired_logins, deployment_evidence_digest)
        self._lock(connection, exclusive=True)
        history = self._history(connection)
        previous = history[-1] if history else None
        self._require_committed_head(connection)
        if expected_head != (previous.digest if previous else ""):
            raise CredentialError("generation-floor publication expected a different history head")
        if state == "retired":
            if observation_pool is None:
                raise ValueError("retired publication requires an independent catalog connection")
            with observation_pool.connection() as observer:
                local = connection.info
                remote = observer.info
                if (local.backend_pid == remote.backend_pid
                        or (local.host, local.port, local.dbname) != (remote.host, remote.port, remote.dbname)):
                    raise CredentialError("retirement observer must be a separate connection to the same database")
                if observer.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
                    raise CredentialError("retirement observer must use READ COMMITTED")
                self._retired_on(observer, retired_logins)
        now = connection.execute("SELECT (extract(epoch FROM pg_catalog.clock_timestamp())*1000000)::bigint").fetchone()[0]
        body = {"schema": _SCHEMA, "component": _COMPONENT, "installation_id": self.installation_id,
                "ordinal": len(history)+1, "previous_digest": expected_head, "generation": generation,
                "state": state, "retired_logins": list(retired_logins),
                "deployment_evidence_digest": deployment_evidence_digest, "observed_at_us": now}
        signature = asdict(signer.sign(body))
        if not self.trust.verify(body, Signature(**signature)):
            raise CredentialError("generation-floor signature does not match configured release trust")
        digest = sha256(canonical_bytes({"body": body, "signature": signature})).hexdigest()
        event = GenerationFloor(len(history)+1, digest, generation, state, retired_logins, deployment_evidence_digest, now)
        self._transition(previous, event)
        connection.execute(sql.SQL("INSERT INTO {}.application_generation_floor_v1 "
                                   "(component,ordinal,previous_digest,record_digest,payload,signature) "
                                   "VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb)").format(sql.Identifier(self.schema)),
                           (_COMPONENT,event.ordinal,expected_head,digest,json.dumps(body),json.dumps(signature)))
        return event
