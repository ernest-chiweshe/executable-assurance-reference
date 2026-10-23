"""Explicit local test provisioning with independent, restricted database logins.

The migration credential is consumed only by provisioning. Returned runtime
pools contain only their own login, and cannot create schemas or change grants.
This demonstrates database duties, not separate-process key custody.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import secrets
from threading import Lock
from typing import Iterator
import uuid
import weakref

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool, PoolTimeout

from assurance_reference.alerts import provision_alerts
from assurance_reference.clock_floor import provision_floor, install_recovery_guard
from assurance_reference.epoch_withdrawal_schema import provision_epoch_receipts
from assurance_reference.clinical_state import provision_clinical_state
from assurance_reference.education_authority_store import provision_education_authority
from assurance_reference.local_sessions import provision_sessions
from assurance_reference.project_state import provision_project_state
from assurance_reference.release_link_authority import migrate_release_materials
from assurance_reference.release_link_pg import migrate_release_links
from assurance_reference.sole_owner_approval import migrate_owner_roster
from assurance_reference.project_entry import migrate_api_keys
from assurance_reference.retained_settlement import migrate_settlements
from assurance_reference.roster_tenancy import migrate_roster_tenancy
from assurance_reference.durable_registries import migrate_governed_registries
from assurance_reference.tenant_fences import migrate_tenant_fences
from factory.packs.lifecycle_pg import PostgresActivationLedger
from regulated_core.clock_pg import DbClock
from regulated_core.prepared_schema_pg import WriterPolicy, migrate_prepared_authority


@dataclass
class LocalPool:
    """Reuse at most three connections for one login, resetting every return.

    SessionBoundPool still owns nested admission. No pool is shared between
    runtime roles, and an idle fixture releases its server connections promptly.
    """

    _dsn: str = field(repr=False)
    schema: str
    role: str
    _pool: ConnectionPool | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)
    _leases: int = field(default=0, init=False, repr=False)

    def _connections(self) -> ConnectionPool:
        with self._lock:
            if self._closed:
                raise RuntimeError("local role pool is closed")
            if self._pool is None:
                self._pool = ConnectionPool(
                    self._dsn, min_size=0, max_size=3, timeout=5,
                    max_idle=5, num_workers=1, open=True,
                    kwargs={"autocommit": True, "connect_timeout": 5,
                            "options": f"-c search_path={self.schema}",
                            "prepare_threshold": None},
                )
                # The callback holds only the underlying pool, never this owner.
                weakref.finalize(self, self._pool.close)
            # Reserve before releasing the lock, including time spent waiting
            # for capacity. Retarget must never race an in-flight checkout.
            self._leases += 1
            return self._pool

    def retarget(self, dsn: str) -> None:
        """Move a quiescent local fixture pool to another loopback endpoint.

        Retire the cached connection pool, keeping the same restricted login,
        database and options. This changes transport only: authority domains,
        permits and clock floors remain unchanged and restore remains HOLD.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("local role pool is closed")
            if self._leases:
                raise RuntimeError("cannot retarget a local role pool with active checkouts")
            try:
                old, new = conninfo_to_dict(self._dsn), conninfo_to_dict(dsn)
            except (psycopg.Error, TypeError) as exc:
                raise ValueError("invalid local pool retarget configuration") from exc
            old_login = {key: value for key, value in old.items() if key not in {"host", "port"}}
            new_login = {key: value for key, value in new.items() if key not in {"host", "port"}}
            if (new.get("host") not in {"127.0.0.1", "::1"}
                    or new.get("dbname") != "factory_test" or new.get("service")
                    or new.get("hostaddr", new.get("host")) != new.get("host")
                    or old_login != new_login):
                raise ValueError("retarget may change only the local endpoint, not login or database")
            if self._pool is not None:
                self._pool.close()
            self._pool = None
            self._dsn = dsn

    def close(self) -> None:
        """Stop accepting work and release this login's idle connections."""
        with self._lock:
            self._closed = True
            if self._pool is not None:
                self._pool.close()

    def _reset(self, connection: psycopg.Connection) -> None:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            connection.rollback()
        connection.autocommit = True
        connection.row_factory = tuple_row
        # DISCARD ALL clears session settings, temporary state, advisory locks
        # and prepared statements. Disable the client prepared-statement cache
        # so it cannot subsequently refer to a discarded server statement.
        connection.prepare_threshold = None
        # Both statements, in this order, in one round trip.
        with connection.pipeline():
            connection.execute("DISCARD ALL", prepare=False)
            connection.execute(sql.SQL("SET search_path TO {}").format(
                sql.Identifier(self.schema)), prepare=False)

    @contextmanager
    def connection(self) -> Iterator[psycopg.Connection]:
        pool = self._connections()
        try:
            try:
                connection = pool.getconn(timeout=5)
            except PoolTimeout as exc:
                raise TimeoutError("local role connection capacity exhausted") from exc
            try:
                # Preserve psycopg's existing commit/rollback context semantics.
                with connection:
                    yield connection
            finally:
                try:
                    if not connection.closed:
                        try:
                            self._reset(connection)
                        except Exception:
                            # Never lend a connection whose cleanup failed.
                            # Preserve the caller's original outcome/error.
                            connection.close()
                finally:
                    pool.putconn(connection)
        finally:
            with self._lock:
                self._leases -= 1


@dataclass(frozen=True)
class LocalAuthorityRoles:
    schema: str
    domain: str
    receiver: LocalPool
    allocator: LocalPool
    recorder: LocalPool
    governor: LocalPool
    clock: LocalPool
    alerts: LocalPool
    session_reader: LocalPool
    session_issuer: LocalPool
    project_state: LocalPool
    education_reader: LocalPool
    education_governor: LocalPool
    monitor_ingress: LocalPool
    delegation_issuer: LocalPool
    egress_reader: LocalPool
    egress_scope: LocalPool
    release_linker: LocalPool
    owner_reader: LocalPool
    api_key_reader: LocalPool
    settlement_writer: LocalPool


def provision_local_roles(dsn: str, *, legacy_lifecycle: bool = False) -> LocalAuthorityRoles:
    """Create only fresh UUID-owned test objects; never discover a database URL.

    Every schema is provisioned with the tenant-partitioned pack lifecycle (B-F7b, candidate 060): runtime logins
    have no access to the shared ``pack_lifecycle`` table. ``legacy_lifecycle=True`` keeps that table as the runtime
    store and exists only for migration evidence; no qualified composition accepts it.

    Callers retain the isolated cluster for evidence. This function performs no
    deletion and never modifies existing schemas, roles, platform rows or keys.
    """
    parameters = conninfo_to_dict(dsn)
    if (parameters.get("dbname") != "factory_test"
            or parameters.get("host") not in {"127.0.0.1", "::1"}
            or parameters.get("hostaddr", parameters.get("host")) != parameters.get("host")
            or parameters.get("service")):
        raise ValueError("explicit loopback factory_test connection required")
    suffix = uuid.uuid4().hex
    schema = "test_reference_roles_" + suffix
    kinds = ("receiver", "allocator", "recorder", "governor", "clock", "alerts",
             "session_reader", "session_issuer", "project_state", "education_reader", "education_governor",
             "monitor_ingress", "delegation_issuer", "egress_reader", "egress_scope",
             "release_linker", "owner_reader", "api_key_reader", "settlement_writer")
    credentials = {kind: ("ref_" + kind + "_" + suffix, secrets.token_urlsafe(32))
                   for kind in kinds}
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        database, address = connection.execute(
            "SELECT current_database(),host(inet_server_addr())"
        ).fetchone()
        if database != "factory_test" or address not in {"127.0.0.1", "::1"}:
            raise ValueError("connected server is outside the local test boundary")
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        for name, password in credentials.values():
            connection.execute(sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
            ).format(sql.Identifier(name), sql.Literal(password)))
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_control_system()"
        ).fetchone()[0]
    owner = LocalPool(dsn, schema, "migration-owner")
    names = {kind: value[0] for kind, value in credentials.items()}
    policy = WriterPolicy(
        ((names["allocator"], "reserve"), (names["allocator"], "release"),
         (names["receiver"], "consume"), (names["governor"], "consume")), (names["recorder"],),
    )
    migrate_prepared_authority(owner, policy)
    PostgresActivationLedger("", pool=owner).migrate()
    provision_alerts(owner)
    provision_floor(owner, DbClock(owner, domain))
    provision_epoch_receipts(owner)
    with owner.connection() as connection, connection.transaction():
        connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(
            sql.Identifier(schema)))
        for name in names.values():
            connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(name)))
            connection.execute(sql.SQL("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}")
                               .format(sql.Identifier(name)))
        # Explicit duties, including reads performed by the unchanged budget
        # and preparation triggers under their invoking runtime login. Newly
        # migrated tables receive no implicit runtime read access.
        import os
        if os.environ.get("REFERENCE_SHARED_EVIDENCE_FIXTURE") == "1":
            from regulated_core.evidence_service_pg import MAP_SCHEMA,SERVICE_SCHEMA
            connection.execute(MAP_SCHEMA);connection.execute(SERVICE_SCHEMA)
            shared_tables=("regulated_evidence_map_v2","regulated_evidence_keys_v1","regulated_evidence_tree_v1",
                "regulated_evidence_frontier_v1","regulated_evidence_heads_v1","regulated_evidence_key_tree_v1",
                "regulated_evidence_key_frontier_v1","regulated_evidence_key_occurrences_v1")
            for table in shared_tables:
                connection.execute(sql.SQL("GRANT SELECT,INSERT ON {} TO {}").format(sql.Identifier(table),sql.Identifier(names["recorder"])))
        reads = {
            "receiver": (
                "pack_lifecycle", "regulated_permit_uses_v1", "regulated_reviews_v1",
                "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
                "regulated_preparations_v1", "regulated_database_attempts_v1",
                "regulated_database_receipts_v1", "regulated_revocation_events_v1",
                "regulated_delegation_grants_v1", "regulated_delegation_revocations_v1",
                "regulated_monitor_clearances_v1", "regulated_governance_events_v1",
                "regulated_governance_fences_v1", "regulated_monitor_heartbeats_v2",
            ),
            "allocator": (
                "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
                "regulated_preparations_v1", "regulated_database_attempts_v1",
                "regulated_database_receipts_v1",
            ),
            "recorder": (
                "regulated_decision_evidence_v1", "regulated_preparations_v1",
                "regulated_preparation_writers_v1", "regulated_mission_budget_events_v1",
            ),
            "governor": (
                "regulated_mission_budget_events_v1", "regulated_budget_writer_roles_v1",
                "pack_lifecycle", "regulated_governance_events_v1",
                "regulated_governance_fences_v1", "regulated_revocation_events_v1",
                "regulated_governance_rosters_v1", "regulated_reviews_v1",
                "reference_epoch_withdrawal_receipts_v1",
            ),
            "delegation_issuer": (
                "regulated_delegation_grants_v1", "regulated_delegation_revocations_v1",
            ),
            "clock": ("reference_clock_floor_v1",),
            "alerts": ("reference_alerts_v1",),
            # X-15: the send-time admission reads tenant scope history only; the
            # separate scope writer appends inventory and enrolment events.
            "egress_reader": ("regulated_egress_scope_v1",),
            "egress_scope": ("regulated_egress_scope_v1",),
        }
        for kind, tables in reads.items():
            for table in tables:
                connection.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(
                    sql.Identifier(table), sql.Identifier(names[kind])))
        inserts = {
            "allocator": ("regulated_mission_budget_events_v1",),
            "receiver": ("regulated_mission_budget_events_v1", "regulated_permit_uses_v1",
                         "regulated_reviews_v1"),
            "recorder": ("regulated_decision_evidence_v1", "regulated_preparations_v1"),
            "governor": ("regulated_mission_budget_events_v1", "regulated_governance_events_v1", "regulated_revocation_events_v1",
                         "regulated_governance_rosters_v1", "reference_epoch_withdrawal_receipts_v1",
                         "pack_lifecycle", "regulated_governance_fences_v1"),
            "alerts": ("reference_alerts_v1",),
            "monitor_ingress": ("regulated_monitor_heartbeats_v2", "regulated_monitor_clearances_v1"),
            "delegation_issuer": ("regulated_delegation_grants_v1",),
            "egress_scope": ("regulated_egress_scope_v1",),
        }
        for kind, tables in inserts.items():
            for table in tables:
                connection.execute(sql.SQL("GRANT INSERT ON {} TO {}").format(
                    sql.Identifier(table), sql.Identifier(names[kind])))
        # The append-only store's ON CONFLICT key requires key-column reads.
        # This login cannot read heartbeat payloads or update/delete any row.
        connection.execute(sql.SQL(
            "GRANT SELECT(installation,monitor_id,sequence) ON regulated_monitor_heartbeats_v2 TO {}"
        ).format(sql.Identifier(names["monitor_ingress"])))
        # Signed clearance ingress has key-column reads only, as for heartbeats.
        connection.execute(sql.SQL(
            "GRANT SELECT(tenant,decision_record_id) ON regulated_monitor_clearances_v1 TO {}"
        ).format(sql.Identifier(names["monitor_ingress"])))
        connection.execute(sql.SQL("GRANT UPDATE ON pack_lifecycle,regulated_governance_fences_v1 TO {}")
                           .format(sql.Identifier(names["governor"])))
        connection.execute(sql.SQL("GRANT UPDATE(highwater_us) ON reference_clock_floor_v1 TO {}")
                           .format(sql.Identifier(names["clock"])))
        # R-2b: the clock login sets a hold only through the owner-defined function (server-computed time).
        connection.execute(sql.SQL("GRANT EXECUTE ON FUNCTION reference_clock_floor_hold_v1(text, text, bigint) TO {}")
                           .format(sql.Identifier(names["clock"])))
    # Identity grants are separate from authority duties. Password material is
    # readable only by the independent authentication issuer.
    provision_sessions(owner)
    with owner.connection() as connection, connection.transaction():
        connection.execute(sql.SQL("GRANT SELECT,INSERT ON reference_identities_v1,reference_sessions_v1 TO {}")
                           .format(sql.Identifier(names["session_issuer"])))
        for table, column in (("reference_identities_v1", "active"), ("reference_sessions_v1", "revoked")):
            connection.execute(sql.SQL("GRANT UPDATE({}) ON {} TO {}").format(
                sql.Identifier(column), sql.Identifier(table), sql.Identifier(names["session_issuer"])))
        connection.execute(sql.SQL("GRANT SELECT(tenant,principal,username,active,lock_anchor) "
                                   "ON reference_identities_v1 TO {}")
                           .format(sql.Identifier(names["session_reader"])))
        connection.execute(sql.SQL("GRANT SELECT ON reference_sessions_v1 TO {}")
                           .format(sql.Identifier(names["session_reader"])))
        # PostgreSQL requires UPDATE privilege for SELECT ... FOR SHARE. This
        # constrained constant column grants locking, not an authority change.
        for name in (names["session_reader"], names["session_issuer"]):
            for table in ("reference_identities_v1", "reference_sessions_v1"):
                connection.execute(sql.SQL("GRANT UPDATE(lock_anchor) ON {} TO {}")
                                   .format(sql.Identifier(table), sql.Identifier(name)))
    # Choreography state has separate grants. Only its own
    # runtime login may read or update it; authority logs remain separate.
    provision_project_state(owner)
    provision_clinical_state(owner)
    with owner.connection() as connection, connection.transaction():
        connection.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE(state,revision,updated_at) "
                                   "ON projectos_states TO {}")
                           .format(sql.Identifier(names["project_state"])))
        connection.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE(payload,record_digest,revision,tombstoned) "
                                   "ON reference_clinical_state_v1 TO {}")
                           .format(sql.Identifier(names["project_state"])))
        connection.execute(sql.SQL("GRANT SELECT,INSERT ON reference_clinical_removals_v1 TO {}")
                           .format(sql.Identifier(names["project_state"])))
    # Authority collections have separate grants. Only the dedicated
    # reader and signed-grant provisioner can see them; receivers cannot edit grants.
    provision_education_authority(owner)
    with owner.connection() as connection, connection.transaction():
        for kind in ("education_reader", "education_governor"):
            connection.execute(sql.SQL("GRANT SELECT ON pack_documents TO {}")
                               .format(sql.Identifier(names[kind])))
        connection.execute(sql.SQL("GRANT INSERT,UPDATE(version,payload,record_digest,updated_at,schema_version) "
                                   "ON pack_documents TO {}")
                           .format(sql.Identifier(names["education_governor"])))
    # X-22 release links: owner-provisioned goal versions and release material. The dedicated linker reads them,
    # row-locks their anchors, appends links, and reads exactly the review and delegation state it re-verifies
    # inside the goal transaction. It cannot write goals, material, reviews, grants or revocations.
    migrate_release_links(owner, names["release_linker"])
    migrate_release_materials(owner, names["release_linker"])
    with owner.connection() as connection, connection.transaction():
        connection.execute(sql.SQL("GRANT SELECT ON regulated_reviews_v1,regulated_delegation_grants_v1,"
                                   "regulated_delegation_revocations_v1,regulated_revocation_events_v1 TO {}")
                           .format(sql.Identifier(names["release_linker"])))
        # The receiving delegated source check reads published links and goal versions only.
        connection.execute(sql.SQL("GRANT SELECT ON reference_release_goal_versions_v1,reference_release_links_v1 TO {}")
                           .format(sql.Identifier(names["receiver"])))
    # X-3 owner roster: owner-provisioned; the dedicated reader may read it and the retained reviews it checks.
    migrate_owner_roster(owner, names["owner_reader"])
    with owner.connection() as connection, connection.transaction():
        connection.execute(sql.SQL("GRANT SELECT ON regulated_reviews_v1 TO {}")
                           .format(sql.Identifier(names["owner_reader"])))
        # Membership currentness only: no credential, session or password material.
        connection.execute(sql.SQL("GRANT SELECT(tenant,principal,active) ON reference_identities_v1 TO {}")
                           .format(sql.Identifier(names["owner_reader"])))
    # X-20 durable API keys: owner-issued digests; the dedicated reader verifies every request.
    migrate_api_keys(owner, names["api_key_reader"])
    # X-4 retained settlements: intent and exact authorization per approved review; never deleted.
    migrate_settlements(owner, names["settlement_writer"])
    # B-F7b: tenant-scoped governance fences under forced RLS; written and read by the governance log login.
    migrate_tenant_fences(owner, writers=(names["governor"],))
    # B-F7b: roster chains are one authority tenant's records; forced RLS by tenant (candidate 060).
    migrate_roster_tenancy(owner)
    # A15: durable governed qualification and issuer registries; receipts tenant-scoped (candidate 062).
    migrate_governed_registries(owner, writers=(names["governor"],), readers=(names["receiver"],))
    # Recheck after grants; a runtime login must never edit its writer policy.
    migrate_prepared_authority(owner, policy)
    pools = {}
    for kind, (name, password) in credentials.items():
        runtime_parameters = {**parameters, "user": name, "password": password}
        # A caller-provided libpq setting may not select an alternate authority.
        for key in ("options", "passfile", "service", "role"):
            runtime_parameters.pop(key, None)
        pools[kind] = LocalPool(make_conninfo(**runtime_parameters), schema, name)
    if type(legacy_lifecycle) is not bool:
        raise TypeError("legacy_lifecycle must be an explicit boolean")
    if not legacy_lifecycle:
        from assurance_reference.lifecycle_migration import migrate_reference_lifecycle
        migrate_reference_lifecycle(owner, runtime_roles=names)
    # R-2b: while a recovery hold is set, every authority table refuses writes (deny by default).
    install_recovery_guard(owner)
    return LocalAuthorityRoles(schema, domain, **pools)
