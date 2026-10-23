"""Host release material and inherited authority held inside the goal transaction (X-22).

The recovered release-link stages (``release_link``, ``release_link_pg`` and
``release_link_reviews``) define the admission, the atomic goal/link store and the
signed-review projection. This module supplies the concrete host ports they leave
to composition:

* ``ChainBoundReleaseMaterial`` reads the owner-provisioned release material (the
  exact governed contract and executor context the executor's review signed) and
  verifies its inherited release authority. Its ``locked_on`` runs entirely on the
  goal transaction's own connection: it locks the material row, resolves the
  signed chain through that connection, takes the shared tenant and per-ancestor
  revocation fences (``lock_current_authority``), re-resolves under them, and reads
  the trusted clock only after every wait. Those transaction locks are held until
  the link publishes or rolls back; a revoker waits for publication, and a
  revocation committed earlier refuses it.
* ``GoalOwnerAuthorization`` re-authorizes the authenticated caller as the current
  goal owner around every read, on the goal transaction's connection when it has
  one.
* ``LinkedReleaseSource`` is the receiving-side delegated source check: a delegated
  release is current only while exactly one published link names its grant and
  that link's goal is still the goal's current, unexpired version.

The executor identity follows the frozen product derivation
(``factory/delegation/release_authority.py@6bba989a project_executor``): the same
schema string and the same five stored scope fields. Reference tenants are not
customer-prefixed workspaces, so the workspace is bound to the tenant itself.

Scheduling and linking are not effects. The final effect still passes the complete
receiving gates, which re-verify the chain and call ``LinkedReleaseSource.status``.
Nothing here signs, issues a grant or permit, or performs an effect.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields as dataclass_fields
import json
from typing import Any, Callable, Iterator

from psycopg import sql

from assurance_reference.release_link import GoalReleaseBinding, ReleaseLinkRefused
from assurance_reference.release_link_pg import _goal_on
from assurance_reference.release_link_reviews import ReleaseMaterial
from factory.collaboration.contracts import canonical_digest
from factory.projectos.regulated import EmissionContext, ReleaseAuthorityBinding
from regulated_core.authority_fence_pg import lock_current_authority
from regulated_core.canonical import digest_hex
from regulated_core.delegation import EXECUTOR_PREFIX, RELEASE_AUTHORITY_FIELD, Chain, DelegationAuthority, DelegationError
from regulated_core.permit import EmissionError
from regulated_core.persistence_pg import PostgresGrantStore

MATERIAL_TABLE = "reference_release_materials_v1"
EXECUTOR_SCHEMA = "delegation.project-executor.v1"
# The executor context fields a release material retains; now_us is always the trusted clock's.
CONTEXT_FIELDS = ("tenant", "actor_id", "project_id", "vertical_name", "action_id", "nonce",
                  "approval", "release_target", "not_after_us", "review_producer_id")


def reference_project_executor(*, tenant_id: str, goal_id: str, vertical: str, project_instance_id: str) -> str:
    """The host-derived executor for one goal's project instance; never an actor override."""
    scope = dict(tenant=tenant_id, workspace=tenant_id, goal=goal_id, vertical=vertical,
                 instance=project_instance_id)
    if any(not isinstance(value, str) or not value.strip() or len(value) > 1024 for value in scope.values()):
        raise ReleaseLinkRefused("executor derivation requires bounded stored scope")
    return EXECUTOR_PREFIX + canonical_digest({"schema": EXECUTOR_SCHEMA, **scope})


def migrate_release_materials(owner, runtime_role: str) -> None:
    """Fresh isolated schema only. Owner-provisioned, immutable to runtime: read and row-lock only."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(f"""CREATE TABLE {MATERIAL_TABLE}(
            tenant text NOT NULL, goal_id text NOT NULL, review_id text NOT NULL,
            project_id text NOT NULL, payload_digest text NOT NULL, payload jsonb NOT NULL,
            lock_anchor boolean NOT NULL DEFAULT true CHECK(lock_anchor),
            PRIMARY KEY(tenant,goal_id,review_id),
            FOREIGN KEY(tenant,goal_id) REFERENCES reference_release_goal_heads_v1)""")
        name = sql.Identifier(MATERIAL_TABLE)
        conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("CREATE POLICY release_scope ON {} USING "
            "(tenant=current_setting('app.release_tenant',true)) WITH CHECK "
            "(tenant=current_setting('app.release_tenant',true))").format(name))
        conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
        conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(name, sql.Identifier(runtime_role)))
        # SELECT ... FOR SHARE requires UPDATE; this checked constant column carries no authority.
        conn.execute(sql.SQL("GRANT UPDATE(lock_anchor) ON {} TO {}").format(name, sql.Identifier(runtime_role)))


def _context_payload(context: EmissionContext) -> dict[str, Any]:
    return {name: getattr(context, name) for name in CONTEXT_FIELDS}


def provision_release_material(owner, *, goal_id: str, review_id: str, contract: dict,
                               context: EmissionContext) -> str:
    """Insert the exact reviewed contract and executor context once; a differing retry refuses."""
    body = {"contract": contract, "context": _context_payload(context)}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    decoded = json.loads(encoded)
    fingerprint = digest_hex(decoded)
    with owner.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.release_tenant',%s,true)", (context.tenant,))
        conn.execute(f"INSERT INTO {MATERIAL_TABLE}(tenant,goal_id,review_id,project_id,payload_digest,payload)"
                     " VALUES(%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING",
                     (context.tenant, goal_id, review_id, context.project_id, fingerprint, encoded))
        row = conn.execute(f"SELECT payload_digest FROM {MATERIAL_TABLE}"
                           " WHERE tenant=%s AND goal_id=%s AND review_id=%s",
                           (context.tenant, goal_id, review_id)).fetchone()
    if row is None or row[0] != fingerprint:
        raise ReleaseLinkRefused("release material already provisioned with different content")
    return fingerprint


class _OnConnection:
    """Present the goal transaction's own connection as a pool. Each store operation runs in a savepoint of that
    transaction; nothing opens, borrows or releases another connection, and no lock is released early."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @contextmanager
    def connection(self) -> Iterator[Any]:
        yield self._conn


class _VerifyOnlyKey:
    """The delegation authority's key identity for chain verification; this port can never sign."""

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id

    def sign(self, payload: Any) -> Any:
        raise DelegationError("release linking verifies grants and never signs one")


class ChainBoundReleaseMaterial:
    """The ReleaseLinkMaterial port: exact retained material plus inherited authority, current inside the goal
    transaction. Composition-owned; holds the linker pool and verification anchors only, no signing key."""

    def __init__(self, *, pool: Any, trust: Any, delegation_key_id: str, clock: Any) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("release material requires the release linker pool")
        if not isinstance(delegation_key_id, str) or not trust.is_known(delegation_key_id):
            raise TypeError("release material requires the registered delegation verification key")
        if not callable(getattr(clock, "now_us", None)):
            raise TypeError("release material requires the trusted clock")
        self.pool, self.trust, self.delegation_key_id, self.clock = pool, trust, delegation_key_id, clock

    def _delegation(self, conn: Any) -> DelegationAuthority:
        return DelegationAuthority(_VerifyOnlyKey(self.delegation_key_id), self.trust,
                                   PostgresGrantStore(pool=_OnConnection(conn)))

    @staticmethod
    def _material(conn: Any, goal: GoalReleaseBinding, request: Any, *, lock: bool) -> ReleaseMaterial:
        row = conn.execute(
            f"SELECT payload_digest,payload,project_id FROM {MATERIAL_TABLE}"
            " WHERE tenant=%s AND goal_id=%s AND review_id=%s" + (" FOR SHARE" if lock else ""),
            (goal.tenant, request.goal_id, request.review_id)).fetchone()
        if row is None:
            raise ReleaseLinkRefused("retained release material is unavailable")
        payload = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        if digest_hex(payload) != row[0] or row[2] != request.project_id or set(payload) != {"contract", "context"}:
            raise ReleaseLinkRefused("retained release material failed integrity")
        fields = payload["context"]
        if not isinstance(fields, dict) or set(fields) != set(CONTEXT_FIELDS) or not isinstance(payload["contract"], dict):
            raise ReleaseLinkRefused("retained release material is malformed")
        known = {f.name for f in dataclass_fields(EmissionContext)}
        if not set(CONTEXT_FIELDS) <= known:
            raise ReleaseLinkRefused("release material context fields differ from the host context")
        return ReleaseMaterial(payload["contract"], EmissionContext(now_us=0, **fields))

    @staticmethod
    def _claim(contract: dict) -> ReleaseAuthorityBinding:
        inherited = contract.get(RELEASE_AUTHORITY_FIELD)
        if (not isinstance(inherited, dict)
                or set(inherited) != {"schema", "grant_digest", "chain_digest", "root_digest", "mission"}
                or inherited["schema"] != "regulated/release-authority/v1"):
            raise ReleaseLinkRefused("current inherited release authority required")
        return ReleaseAuthorityBinding(**{k: v for k, v in inherited.items() if k != "schema"})

    def _matches(self, chain: Chain, claim: ReleaseAuthorityBinding, goal: GoalReleaseBinding) -> None:
        leaf, root = chain.leaf, chain.root
        if (len(chain.grants) < 2 or leaf.is_root
                or (leaf.digest(), chain.digest, root.digest(), root.root_mission) !=
                (claim.grant_digest, claim.chain_digest, claim.root_digest, claim.mission)
                or root.subject != goal.owner or leaf.subject != goal.executor
                or root.tenant_id != goal.tenant):
            raise ReleaseLinkRefused("inherited authority is not the goal owner's chain to this executor")

    def _chain(self, conn: Any, tenant: str, claim: ReleaseAuthorityBinding) -> Chain:
        try:
            # Every blocking read (grants, signatures, revocations) through this connection; expiry is judged
            # separately on the trusted clock after all waits.
            return self._delegation(conn).resolve(tenant, claim.grant_digest, now_us=None)
        except DelegationError as error:
            raise ReleaseLinkRefused(str(error)) from error

    def _unexpired(self, chain: Chain) -> None:
        now = self.clock.now_us()
        if type(now) is not int or now <= 0 or now >= chain.expires_at_us:
            raise ReleaseLinkRefused("inherited release authority has expired")

    @staticmethod
    def _scope(conn: Any, tenant: str) -> None:
        conn.execute("SELECT set_config('app.release_tenant',%s,true)", (tenant,))
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))

    def read(self, goal: GoalReleaseBinding, request: Any) -> ReleaseMaterial:
        """Preflight: material and inherited authority in one independent read transaction (no fences held)."""
        with self.pool.connection() as conn, conn.transaction():
            self._scope(conn, goal.tenant)
            material = self._material(conn, goal, request, lock=False)
            claim = self._claim(material.contract)
            chain = self._chain(conn, goal.tenant, claim)
            self._matches(chain, claim, goal)
        self._unexpired(chain)
        return material

    def locked_on(self, connection: Any, goal: GoalReleaseBinding, request: Any) -> ReleaseMaterial:
        """Inside the goal transaction: lock material, fence the chain's revocation, re-resolve, then judge expiry.
        Every lock is transaction-scoped on this connection and is held until publication commits or rolls back."""
        self._scope(connection, goal.tenant)
        material = self._material(connection, goal, request, lock=True)
        claim = self._claim(material.contract)
        chain = self._chain(connection, goal.tenant, claim)
        self._matches(chain, claim, goal)
        epoch = connection.execute("SELECT COALESCE(MAX(epoch),0) FROM regulated_revocation_events_v1"
                                   " WHERE tenant=%s", (goal.tenant,)).fetchone()[0]
        try:
            lock_current_authority(connection, tenant_id=goal.tenant, expected_epoch=int(epoch),
                                   grant_digests=tuple(grant.digest() for grant in chain.grants))
        except EmissionError as error:
            raise ReleaseLinkRefused(str(error)) from error
        # A grant revoked while this transaction waited for the fences is now visible (READ COMMITTED).
        fenced = self._chain(connection, goal.tenant, claim)
        if fenced != chain:
            raise ReleaseLinkRefused("inherited authority changed while waiting for its fences")
        self._unexpired(fenced)
        return material


class GoalOwnerAuthorization:
    """The admission's authorize port: the authenticated principal must be the current owner of the goal."""

    def __init__(self, *, pool: Any) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("goal authorization requires the release linker pool")
        self.pool = pool

    @staticmethod
    def _check(conn: Any, identity: Any, request: Any) -> None:
        conn.execute("SELECT set_config('app.release_tenant',%s,true)", (identity.tenant,))
        head = conn.execute("SELECT lock_anchor FROM reference_release_goal_heads_v1"
                            " WHERE tenant=%s AND goal_id=%s FOR SHARE",
                            (identity.tenant, request.goal_id)).fetchone()
        if head is None:
            raise ReleaseLinkRefused("retained goal head is unavailable")
        goal = _goal_on(conn, identity.tenant, request.goal_id)
        if goal.owner != identity.principal:
            raise ReleaseLinkRefused("only the authenticated goal owner may link a release")

    def __call__(self, identity: Any, request: Any, *, connection: Any = None) -> None:
        if connection is not None:
            self._check(connection, identity, request)
            return
        with self.pool.connection() as conn, conn.transaction():
            self._check(conn, identity, request)


class LinkedReleaseSource:
    """Receiving-side delegated source status: the release's grant must be named by exactly one published link
    whose goal is still that goal's current, unexpired version. Read-only; composed as the host's
    ``delegation_source_status``."""

    def __init__(self, *, pool: Any, clock_us: Callable[[], int]) -> None:
        if not callable(getattr(pool, "connection", None)) or not callable(clock_us):
            raise TypeError("linked release source requires a read pool and the trusted clock")
        self.pool, self.clock_us = pool, clock_us

    def __call__(self, tenant: str, grant_digest: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.release_tenant',%s,true)", (tenant,))
            rows = conn.execute("SELECT goal_id,payload_digest,payload FROM reference_release_links_v1"
                                " WHERE tenant=%s AND payload->'review'->'authority'->>'grant_digest'=%s",
                                (tenant, grant_digest)).fetchall()
            if len(rows) != 1:
                raise EmissionError("delegated release has no single published goal link")
            goal_id, expected, payload = rows[0]
            payload = payload if isinstance(payload, dict) else json.loads(payload)
            if digest_hex(payload) != expected:
                raise EmissionError("published release link failed integrity")
            current = _goal_on(conn, tenant, goal_id)
        linked = payload.get("goal")
        if not isinstance(linked, dict) or linked != {f.name: getattr(current, f.name)
                                                       for f in dataclass_fields(GoalReleaseBinding)}:
            raise EmissionError("the linked goal changed after the release was linked")
        if self.clock_us() >= current.expires_at_us:
            raise EmissionError("the linked goal has expired")


__all__ = ["CONTEXT_FIELDS", "ChainBoundReleaseMaterial", "GoalOwnerAuthorization", "LinkedReleaseSource",
           "MATERIAL_TABLE", "migrate_release_materials", "provision_release_material",
           "reference_project_executor"]
