"""One sole-owner self-approval check, used at grant, at settlement and inside the receiving transaction (X-3).

Generic form of the frozen ``factory/customer/studio_self_approval_pg.py@6bba989a``
(``require_studio_self_approval_on``) and its signed term
(``studio_owner_policy._valid_self_approval_term``):

* a requester may approve their own action only where the installed signed rulebook
  says so for that exact action: ``requester_may_approve`` true together with the
  explicit ``self_approval_term`` ``sole-owner/v1``. Either half without the other
  is a malformed policy and refuses startup; no request flag enables the rule;
* each check runs on a caller-owned READ COMMITTED transaction, takes the tenant's
  owner-roster lock in shared mode (roster writers take it exclusively), reads the
  roster on the trusted clock and requires the requester to be the tenant's one
  current owner and a currently active member identity. A second current owner, an
  expired or revoked roster entry, a deactivated or missing identity, or a producer
  that is also the requester refuses;
* a future owner activation bounds the authority: the earliest pending activation
  is returned as a deadline that the effect must precede.

Grants by anyone other than the requester are unaffected and return ``None``.
This does not replace credential, approval-certificate or policy verification.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from psycopg import sql
from psycopg.pq import TransactionStatus

from regulated_core.identity_provider import CredentialError

SOLE_OWNER_TERM = "sole-owner/v1"
ROSTER_TABLE = "reference_tenant_owners_v1"


def roster_lock_key(tenant: str) -> str:
    return "reference-owner-roster:" + tenant


def validate_self_approval_terms(pack: Any) -> None:
    """Startup: every governed approval either forbids self-approval or names exactly the sole-owner term."""
    for action, rule in pack.rulebook.effective_content["rules"].items():
        approval = rule.get("approval")
        if approval is None:
            continue
        allowed, term = approval.get("requester_may_approve", False), approval.get("self_approval_term")
        if not ((allowed is False and term is None) or (allowed is True and term == SOLE_OWNER_TERM)):
            raise ValueError(f"{action}: self-approval requires exactly requester_may_approve with the "
                             f"signed {SOLE_OWNER_TERM} term")


def migrate_owner_roster(owner: Any, reader_role: str) -> None:
    """Fresh isolated schema only. Owner-provisioned roster; the runtime reader may only SELECT it."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(f"""CREATE TABLE {ROSTER_TABLE}(
            tenant text NOT NULL, principal text NOT NULL,
            active_from_us bigint NOT NULL CHECK(active_from_us >= 0),
            expires_at_us bigint CHECK(expires_at_us IS NULL OR expires_at_us > active_from_us),
            revoked_at_us bigint, PRIMARY KEY(tenant,principal))""")
        name = sql.Identifier(ROSTER_TABLE)
        conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(name))
        conn.execute(sql.SQL("CREATE POLICY owner_roster_scope ON {} USING "
                             "(tenant=current_setting('app.tenant',true)) WITH CHECK "
                             "(tenant=current_setting('app.tenant',true))").format(name))
        conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
        conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(name, sql.Identifier(reader_role)))


def set_tenant_owner(owner: Any, *, tenant: str, principal: str, active_from_us: int,
                     expires_at_us: int | None = None, revoked_at_us: int | None = None) -> None:
    """Owner-only roster write under the exclusive roster lock; checks holding the shared lock wait for it."""
    with owner.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (roster_lock_key(tenant),))
        conn.execute(f"INSERT INTO {ROSTER_TABLE}(tenant,principal,active_from_us,expires_at_us,revoked_at_us)"
                     " VALUES(%s,%s,%s,%s,%s) ON CONFLICT(tenant,principal) DO UPDATE SET"
                     " active_from_us=EXCLUDED.active_from_us, expires_at_us=EXCLUDED.expires_at_us,"
                     " revoked_at_us=EXCLUDED.revoked_at_us",
                     (tenant, principal, active_from_us, expires_at_us, revoked_at_us))


def require_sole_owner_self_approval_on(connection: Any, *, pack: Any, record: Any, reviewers: Iterable[str],
                                        producer: str, clock_us: Callable[[], int]) -> int | None:
    """Check sole current ownership for a self-approval; ``None`` when the requester is not among the reviewers.

    Call after authenticating the retained review. A prospective grant supplies its authenticated reviewer; the
    settlement and receiving checks pass the retained grants' reviewers. The returned deadline, when not None, must
    bound the effect. The shared roster lock is held until the caller's transaction ends.
    """
    if record.actor_id not in set(reviewers):
        return None
    ref = pack.rulebook.ref
    if ((record.policy.vertical, record.policy.policy_id, record.policy.version, record.policy.digest) !=
            (ref.vertical, ref.policy_id, ref.version, ref.digest) or not record.tenant_id
            or not record.actor_id or record.actor_id == producer):
        raise CredentialError("self-approval requires its signed sole-owner policy")
    validate_self_approval_terms(pack)
    rule = pack.rulebook.effective_content["rules"].get(record.action.action_id, {})
    requirement = record.decision.approval
    if (requirement is None or not requirement.requester_may_approve
            or rule.get("approval", {}).get("self_approval_term") != SOLE_OWNER_TERM):
        raise CredentialError("the signed sole-owner self-approval term is not present")
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise CredentialError("sole-owner self-approval requires the caller's transaction")
    if connection.execute("SHOW transaction_isolation").fetchone()[0] != "read committed":
        raise CredentialError("sole-owner self-approval requires READ COMMITTED")
    connection.execute("SELECT set_config('app.tenant',%s,true)", (record.tenant_id,))
    connection.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s,0))",
                       (roster_lock_key(record.tenant_id),))
    rows = connection.execute(f"SELECT principal,active_from_us,expires_at_us,revoked_at_us FROM {ROSTER_TABLE}"
                              " WHERE tenant=%s ORDER BY principal", (record.tenant_id,)).fetchall()
    now = clock_us()
    if type(now) is not int or now <= 0:
        raise CredentialError("sole-owner self-approval requires the trusted clock")
    owners, future = set(), []
    for principal, active_from, expires, revoked in rows:
        if revoked is not None or (expires is not None and expires <= now):
            continue
        if active_from <= now:
            owners.add(principal)
        elif principal != record.actor_id:
            future.append(int(active_from))
    if owners != {record.actor_id}:
        raise CredentialError("self-approval requires the current sole tenant owner")
    # Current identity membership, read in this same transaction: a deactivated or removed requester is no member.
    member = connection.execute("SELECT active FROM reference_identities_v1 WHERE tenant=%s AND principal=%s",
                                (record.tenant_id, record.actor_id)).fetchone()
    if member is None or member[0] is not True:
        raise CredentialError("self-approval requires the requester's current tenant membership")
    return min(future) if future else None


__all__ = ["ROSTER_TABLE", "SOLE_OWNER_TERM", "migrate_owner_roster", "require_sole_owner_self_approval_on",
           "roster_lock_key", "set_tenant_owner", "validate_self_approval_terms"]
