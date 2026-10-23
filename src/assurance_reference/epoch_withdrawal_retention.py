"""Retain an original signed supervisor review before permit issuance.

This is storage admission, not an approval issuer. The caller obtains the
ApprovedDecision through the configured approval workflow and authenticated
supervisor identity flow. The epoch writer independently verifies it again.
"""
from regulated_core.approval import ApprovedDecision
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.persistence_pg import PersistenceError, _tenant
from regulated_core.review_store import PostgresReviewStore

from assurance_reference.epoch_withdrawal_admission import checked_change, verify_supervisor_approval
from assurance_reference.epoch_withdrawal_review import (
    EpochWithdrawalReviewLoader, _LockedRosterObservation, encode_review,
)


def retain_approved_withdrawal(loader, *, tenant_id, change, requester_id, approved):
    """Store once under roster-before-review locks; never refresh signed evidence."""
    if not isinstance(loader, EpochWithdrawalReviewLoader) or not isinstance(approved, ApprovedDecision):
        raise TypeError("withdrawal retention requires configured loader and original approved decision")
    if tenant_id != loader.roster._proof_verifier.tenant:
        raise PersistenceError("withdrawal retention tenant differs from configured roster authority")
    change = checked_change(tenant_id, change)
    review_id = approved.certificate.request_id
    if not isinstance(review_id, str) or not review_id.strip():
        raise PersistenceError("withdrawal retention requires an explicit review ID")
    proposed = encode_review(tenant_id, change, approved)
    with loader.reviews._pool.connection() as connection, connection.transaction():
        _tenant(connection, tenant_id)
        isolation = connection.execute("SELECT current_setting('transaction_isolation')").fetchone()[0]
        if isolation != "read committed":
            raise PersistenceError("withdrawal retention requires READ COMMITTED")
        connection.execute("SELECT pg_advisory_xact_lock_shared(hashtextextended(%s, 0))",
                           ("regulated-governance-roster:" + loader.installation,))
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                           ("regulated-review-v1:" + digest_hex([tenant_id, review_id]),))
        row = PostgresReviewStore._latest(connection, tenant_id, review_id)
        if row is not None and canonical_bytes(PostgresReviewStore._payload(row)) != canonical_bytes(proposed):
            raise PersistenceError("withdrawal review ID already retains different original evidence")
        # The receiver already holds the database-wide shared roster lock.
        # Keep roster rows confined to the configured governor login. The
        # receiver lock remains held until its review write commits.
        with loader.roster._pool.connection() as roster_connection, roster_connection.transaction():
            _tenant(roster_connection, tenant_id)
            if roster_connection.execute("SELECT current_setting('transaction_isolation')").fetchone()[0] != "read committed":
                raise PersistenceError("withdrawal roster retention requires READ COMMITTED")
            history = loader.roster._verified_history(roster_connection, loader.installation)
        if not history:
            raise PersistenceError("withdrawal retention requires a verified persisted roster")
        observation = _LockedRosterObservation(loader.installation, history[-1][0])
        now = loader.clock.read_on(connection).now_us
        verify_supervisor_approval(approved, workflow=loader.workflow, recorder=loader.recorder,
            roster_store=observation, installation=loader.installation, tenant_id=tenant_id,
            change=change, requester_id=requester_id, now_us=now)
        if row is None:
            connection.execute(
                "INSERT INTO regulated_reviews_v1 (tenant,review_id,version,payload_digest,payload)"
                " VALUES (%s,%s,%s,%s,%s::jsonb)",
                (tenant_id, review_id, 0, digest_hex(proposed), canonical_bytes(proposed).decode("utf-8")))
    return review_id
