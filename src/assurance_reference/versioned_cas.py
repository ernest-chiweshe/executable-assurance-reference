"""Explicitly admitted versioned-row effects over the existing PG receiver.

New reference composition for frozen X-1/X-2. Existing draft integrations are
unchanged. The host verifier authenticates and locks current retained approval;
the receiver retains its independent signature, currentness, nonce and budget
checks. Python proof objects are not credential custody or a security sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
from typing import Any, Callable
from weakref import WeakKeyDictionary, ref

from psycopg.pq import TransactionStatus

from regulated_core.canonical import digest_hex
from regulated_core.database_receiver_pg import PostgresTargetReceiver
from regulated_core.permit import EmissionError
from regulated_core.target import ABSENT, SignedTargetPermit, TargetRef


SCHEMA = """
CREATE TABLE IF NOT EXISTS reference_versioned_state_v1 (
 tenant TEXT NOT NULL, target TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision >= 0),
 body BYTEA NOT NULL, PRIMARY KEY(tenant,target));
ALTER TABLE reference_versioned_state_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE reference_versioned_state_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS versioned_tenant_v1 ON reference_versioned_state_v1;
CREATE POLICY versioned_tenant_v1 ON reference_versioned_state_v1
 USING(tenant=current_setting('app.tenant',true))
 WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS versioned_writer_v1 ON reference_versioned_state_v1;
CREATE TRIGGER versioned_writer_v1 BEFORE INSERT OR UPDATE ON reference_versioned_state_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_database_writer_v1();
DROP TRIGGER IF EXISTS versioned_no_delete_v1 ON reference_versioned_state_v1;
CREATE TRIGGER versioned_no_delete_v1 BEFORE DELETE ON reference_versioned_state_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS versioned_no_truncate_v1 ON reference_versioned_state_v1;
CREATE TRIGGER versioned_no_truncate_v1 BEFORE TRUNCATE ON reference_versioned_state_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


def _transaction_id(conn: Any) -> str:
    if conn.info.transaction_status != TransactionStatus.INTRANS:
        raise EmissionError("admission requires an active receiver transaction")
    row = conn.execute("SELECT pg_current_xact_id()::text").fetchone()
    if row is None or not isinstance(row[0], str) or not row[0]:
        raise EmissionError("database transaction identity unavailable")
    return row[0]


@dataclass(frozen=True)
class _Proof:
    connection: Any
    transaction_id: str
    output_digest: str
    permit_digest: str
    deadline: int


class TransactionBoundAdmission:
    """Keep one current proof per connection, consumed at the effect boundary.

    verify_on is trusted host composition, never request-selected. It must
    verify the exact signed request and current retained approval, acquire
    customer/review locks in the established order, and return an exclusive
    database-clock deadline. It must not commit or leave the supplied transaction.
    The receiver checks that deadline before claim and before commit.
    """

    def __init__(self, *, tenant_id: str, target: TargetRef, operation: str,
                 verify_on: Callable[[Any, SignedTargetPermit, TargetRef], int]):
        if not tenant_id or not operation or not callable(verify_on):
            raise ValueError("configured tenant, operation and verifier are required")
        self.tenant_id, self.target, self.operation = tenant_id, target, operation
        self._verify = verify_on
        self._pending = WeakKeyDictionary()
        self._lock = Lock()

    def lock_current_on(self, conn, signed, target) -> int:
        with self._lock:
            self._pending.pop(conn, None)
        p = signed.permit
        if (target != self.target or p.tenant_id != self.tenant_id
                or p.target_kind != target.kind or p.target_digest != target.digest()
                or p.operation != self.operation):
            raise EmissionError("admission is not bound to this configured effect")
        transaction_id = _transaction_id(conn)
        deadline = self._verify(conn, signed, target)
        if type(deadline) is not int or deadline <= 0:
            raise EmissionError("admission verifier returned an invalid deadline")
        if _transaction_id(conn) != transaction_id:
            raise EmissionError("admission verifier left the receiver transaction")
        deadline = min(deadline, p.expires_at_us)
        proof = _Proof(ref(conn), transaction_id, p.output_digest,
                       digest_hex(p.signed_body()), deadline)
        with self._lock:
            self._pending[conn] = proof
        return min(deadline, p.expires_at_us)

    def require_effect_on(self, conn, output: bytes) -> None:
        # A failed consumption attempt also retires this in-memory proof.
        # Durable permit replay prevention remains the receiver's nonce table.
        with self._lock:
            proof = self._pending.pop(conn, None)
        if proof is None:
            raise EmissionError("one-use database admission proof required")
        if proof.connection() is not conn or proof.transaction_id != _transaction_id(conn):
            raise EmissionError("admission proof belongs to another transaction")
        if not isinstance(output, bytes) or sha256(output).hexdigest() != proof.output_digest:
            raise EmissionError("admission proof differs from exact effect bytes")
        row = conn.execute(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise EmissionError("database admission clock unavailable")
        if row[0] >= proof.deadline:
            raise EmissionError("database admission expired before effect")



def state_digest(revision: int, body: bytes) -> str:
    return digest_hex({"revision": revision, "body_sha256": sha256(body).hexdigest()})


@dataclass(frozen=True)
class VersionedRowEffect:
    """Exact-state CAS of an existing row; the uncomposed default refuses writes.

    Row creation is a separate host provisioning operation. This generic fixture
    does not supply customer ownership policy or qualify production credentials.
    Receiver authority checks and a transaction lock precede the write.
    """

    tenant_id: str
    target: TargetRef
    operation: str
    expected_revision: int

    def __post_init__(self):
        if (not self.tenant_id or not self.operation
                or type(self.expected_revision) is not int
                or not 0 <= self.expected_revision < 2**63 - 1):
            raise ValueError("valid tenant, operation and incrementable revision required")

    def current_state_on(self, conn) -> str:
        row = conn.execute(
            "SELECT revision,body FROM reference_versioned_state_v1 "
            "WHERE tenant=%s AND target=%s FOR UPDATE",
            (self.tenant_id, self.target.digest()),
        ).fetchone()
        return ABSENT if row is None else state_digest(row[0], bytes(row[1]))

    def _authorize_on(self, conn, output):
        raise EmissionError("versioned-row effect requires composed admission")

    def apply_on(self, conn, output: bytes) -> str:
        self._authorize_on(conn, output)
        if not isinstance(output, bytes):
            raise EmissionError("versioned-row effect requires exact bytes")
        row = conn.execute(
            "UPDATE reference_versioned_state_v1 SET revision=revision+1,body=%s "
            "WHERE tenant=%s AND target=%s AND revision=%s RETURNING revision,body",
            (output, self.tenant_id, self.target.digest(), self.expected_revision),
        ).fetchone()
        if row is None:
            raise EmissionError("versioned-row revision changed or row absent")
        if row[0] != self.expected_revision + 1 or bytes(row[1]) != output:
            raise EmissionError("versioned-row result differs from exact approved state")
        return state_digest(row[0], bytes(row[1]))


@dataclass(frozen=True)
class AdmittedVersionedRowEffect(VersionedRowEffect):
    admission: TransactionBoundAdmission

    def __post_init__(self):
        super().__post_init__()
        if (self.tenant_id, self.target, self.operation) != (
                self.admission.tenant_id, self.admission.target, self.admission.operation):
            raise ValueError("CAS effect and admission configuration differ")

    def _authorize_on(self, conn, output):
        self.admission.require_effect_on(conn, output)


def compose_versioned_receiver(*, pool, authority, tenant_id, target, operation,
                               expected_revision, verify_on, lock_timeout_ms=2000):
    """Pin the same admission to the receiver and its default-refusing CAS effect."""
    admission = TransactionBoundAdmission(
        tenant_id=tenant_id, target=target, operation=operation, verify_on=verify_on)
    effect = AdmittedVersionedRowEffect(
        tenant_id, target, operation, expected_revision, admission)
    return PostgresTargetReceiver(pool=pool, effect=effect, authority=authority,
                                  admission=admission, lock_timeout_ms=lock_timeout_ms)


class RetainedCasApprovalVerifier:
    """Recheck locked retained approval before the existing receiver claims.

    authenticate_and_lock_on is the host's mandatory customer/request boundary.
    It authenticates the principal and exact request, locks current customer
    and reviewer membership in the established order, and returns their earliest
    database-clock expiry. It must use the supplied transaction only.
    Review locking follows those customer locks. Core authority and target locks
    remain in PostgresTargetReceiver; this verifier neither claims nor writes.
    """

    def __init__(self, *, authority, authenticate_and_lock_on):
        if authority.approvals is None or authority.history is None:
            raise ValueError("retained CAS requires approval authority and pinned history")
        if not callable(authenticate_and_lock_on):
            raise ValueError("retained CAS requires a host authentication boundary")
        self.authority = authority
        self._authenticate = authenticate_and_lock_on

    def __call__(self, conn, signed, target) -> int:
        from regulated_core.persistence_pg import PersistenceError
        from regulated_core.retained_authority_pg import verify_retained_draft
        from regulated_core.review_store import PostgresReviewStore
        from regulated_core.target import require_permit_clock

        p = signed.permit
        authority = self.authority
        if (signed.signature.key_id != authority.issuer_key_id
                or not authority.trust.verify(p.signed_body(), signed.signature)
                or target.kind != p.target_kind or target.digest() != p.target_digest):
            raise EmissionError("retained CAS permit authentication failed")
        if not p.approval_ref:
            raise EmissionError("retained CAS requires an explicit approval reference")
        deadline = self._authenticate(conn, signed, target)
        if type(deadline) is not int or deadline <= 0:
            raise EmissionError("host authentication returned an invalid deadline")
        try:
            state = PostgresReviewStore.read_locked_on(conn, p.tenant_id, p.approval_ref)
            if state is None:
                raise EmissionError("retained CAS review is missing")
            # This is verification under customer/review locks, not the claim.
            # The receiver later rechecks and fences core authority independently.
            _, _, approval_digest = verify_retained_draft(
                conn, p, issuer_key_id=authority.issuer_key_id,
                evidence_trust=authority.trust,
                current_evidence_key_id=authority.evidence_key_id,
                expected_policy_version=authority.policy_version,
                max_decision_age_us=authority.max_decision_age_us,
                approval_authority=authority.approvals,
                evidence_verifier=authority.history,
            )
        except PersistenceError as exc:
            raise EmissionError("retained CAS review could not be authenticated") from exc
        if not approval_digest:
            raise EmissionError("retained CAS lacks verified approval")
        reading = require_permit_clock(p, authority.clock, connection=conn)
        deadline = min(deadline, p.expires_at_us)
        if reading is None or reading.now_us >= deadline:
            raise EmissionError("retained CAS admission expired")
        return deadline


def compose_retained_versioned_receiver(*, pool, authority, tenant_id, target,
                                       operation, expected_revision,
                                       authenticate_and_lock_on, lock_timeout_ms=2000):
    """Compose actual retained-review verification with transaction proof and CAS."""
    verifier = RetainedCasApprovalVerifier(
        authority=authority, authenticate_and_lock_on=authenticate_and_lock_on)
    return compose_versioned_receiver(
        pool=pool, authority=authority, tenant_id=tenant_id, target=target,
        operation=operation, expected_revision=expected_revision, verify_on=verifier,
        lock_timeout_ms=lock_timeout_ms)
