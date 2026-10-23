"""Prepared database effects with atomic settlement and terminal reconciliation.

The configured receiver and target are trusted code. SQL privileges must keep
executors out of their credentials. Python objects do not provide that custody.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from .approval import ApprovalWorkflow
from .authority_fence_pg import lock_database_target
from .clock import ConnectionClock
from .canonical import digest_hex
from .budget import BudgetError
from .delegated_effect_pg import DelegatedEffectVerifier
from .evidence_checkpoints_pg import PinnedVerifier
from .input_evidence import InputVerifier
from .permit import EmissionError
from .persistence_pg import PostgresMissionBudget, _tenant
from .prepared_issuance_pg import load_preparation_on
from .retained_authority_pg import claim_retained_authorization
from .signing import TrustDirectory
from .target import Outcome, SignedTargetPermit, TargetRef, TargetResult, require_permit_clock

SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_database_attempts_v1 (
 tenant TEXT NOT NULL, nonce TEXT NOT NULL, permit_digest TEXT NOT NULL,
 target_digest TEXT NOT NULL, operation TEXT NOT NULL, output_digest TEXT NOT NULL,
 PRIMARY KEY(tenant,nonce));
CREATE TABLE IF NOT EXISTS regulated_database_receipts_v1 (
 tenant TEXT NOT NULL, nonce TEXT NOT NULL, permit_digest TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('committed','not_committed')),
 target_state TEXT NOT NULL,
 PRIMARY KEY(tenant,nonce),
 FOREIGN KEY(tenant,nonce) REFERENCES regulated_database_attempts_v1(tenant,nonce));
CREATE OR REPLACE FUNCTION regulated_database_writer_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM regulated_budget_writer_roles_v1
               WHERE role_name=session_user AND kind='consume') THEN
  RAISE EXCEPTION 'database receiver login required' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
DO $$
BEGIN
 EXECUTE format('ALTER FUNCTION %I.regulated_database_writer_v1() SET search_path = pg_catalog, %I, pg_temp',
                current_schema(), current_schema());
END $$;
"""
for _table in ("regulated_database_attempts_v1", "regulated_database_receipts_v1"):
    SCHEMA += f"""
ALTER TABLE {_table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {_table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS receiver_tenant_v1 ON {_table};
CREATE POLICY receiver_tenant_v1 ON {_table}
 USING(tenant=current_setting('app.tenant',true))
 WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS receiver_insert_v1 ON {_table};
CREATE TRIGGER receiver_insert_v1 BEFORE INSERT ON {_table}
 FOR EACH ROW EXECUTE FUNCTION regulated_database_writer_v1();
DROP TRIGGER IF EXISTS receiver_immutable_v1 ON {_table};
CREATE TRIGGER receiver_immutable_v1 BEFORE UPDATE OR DELETE ON {_table}
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS receiver_no_truncate_v1 ON {_table};
CREATE TRIGGER receiver_no_truncate_v1 BEFORE TRUNCATE ON {_table}
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


class DatabaseEffect(Protocol):
    """A host-configured target using only the receiver's supplied connection."""

    tenant_id: str
    target: TargetRef
    operation: str

    def current_state_on(self, conn: Any) -> str:
        """Read and lock authoritative state and ownership."""
        ...

    def apply_on(self, conn: Any, output: bytes) -> str:
        """Write exact approved state and return its new revision digest."""
        ...


class DatabaseAdmission(Protocol):
    """Host admission held on the receiving transaction until settlement.

    Implementations authenticate the exact signed request, take their customer
    and review locks before core authority locks, and return a database-clock
    expiry in microseconds. Refusal must raise EmissionError. A callback must
    use only the supplied connection and must never commit it. Construction is
    trusted host configuration; request data cannot select this verifier.
    """

    def lock_current_on(
        self, conn: Any, signed: SignedTargetPermit, target: TargetRef
    ) -> int:
        """Verify and fence current admission, returning its exclusive deadline."""
        ...


@dataclass(frozen=True)
class ReceiverAuthority:
    """Explicit verification configuration, with no permit signing capability."""

    trust: TrustDirectory
    issuer_key_id: str
    evidence_key_id: str
    policy_version: str
    max_decision_age_us: int
    history: PinnedVerifier
    inputs: InputVerifier
    approvals: ApprovalWorkflow | None = None
    delegation: DelegatedEffectVerifier | None = None
    clock: ConnectionClock | None = None

    def claim_on(self, conn: Any, signed: SignedTargetPermit, target: TargetRef) -> None:
        claim_retained_authorization(
            conn,
            signed,
            evidence_trust=self.trust,
            current_evidence_key_id=self.evidence_key_id,
            expected_policy_version=self.policy_version,
            max_decision_age_us=self.max_decision_age_us,
            evidence_verifier=self.history,
            input_verifier=self.inputs,
            approval_authority=self.approvals,
            delegated_verifier=self.delegation,
            fence_grant_digests=None if signed.permit.grant_digest else (),
            require_preparation=True,
            target_ref=target,
        )


class PostgresTargetReceiver:
    """Commit one exact database effect or reconcile its durable attempt.

    Reconciliation of an attempted but uncommitted operation writes a terminal
    tombstone under its target lock. A delayed receiver must honor it. No
    attempt, an unavailable database or a lock timeout remains UNKNOWN.
    """

    def __init__(
        self,
        *,
        pool: Any,
        effect: DatabaseEffect,
        authority: ReceiverAuthority,
        lock_timeout_ms: int = 2000,
        admission: DatabaseAdmission | None = None,
    ) -> None:
        if type(lock_timeout_ms) is not int or lock_timeout_ms < 1:
            raise ValueError("a positive lock timeout is required")
        self._pool, self._effect, self._authority = pool, effect, authority
        self._timeout = lock_timeout_ms
        self._admission = admission

    @property
    def target(self) -> TargetRef:
        return self._effect.target

    @property
    def operation(self) -> str:
        return self._effect.operation

    def _authenticate(self, signed: SignedTargetPermit) -> None:
        p = signed.permit
        if (
            signed.signature.key_id != self._authority.issuer_key_id
            or not self._authority.trust.verify(p.signed_body(), signed.signature)
            or not p.preparation_digest
            or p.tenant_id != self._effect.tenant_id
            or p.target_kind != self.target.kind
            or p.target_digest != self.target.digest()
            or p.operation != self.operation
        ):
            raise EmissionError("database permit authentication or target binding failed")

    def _scope(self, conn: Any) -> None:
        _tenant(conn, self._effect.tenant_id)
        conn.execute("SELECT set_config('lock_timeout',%s,true)", (f"{self._timeout}ms",))

    @staticmethod
    def _fresh(conn: Any) -> None:
        from psycopg.pq import TransactionStatus

        if conn.info.transaction_status != TransactionStatus.IDLE:
            raise EmissionError("receiver requires its own fresh transaction")

    def _lock(self, conn: Any) -> None:
        lock_database_target(
            conn, tenant_id=self._effect.tenant_id, target_digest=self.target.digest()
        )

    def _attempt(self, conn: Any, signed: SignedTargetPermit) -> bool:
        p = signed.permit
        row = conn.execute(
            "SELECT permit_digest,target_digest,operation,output_digest FROM regulated_database_attempts_v1"
            " WHERE tenant=%s AND nonce=%s",
            (p.tenant_id, p.nonce),
        ).fetchone()
        expected = (digest_hex(p.signed_body()), p.target_digest, p.operation, p.output_digest)
        if row is not None and tuple(row) != expected:
            raise EmissionError("nonce belongs to a different exact database permit")
        return row is not None

    def _receipt(self, conn: Any, signed: SignedTargetPermit) -> TargetResult | None:
        p = signed.permit
        row = conn.execute(
            "SELECT permit_digest,outcome,target_state FROM regulated_database_receipts_v1"
            " WHERE tenant=%s AND nonce=%s",
            (p.tenant_id, p.nonce),
        ).fetchone()
        if row is None:
            return None
        if row[0] != digest_hex(p.signed_body()):
            raise EmissionError("receipt belongs to a different permit")
        return TargetResult(Outcome(row[1]), "durable receiving outcome", row[2])

    def _finish(
        self, conn: Any, signed: SignedTargetPermit, outcome: Outcome, state: str = ""
    ) -> None:
        p = signed.permit
        conn.execute(
            "INSERT INTO regulated_database_receipts_v1"
            " (tenant,nonce,permit_digest,outcome,target_state) VALUES (%s,%s,%s,%s,%s)",
            (p.tenant_id, p.nonce, digest_hex(p.signed_body()), outcome.value, state),
        )

    def current_state(self) -> str:
        with self._pool.connection() as conn:
            self._fresh(conn)
            with conn.transaction():
                self._scope(conn)
                self._lock(conn)
                return self._effect.current_state_on(conn)

    def _admit_on(self, conn: Any, signed: SignedTargetPermit) -> int:
        """Fence host admission before core locks and retain its earlier expiry."""
        deadline = signed.permit.expires_at_us
        if self._admission is not None:
            admitted_until = self._admission.lock_current_on(conn, signed, self.target)
            if type(admitted_until) is not int or admitted_until <= 0:
                raise EmissionError("database admission returned an invalid deadline")
            deadline = min(deadline, admitted_until)
        reading = require_permit_clock(signed.permit, self._authority.clock, connection=conn)
        if reading is None:
            raise EmissionError("database receiver requires a qualified clock")
        if reading.now_us >= deadline:
            raise EmissionError("database admission or permit expired before claim")
        return deadline

    def commit(self, signed: SignedTargetPermit, output: bytes) -> TargetResult:
        import psycopg

        attempted = False
        try:
            self._authenticate(signed)
            if (
                not isinstance(output, bytes)
                or sha256(output).hexdigest() != signed.permit.output_digest
            ):
                raise EmissionError("database effect bytes differ from the permit")
            # Durable intent grants no effect authority. A terminal receipt can
            # cancel this intent while the effect transaction waits on authority.
            with self._pool.connection() as conn:
                self._fresh(conn)
                with conn.transaction():
                    self._scope(conn)
                    self._lock(conn)
                    if not self._attempt(conn, signed):
                        p = signed.permit
                        conn.execute(
                            "INSERT INTO regulated_database_attempts_v1 VALUES (%s,%s,%s,%s,%s,%s)",
                            (
                                p.tenant_id,
                                p.nonce,
                                digest_hex(p.signed_body()),
                                p.target_digest,
                                p.operation,
                                p.output_digest,
                            ),
                        )
                    known = self._receipt(conn, signed)
                    if known is not None:
                        return known
            attempted = True
            with self._pool.connection() as conn:
                self._fresh(conn)
                with conn.transaction():
                    self._scope(conn)
                    deadline = self._admit_on(conn, signed)
                    self._authority.claim_on(conn, signed, self.target)
                    # Admission imposes customer -> review, followed by core
                    # authority -> target -> mission on this same transaction.
                    if not self._attempt(conn, signed) or self._receipt(conn, signed) is not None:
                        raise EmissionError("database attempt already terminal or absent")
                    p = signed.permit
                    if self._effect.current_state_on(conn) != p.expected_target_state:
                        raise EmissionError("database target revision changed")
                    proof = load_preparation_on(
                        conn,
                        p,
                        issuer_key_id=self._authority.issuer_key_id,
                        evidence_trust=self._authority.trust,
                        current_evidence_key_id=self._authority.evidence_key_id,
                    ).signed_body()
                    PostgresMissionBudget(pool=None).consume_on(
                        conn,
                        p.tenant_id,
                        p.mission,
                        p.budget_reservation,
                        subject_digest=proof["subject_digest"],
                        units=proof["budget_units"],
                        limit=proof["budget_limit"],
                    )
                    conn.execute(
                        "INSERT INTO regulated_permit_uses_v1(tenant,nonce) VALUES(%s,%s)",
                        (p.tenant_id, p.nonce),
                    )
                    state = self._effect.apply_on(conn, output)
                    self._finish(conn, signed, Outcome.COMMITTED, state)
                    # Roll back transactional writes when expiry is observable.
                    # The interval until durable COMMIT remains a paper obligation.
                    reading = require_permit_clock(p, self._authority.clock, connection=conn)
                    if reading is None:
                        raise EmissionError("database receiver requires a qualified clock")
                    if reading.now_us >= deadline:
                        raise EmissionError("authority expired before database commit")
            return TargetResult(Outcome.COMMITTED, "database effect and receipt committed", state)
        except (EmissionError, BudgetError) as exc:
            if attempted:
                # Another delivery may have committed the same permit while
                # this transaction waited. Resolve under the same target lock;
                # rollback here alone does not prove a globally absent effect.
                known = self.status(signed)
                if known.outcome is not Outcome.NOT_COMMITTED:
                    return known
            return TargetResult(Outcome.FAILED, str(exc))
        except (psycopg.OperationalError, psycopg.InterfaceError):
            return TargetResult(
                Outcome.UNKNOWN, "database outcome unavailable; reconcile exact permit"
            )

    def observe(self, signed: SignedTargetPermit) -> TargetResult:
        """Read a retained outcome without delivery or terminal reconciliation.

        The exact signed permit authenticates this historical lookup, including
        after its delivery deadline. The caller remains responsible for current
        customer access. One statement observes the attempt and receipt together
        in a read-only transaction. Missing evidence stays UNKNOWN: it cannot
        establish failure or prevent an in-flight delivery from completing.
        """
        import psycopg

        try:
            self._authenticate(signed)
            p = signed.permit
            with self._pool.connection() as conn:
                self._fresh(conn)
                with conn.transaction():
                    conn.execute("SET TRANSACTION READ ONLY")
                    self._scope(conn)
                    row = conn.execute(
                        "SELECT a.permit_digest,a.target_digest,a.operation,a.output_digest,"
                        "r.permit_digest,r.outcome,r.target_state "
                        "FROM regulated_database_attempts_v1 a "
                        "LEFT JOIN regulated_database_receipts_v1 r "
                        "ON r.tenant=a.tenant AND r.nonce=a.nonce "
                        "WHERE a.tenant=%s AND a.nonce=%s",
                        (p.tenant_id, p.nonce),
                    ).fetchone()
            if row is None:
                return TargetResult(Outcome.UNKNOWN, "no durable attempt is known")
            expected = (digest_hex(p.signed_body()), p.target_digest, p.operation, p.output_digest)
            if tuple(row[:4]) != expected:
                raise EmissionError("attempt belongs to a different exact database permit")
            if row[4] is None:
                return TargetResult(Outcome.UNKNOWN, "no durable receiving outcome is known")
            if row[4] != expected[0] or row[5] not in {"committed", "not_committed"}:
                raise EmissionError("receipt differs from the exact database permit")
            return TargetResult(Outcome(row[5]), "durable receiving outcome", row[6])
        except EmissionError as exc:
            return TargetResult(Outcome.UNKNOWN, str(exc))
        except psycopg.Error:
            return TargetResult(Outcome.UNKNOWN, "database outcome unavailable")

    def status(self, signed: SignedTargetPermit) -> TargetResult:
        import psycopg

        try:
            self._authenticate(signed)
            with self._pool.connection() as conn:
                self._fresh(conn)
                with conn.transaction():
                    self._scope(conn)
                    self._lock(conn)
                    if not self._attempt(conn, signed):
                        return TargetResult(Outcome.UNKNOWN, "no durable attempt is known")
                    known = self._receipt(conn, signed)
                    if known is not None:
                        return known
                    self._finish(conn, signed, Outcome.NOT_COMMITTED)
            return TargetResult(
                Outcome.NOT_COMMITTED, "attempt terminally reconciled without an effect"
            )
        except EmissionError as exc:
            return TargetResult(Outcome.UNKNOWN, str(exc))
        except (psycopg.OperationalError, psycopg.InterfaceError):
            return TargetResult(Outcome.UNKNOWN, "database outcome unavailable or still in flight")

    def status_of(self, tenant_id: str, nonce: str, output_digest: str) -> TargetResult:
        """An unbound lookup cannot establish an authenticated receiving outcome."""
        return TargetResult(Outcome.UNKNOWN, "reconciliation requires the exact signed permit")
