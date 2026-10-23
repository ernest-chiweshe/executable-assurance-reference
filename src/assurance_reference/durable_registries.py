"""Durable governed registries for checker qualification and approver-issuer recognition (A15, candidate 062).

The recovered qualification and certificate registries apply a governed change and its receiving receipt together, but
in process memory, so the reference refused to compose their governance targets. These PostgreSQL registries keep the
same governed-change contract (regulated_core/governance_targets.GovernedChange), inside one database transaction under
an advisory lock on the subject: (1) read the history and refuse unless it is the approved prior state; (2) run the
permit's final check, which consumes the mission budget on this same connection; (3) append the change AND its exact
receipt. A failure at any step rolls back the effect, the receipt and the consumption together. The receipt answers
COMMITTED for the exact key and UNKNOWN when absent, so a lost acknowledgement is resolved only by the receipt, never by
applying again.

Qualification reports and issuer recognitions are installation authority with no tenant content; the receipt, which
names the governing tenant and its nonce, lives in ``reference_governed_receipts_v1`` under forced row-level security on
``tenant = app.tenant`` (B-F7b). Every stored report is re-verified against the qualification authority on read.
"""
from __future__ import annotations

import json
from typing import Any

from psycopg import sql

from regulated_core.canonical import digest_hex
from regulated_core.governance_transaction import run_governance_check
from regulated_core.persistence_pg import _tenant
from regulated_core.qualification import (OperatingCharacteristics, QualificationError, QualificationReport,
                                          verify_report)
from regulated_core.signing import Signature, TrustDirectory

REPORTS, ISSUERS, RECEIPTS = ("reference_qualification_reports_v1", "reference_issuer_recognitions_v1",
                              "reference_governed_receipts_v1")


def migrate_governed_registries(owner: Any, *, writers: tuple[str, ...] = (), readers: tuple[str, ...] = ()) -> None:
    """Fresh schema only: append-only installation registries, the tenant-scoped receipt table, explicit grants."""
    with owner.connection() as conn, conn.transaction():
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reference_qualification_reports_v1 ("
            " verification_class TEXT NOT NULL CHECK (length(verification_class) > 0),"
            " seq BIGINT NOT NULL CHECK (seq > 0), report_digest TEXT NOT NULL UNIQUE CHECK (length(report_digest) = 64),"
            " body JSONB NOT NULL, signature JSONB NOT NULL,"
            " recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (verification_class, seq))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reference_issuer_recognitions_v1 ("
            " issuer_key_id TEXT NOT NULL CHECK (length(issuer_key_id) > 0),"
            " version BIGINT NOT NULL CHECK (version > 0), kind TEXT NOT NULL CHECK (length(kind) > 0),"
            " recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (issuer_key_id, version))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reference_governed_receipts_v1 ("
            " tenant TEXT NOT NULL CHECK (length(tenant) > 0), operation TEXT NOT NULL CHECK (length(operation) > 0),"
            " nonce TEXT NOT NULL CHECK (length(nonce) > 0), change_digest TEXT NOT NULL CHECK (length(change_digest) = 64),"
            " subject TEXT NOT NULL CHECK (length(subject) > 0),"
            " recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant, operation, nonce))")
        conn.execute("ALTER TABLE reference_governed_receipts_v1 ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE reference_governed_receipts_v1 FORCE ROW LEVEL SECURITY")
        conn.execute("DROP POLICY IF EXISTS governed_receipt_tenant ON reference_governed_receipts_v1")
        conn.execute("CREATE POLICY governed_receipt_tenant ON reference_governed_receipts_v1"
                     " USING (tenant = current_setting('app.tenant', true))"
                     " WITH CHECK (tenant = current_setting('app.tenant', true))")
        for table in (REPORTS, ISSUERS, RECEIPTS):
            name = sql.Identifier(table)
            conn.execute(sql.SQL("DROP TRIGGER IF EXISTS governed_registry_immutable ON {}").format(name))
            conn.execute(sql.SQL("CREATE TRIGGER governed_registry_immutable BEFORE UPDATE OR DELETE ON {} "
                                 "FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1()").format(name))
            conn.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(name))
            for role in writers:
                conn.execute(sql.SQL("GRANT SELECT, INSERT ON {} TO {}").format(name, sql.Identifier(role)))
        for role in readers:
            for table in (REPORTS, ISSUERS):
                conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(sql.Identifier(table), sql.Identifier(role)))


def _lock(conn: Any, subject: str) -> None:
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("reference-governed-registry:" + subject,))


def _receipt_on(conn: Any, governed: Any) -> None:
    conn.execute("INSERT INTO reference_governed_receipts_v1 (tenant, operation, nonce, change_digest, subject)"
                 " VALUES (%s, %s, %s, %s, %s)", (governed.tenant_id, governed.operation, governed.nonce,
                                                 governed.change_digest, governed.subject))


class _GovernedReceipts:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def governance_receipt(self, tenant_id: str, operation: str, nonce: str, change_digest: str) -> Any:
        """COMMITTED only for the exact durable receipt; UNKNOWN when absent (never NOT_COMMITTED by absence)."""
        from regulated_core.target import Outcome
        with self._pool.connection() as conn, conn.transaction():
            _tenant(conn, tenant_id)
            row = conn.execute("SELECT change_digest FROM reference_governed_receipts_v1"
                               " WHERE tenant=%s AND operation=%s AND nonce=%s", (tenant_id, operation, nonce)).fetchone()
        return Outcome.COMMITTED if row is not None and row[0] == change_digest else Outcome.UNKNOWN


def _report(body: Any, signature: Any) -> QualificationReport:
    body = body if isinstance(body, dict) else json.loads(body)
    signature = signature if isinstance(signature, dict) else json.loads(signature)
    c = body["characteristics"]
    return QualificationReport(
        verification_class=body["verification_class"], verifier_version=body["verifier_version"],
        dataset_id=body["dataset_id"], dataset_version=body["dataset_version"], dataset_digest=body["dataset_digest"],
        characteristics=OperatingCharacteristics(c["precision"], c["recall"], c["f1"], c["tp"], c["fp"], c["fn"],
                                                 c["tn"], tuple(c["jurisdictions"]), tuple(c["languages"]),
                                                 tuple(c["document_types"])),
        qualified_at_us=body["qualified_at_us"], expires_at_us=body["expires_at_us"],
        qualified_by=body["qualified_by"], limitations=tuple(body["limitations"]), supersedes=body["supersedes"],
        signature=Signature(**signature))


class PostgresQualificationRegistry(_GovernedReceipts):
    """Durable, append-only, trust-anchored qualification history; written only through the governance target."""

    def __init__(self, *, pool: Any, trust: TrustDirectory, authority: str, guard: Any = None) -> None:
        if not isinstance(trust, TrustDirectory) or not authority:
            raise TypeError("a durable qualification registry needs its trust directory and qualification authority")
        super().__init__(pool)
        self._trust, self._authority, self.governance_guard = trust, authority, guard

    def _history_on(self, conn: Any, verification_class: str) -> tuple[QualificationReport, ...]:
        rows = conn.execute("SELECT seq, report_digest, body, signature FROM reference_qualification_reports_v1"
                            " WHERE verification_class=%s ORDER BY seq", (verification_class,)).fetchall()
        reports = []
        for index, (seq, digest, body, signature) in enumerate(rows):
            report = _report(body, signature)
            if (seq != index + 1 or report.digest() != digest or report.verification_class != verification_class
                    or not verify_report(self._trust, report, authority=self._authority)):
                raise QualificationError("stored qualification history failed verification")
            reports.append(report)
        return tuple(reports)

    def history(self, verification_class: str) -> tuple[QualificationReport, ...]:
        with self._pool.connection() as conn, conn.transaction():
            return self._history_on(conn, verification_class)

    def current(self, verification_class: str, now_us: int) -> QualificationReport | None:
        live = [r for r in self.history(verification_class) if now_us < r.expires_at_us]
        return max(live, key=lambda r: r.qualified_at_us) if live else None

    def add_governed(self, report: QualificationReport, governed: Any) -> None:
        if self.governance_guard is not None:
            self.governance_guard.require("checker-qualification", report.verification_class)
        if not verify_report(self._trust, report, authority=self._authority):
            raise QualificationError("qualification report signature invalid or untrusted")
        with self._pool.connection() as conn, conn.transaction():
            _lock(conn, "qualification:" + report.verification_class)
            _tenant(conn, governed.tenant_id)
            history = self._history_on(conn, report.verification_class)
            if digest_hex([r.digest() for r in history]) != governed.approved_prior:
                raise QualificationError("the qualification history changed since the change was approved")
            if any(r.digest() == report.digest() for r in history):
                raise QualificationError("duplicate report; reports are immutable")
            run_governance_check(governed.final_check, conn)
            conn.execute("INSERT INTO reference_qualification_reports_v1"
                         " (verification_class, seq, report_digest, body, signature) VALUES (%s, %s, %s, %s, %s)",
                         (report.verification_class, len(history) + 1, report.digest(),
                          json.dumps(report.signed_body(), sort_keys=True),
                          json.dumps({"key_id": report.signature.key_id, "value": report.signature.value,
                                      "alg": report.signature.alg}, sort_keys=True)))
            _receipt_on(conn, governed)


class PostgresIssuerRegistry(_GovernedReceipts):
    """Durable approver-issuer recognitions (latest version wins); written only through the governance target."""

    def __init__(self, *, pool: Any, trust: TrustDirectory, guard: Any = None) -> None:
        if not isinstance(trust, TrustDirectory):
            raise TypeError("a durable issuer registry needs its trust directory")
        super().__init__(pool)
        self._trust, self.governance_guard = trust, guard

    @staticmethod
    def _kind_on(conn: Any, issuer_key_id: str) -> tuple[int, str | None]:
        row = conn.execute("SELECT version, kind FROM reference_issuer_recognitions_v1 WHERE issuer_key_id=%s"
                           " ORDER BY version DESC LIMIT 1", (issuer_key_id,)).fetchone()
        return (0, None) if row is None else (int(row[0]), str(row[1]))

    def issuer_kind(self, issuer_key_id: str) -> str | None:
        with self._pool.connection() as conn, conn.transaction():
            return self._kind_on(conn, issuer_key_id)[1]

    def recognise_governed(self, issuer_key_id: str, kind: str, governed: Any) -> None:
        if self.governance_guard is not None:
            self.governance_guard.require("approver-issuer", issuer_key_id)
        if not self._trust.is_known(issuer_key_id) or not isinstance(kind, str) or not kind.strip():
            raise ValueError("an issuer must be a registered key, recognised for an explicit kind")
        with self._pool.connection() as conn, conn.transaction():
            _lock(conn, "issuer:" + issuer_key_id)
            _tenant(conn, governed.tenant_id)
            version, current = self._kind_on(conn, issuer_key_id)
            if (current or "absent") != governed.approved_prior:
                raise ValueError("the issuer's recognition changed since the change was approved")
            run_governance_check(governed.final_check, conn)
            conn.execute("INSERT INTO reference_issuer_recognitions_v1 (issuer_key_id, version, kind)"
                         " VALUES (%s, %s, %s)", (issuer_key_id, version + 1, kind))
            _receipt_on(conn, governed)


__all__ = ["PostgresIssuerRegistry", "PostgresQualificationRegistry", "migrate_governed_registries"]
