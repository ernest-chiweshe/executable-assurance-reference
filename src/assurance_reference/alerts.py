"""Retain signed reconciliation alerts without depending on the authority clock."""

from __future__ import annotations

import json
import uuid
from typing import Any

from regulated_core.canonical import canonical_bytes
from regulated_core.signing import Signature, Signer, TrustDirectory


class AlertUnavailable(RuntimeError):
    """The caller cannot claim that an alert was durably retained."""


def provision_alerts(pool: Any) -> None:
    """Explicit host bootstrap; ordinary appends never create missing storage."""
    with pool.connection() as connection, connection.transaction():
        connection.execute(
            "CREATE TABLE IF NOT EXISTS reference_alerts_v1 ("
            "alert_id text PRIMARY KEY, envelope bytea NOT NULL)"
        )
        connection.execute("ALTER TABLE reference_alerts_v1 ENABLE ROW LEVEL SECURITY")
        connection.execute("ALTER TABLE reference_alerts_v1 FORCE ROW LEVEL SECURITY")
        connection.execute("DROP POLICY IF EXISTS alert_tenant_scope ON reference_alerts_v1")
        connection.execute("""CREATE POLICY alert_tenant_scope ON reference_alerts_v1
            USING ((convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id')
                   = current_setting('app.alert_tenant',true))
            WITH CHECK ((convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id')
                   = current_setting('app.alert_tenant',true))""")


class AlertJournal:
    """A local signed outbox, not proof that an operator received an alert.

    Each append commits on its own connection. No authority-clock reading is
    required or implied: these records make no claim about when an effect occurred.
    Database availability, trusted key distribution and administrator integrity
    remain host obligations. This journal cannot repair a process crash before
    append, nor prevent an effect which already happened.
    """

    def __init__(self, pool: Any, signer: Signer, trust: TrustDirectory) -> None:
        self.pool = pool
        self.signer = signer
        self.trust = trust

    @staticmethod
    def _scope(connection, tenant_id):
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("explicit alert tenant required")
        connection.execute("SELECT set_config('app.alert_tenant',%s,true)", (tenant_id,))
        connection.execute("SET LOCAL lock_timeout = '5s'")
        connection.execute("SET LOCAL statement_timeout = '5s'")

    def retain_signed(self, payload: dict, signature: Signature) -> None:
        """Persist a verified tenant-bound alert without consulting authority time."""
        if signature.key_id != self.signer.key_id or not self.trust.verify(payload, signature):
            raise ValueError("alert signer is not trusted")
        tenant_id, alert_id = payload["tenant_id"], payload["alert_id"]
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("explicit alert tenant required")
        if not isinstance(alert_id, str) or not alert_id:
            raise ValueError("explicit alert identity required")
        encoded = canonical_bytes({"payload": payload, "signature": signature})
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                "INSERT INTO reference_alerts_v1 (alert_id,envelope) VALUES (%s,%s)",
                (alert_id, encoded))

    def list_ids(self, *, tenant_id: str) -> tuple[str, ...]:
        """List identifiers within a host-selected tenant; never infer a tenant."""
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT alert_id FROM reference_alerts_v1 WHERE "
                "convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id'=%s ORDER BY alert_id",
                (tenant_id,)).fetchall()
        return tuple(row[0] for row in rows)

    def append(
        self,
        *,
        tenant_id: str,
        decision_hash: str,
        permit_hash: str,
        code: str,
        outcome: str,
    ) -> str:
        """Store references, not effect content or exception messages."""
        if code not in {"TARGET_UNKNOWN", "OUTCOME_RECORDING_FAILED"}:
            raise ValueError("unknown alert code")
        if outcome not in {"committed", "failed", "unknown", "not_committed"}:
            raise ValueError("unknown target outcome")
        if not tenant_id:
            raise ValueError("tenant is required")
        for value in (decision_hash, permit_hash):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("an exact SHA-256 reference is required")
        alert_id = uuid.uuid4().hex
        payload = {
            "schema": "executable-assurance/alert/v1",
            "alert_id": alert_id,
            "tenant_id": tenant_id,
            "decision_hash": decision_hash,
            "permit_hash": permit_hash,
            "code": code,
            "outcome": outcome,
            "authority_time_us": None,
            "requires_reconciliation": True,
        }
        try:
            signature = self.signer.sign(payload)
            if not self.trust.verify(payload, signature):
                raise ValueError("alert signer is not trusted")
            self.retain_signed(payload, signature)
        except Exception as exc:
            raise AlertUnavailable("signed reconciliation alert was not confirmed durable") from exc
        return alert_id

    def read(self, alert_id: str, *, tenant_id: str) -> dict:
        """Require host tenant scope and verify both tenant and signature binding."""
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT envelope FROM reference_alerts_v1 WHERE alert_id = %s AND "
                "convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id'=%s",
                (alert_id, tenant_id),
            ).fetchone()
        if row is None:
            raise KeyError(alert_id)
        envelope = json.loads(bytes(row[0]))
        payload = envelope["payload"]
        if payload["tenant_id"] != tenant_id or payload["alert_id"] != alert_id or not self.trust.verify(
            payload, Signature(**envelope["signature"])
        ):
            raise ValueError("alert identity or signature is invalid")
        return envelope

    def append_refusal(self, *, tenant_id: str, request_hash: str,
                       decision_hash: str | None, code: str) -> str:
        """Retain request-bound refusal or uncertainty without inventing a permit."""
        if not tenant_id or code not in {"AUTHORIZATION_REFUSED", "ADMISSION_REFUSED", "AUTHORIZATION_UNCERTAIN"}:
            raise ValueError("a tenant and known refusal code are required")
        for value in (request_hash,) + (() if decision_hash is None else (decision_hash,)):
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("an exact SHA-256 reference is required")
        alert_id = uuid.uuid4().hex
        payload = {
            "schema": "executable-assurance/refusal-alert/v1", "alert_id": alert_id,
            "tenant_id": tenant_id, "request_hash": request_hash, "decision_hash": decision_hash,
            "permit_hash": None, "code": code,
            "outcome": "unknown" if code == "AUTHORIZATION_UNCERTAIN" else "failed",
            "authority_time_us": None, "requires_reconciliation": code == "AUTHORIZATION_UNCERTAIN",
        }
        try:
            signature = self.signer.sign(payload)
            if not self.trust.verify(payload, signature):
                raise ValueError("alert signer is not trusted")
            self.retain_signed(payload, signature)
        except Exception as exc:
            raise AlertUnavailable("signed refusal alert was not confirmed durable") from exc
        return alert_id
