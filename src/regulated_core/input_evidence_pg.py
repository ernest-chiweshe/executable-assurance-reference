"""Atomic append and authenticated rereading of decision input companions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, digest_hex
from .evidence import SignedDecisionEnvelope
from .evidence_checkpoints_pg import PinnedVerifier
from .input_evidence import DecisionInputs, InputAdmission, InputVerifier
from .models import ActionEffect, Decision, DecisionRecord
from .permit import EmissionError
from .persistence_pg import PostgresDecisionRecorder, _tenant
from .signing import Signature, TrustDirectory

SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_decision_inputs_v1 (
 tenant TEXT NOT NULL, seq BIGINT NOT NULL, input_digest TEXT NOT NULL,
 body JSONB NOT NULL, signature JSONB NOT NULL,
 request_id TEXT NOT NULL, permit_nonce TEXT NOT NULL,
 UNIQUE(tenant,request_id), UNIQUE(tenant,permit_nonce),
 PRIMARY KEY (tenant,seq),
 FOREIGN KEY (tenant,seq) REFERENCES regulated_decision_evidence_v1(tenant,seq));
ALTER TABLE regulated_decision_inputs_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_decision_inputs_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_inputs_tenant_v1 ON regulated_decision_inputs_v1;
CREATE POLICY regulated_inputs_tenant_v1 ON regulated_decision_inputs_v1
 USING (tenant=current_setting('app.tenant',true))
 WITH CHECK (tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS regulated_inputs_immutable_v1 ON regulated_decision_inputs_v1;
CREATE TRIGGER regulated_inputs_immutable_v1 BEFORE UPDATE OR DELETE
 ON regulated_decision_inputs_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_inputs_no_truncate_v1 ON regulated_decision_inputs_v1;
CREATE TRIGGER regulated_inputs_no_truncate_v1 BEFORE TRUNCATE
 ON regulated_decision_inputs_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


def _scope(conn: Any, tenant: str) -> None:
    from psycopg.pq import TransactionStatus

    if conn is None or conn.info.transaction_status != TransactionStatus.INTRANS:
        raise EmissionError("input evidence requires an active transaction")
    found, isolation = conn.execute(
        "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
    ).fetchone()
    if found != tenant or isolation != "read committed":
        raise EmissionError("input evidence transaction scope mismatch")


def _match(inputs: DecisionInputs, record: DecisionRecord) -> None:
    c = inputs.context
    if (inputs.assertion.tenant_id != record.tenant_id or c.tenant_id != record.tenant_id
            or inputs.assertion.assertion_id != record.assertion_id
            or inputs.assertion.content_digest != record.assertion_digest
            or inputs.action != record.action or inputs.policy != record.policy
            or c.actor.actor_id != record.actor_id or c.purpose != record.purpose
            or c.correlation_id != record.correlation_id or c.now_us != record.decided_at_us):
        raise EmissionError("input companion differs from the retained decision")
    if (record.decision.is_allow_class and c.actor.producer
            and inputs.action.effect in (ActionEffect.AUTHORITATIVE, ActionEffect.EXTERNAL)):
        raise EmissionError("producer cannot authorize an authoritative effect")


def record_with_inputs(
    recorder: PostgresDecisionRecorder, inputs: DecisionInputs, decision: Decision, *,
    admission: InputAdmission, verifier: InputVerifier,
) -> SignedDecisionEnvelope:
    """Commit decision and companion together; no legacy record bytes change."""
    if recorder.clock is not verifier.clock:
        raise EmissionError("input verifier and decision recorder clocks differ")
    record, record_hash = recorder.make_record(
        inputs.assertion, inputs.action, inputs.context, inputs.policy, decision
    )
    _match(inputs, record)
    with recorder._pool.connection() as conn, conn.transaction():
        _tenant(conn, record.tenant_id)
        _scope(conn, record.tenant_id)
        verifier.verify_on(conn, inputs, admission, evidence_key_id=recorder._signer.key_id,
                           now_us=verifier.now_on(conn))
        envelope = recorder._append_on(conn, record, record_hash)
        if envelope.clock_domain != admission.clock_domain:
            raise EmissionError("decision and input admission clock domains differ")
        body = {"schema": "regulated/input-evidence/v1", "tenant": record.tenant_id,
                "seq": envelope.seq, "record_hash": record_hash,
                "inputs": inputs.body(), "admission": {
                    **{k: v for k, v in admission.signed_body().items() if k != "schema"},
                    "signature": admission.signature}}
        signature = recorder._signer.sign(body)
        if (signature.key_id != recorder._signer.key_id
                or not recorder._trust.verify(body, signature)):
            raise EmissionError("input evidence signer mismatch")
        conn.execute(
            "INSERT INTO regulated_decision_inputs_v1(tenant,seq,input_digest,body,signature,request_id,permit_nonce)"
            " VALUES (%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s)",
            (record.tenant_id, envelope.seq, inputs.digest(),
             canonical_bytes(body).decode("utf-8"), canonical_bytes(signature).decode("utf-8"),
             admission.request_id, admission.permit_nonce),
        )
        # Signing and evidence-chain serialization may block. Recheck current
        # host authority and expiry at the end of the transaction's work.
        verifier.verify_on(conn, inputs, admission, evidence_key_id=recorder._signer.key_id,
                           now_us=verifier.now_on(conn))
        verifier.verify_at(inputs, admission, evidence_key_id=recorder._signer.key_id,
                           now_us=verifier.now_on(conn))
    return envelope


@dataclass(frozen=True)
class RetainedInputs:
    inputs: DecisionInputs
    admission: InputAdmission
    companion_digest: str


def _load_inputs_on(
    conn: Any, envelope: SignedDecisionEnvelope, *, verifier: InputVerifier,
    evidence_trust: TrustDirectory, evidence_key_id: str,
    evidence_verifier: PinnedVerifier, expected_nonce: str,
    historical_at_us: int | None = None,
) -> RetainedInputs:
    """Verify input bytes; historical mode alone never authorizes a new action."""
    _scope(conn, envelope.record.tenant_id)
    if canonical_bytes(evidence_verifier.verify(conn, envelope.seq,
            require_current=historical_at_us is None)) != canonical_bytes(envelope):
        raise EmissionError("input evidence decision is not in verified retained history")
    row = conn.execute(
        "SELECT input_digest,body,signature,request_id,permit_nonce FROM regulated_decision_inputs_v1"
        " WHERE tenant=%s AND seq=%s", (envelope.record.tenant_id, envelope.seq),
    ).fetchone()
    if row is None:
        raise EmissionError("retained decision has no authenticated input companion")
    try:
        body, signature = row[1], Signature(**row[2])
        if (set(body) != {"schema", "tenant", "seq", "record_hash", "inputs", "admission"}
                or body["schema"] != "regulated/input-evidence/v1"
                or body["tenant"] != envelope.record.tenant_id or body["seq"] != envelope.seq
                or body["record_hash"] != envelope.record_hash
                or signature.key_id != evidence_key_id
                or not evidence_trust.verify(body, signature)):
            raise EmissionError("input companion signature or decision binding invalid")
        inputs = DecisionInputs.decode(body["inputs"])
        admission = InputAdmission.decode(body["admission"])
        if admission.clock_domain != envelope.clock_domain:
            raise EmissionError("retained input and decision clock domains differ")
        if (not expected_nonce or admission.permit_nonce != expected_nonce
                or row[3:] != (admission.request_id, admission.permit_nonce)):
            raise EmissionError("input admission request or permit nonce mismatch")
        if inputs.digest() != row[0]:
            raise EmissionError("input companion digest mismatch")
        _match(inputs, envelope.record)
        if historical_at_us is None:
            verifier.verify_on(conn, inputs, admission, evidence_key_id=evidence_key_id,
                               now_us=verifier.now_on(conn))
            verifier.verify_at(inputs, admission, evidence_key_id=evidence_key_id, now_us=verifier.now_on(conn))
        else:
            verifier.verify_at(inputs, admission, evidence_key_id=evidence_key_id,
                               now_us=historical_at_us)
        return RetainedInputs(inputs, admission, digest_hex({"body": body, "signature": signature}))
    except (KeyError, TypeError, ValueError) as exc:
        raise EmissionError("input companion malformed") from exc


def load_inputs_on(
    conn: Any, envelope: SignedDecisionEnvelope, *, verifier: InputVerifier,
    evidence_trust: TrustDirectory, evidence_key_id: str,
    evidence_verifier: PinnedVerifier, expected_nonce: str,
) -> RetainedInputs:
    """Verify retained inputs and present host authority for a new action."""
    return _load_inputs_on(
        conn, envelope, verifier=verifier, evidence_trust=evidence_trust,
        evidence_key_id=evidence_key_id, evidence_verifier=evidence_verifier,
        expected_nonce=expected_nonce,
    )
