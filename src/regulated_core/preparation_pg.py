"""Retained preparation for budgeted target authority.

This is a recorder-owned persistence boundary, not a permit issuer. Policy and
issuer configuration are supplied by the trusted host. Delegated requests also
require the configured chain and current-input verifier; unbudgeted requests refuse.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .delegated_effect_pg import DelegatedEffectVerifier, verify_delegation_on
from .clock import ConnectionClock
from .canonical import canonical_bytes, digest_hex
from .permit import EmissionError
from .budget import BudgetError
from .persistence_pg import PostgresDecisionRecorder, PostgresMissionBudget
from .approval import ApprovalWorkflow
from .evidence_checkpoints_pg import PinnedVerifier
from .registry import ConsequencePolicy, DeclaresMissionBudget
from .reservation_subject import retained_subject
from .retained_authority_pg import verify_retained_draft
from .signing import Signature
from .input_evidence import InputVerifier
from .input_evidence_pg import load_inputs_on
from .target import TargetPermit, require_permit_clock


@dataclass(frozen=True, slots=True)
class SignedPreparation:
    """Immutable signed bytes naming the exact draft and retained authority."""

    body_json: str
    signature: Signature

    def signed_body(self) -> dict[str, Any]:
        body: dict[str, Any] = json.loads(self.body_json)
        return body

    def digest(self) -> str:
        return digest_hex({"body": self.signed_body(), "signature": self.signature})


def prepare_target_on(
    recorder: PostgresDecisionRecorder, conn: Any, draft: TargetPermit, *, issuer_key_id: str,
    policy: ConsequencePolicy, evidence_verifier: PinnedVerifier, max_decision_age_us: int,
    approval_authority: ApprovalWorkflow | None = None,
    input_verifier: InputVerifier | None = None,
    delegated_verifier: DelegatedEffectVerifier | None = None,
    clock: ConnectionClock | None = None,
) -> SignedPreparation:
    """Retain checked preparation in the recorder's transaction; issue nothing."""
    require_permit_clock(draft, clock, connection=conn)
    if draft.preparation_digest:
        raise EmissionError("preparation requires unsigned, unprepared terms")
    if evidence_verifier is None:
        raise EmissionError("preparation requires bounded retained verification")
    if not issuer_key_id or issuer_key_id == recorder._signer.key_id:
        raise EmissionError("preparation and issuer authorities must differ")
    if any((draft.grant_digest, draft.chain_digest, draft.root_digest)) and delegated_verifier is None:
        raise EmissionError("delegated preparation is not yet qualified")
    policy_ref = policy.ref
    policy_version = f"{policy_ref.vertical}/{policy_ref.policy_id}@{policy_ref.version}"
    policy_version += f"#{policy_ref.digest}" if policy_ref.digest else ""
    selected, authority_hash, approval_digest = verify_retained_draft(
        conn, draft, issuer_key_id=issuer_key_id, evidence_trust=recorder._trust,
        current_evidence_key_id=recorder._signer.key_id,
        historical_evidence_key_ids=recorder._history_keys - {recorder._signer.key_id},
        expected_policy_version=policy_version, max_decision_age_us=max_decision_age_us,
        evidence_verifier=evidence_verifier, fence_grant_digests=None if draft.grant_digest else (),
        approval_authority=approval_authority,
    )
    if draft.grant_digest and (delegated_verifier is None or delegated_verifier.policy is not policy):
        raise EmissionError("preparation and delegated policy configuration differ")
    verify_delegation_on(conn, draft, selected, verifier=delegated_verifier,
                         inputs=input_verifier, history=evidence_verifier, approval_authority=approval_authority)
    if not isinstance(policy, DeclaresMissionBudget) or selected.record.policy != policy_ref:
        raise EmissionError("preparation requires matching trusted budget policy")
    terms = policy.mission_budget(selected.record.action.action_id)
    if terms is None or set(terms) != {"units", "limit"}:
        raise EmissionError("preparation requires explicit policy budget terms")
    units, limit = terms["units"], terms["limit"]
    if draft.budget_units != units:
        raise EmissionError("draft budget differs from policy or request nonce")
    subject = retained_subject(selected.record, mission=draft.mission, nonce=draft.nonce)
    budget = PostgresMissionBudget(pool=recorder._pool)
    try:
        budget.require_request_attempt_on(
            conn, draft.tenant_id, draft.mission, draft.budget_reservation,
            request_id=draft.nonce, subject_digest=subject, units=units, limit=limit,
        )
    except BudgetError as exc:
        raise EmissionError(str(exc)) from exc
    if conn.execute(
        "SELECT 1 FROM regulated_decision_uses_v1 WHERE tenant=%s AND record_hash=%s",
        (draft.tenant_id, authority_hash),
    ).fetchone():
        raise EmissionError("preparation authority already consumed")
    now = int(conn.execute(
        "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
    ).fetchone()[0])
    if now >= draft.expires_at_us or policy.ref != policy_ref:
        raise EmissionError("authority expired or policy changed during preparation")
    body = {
        "schema": "regulated/preparation/v1", "draft": draft.signed_body(),
        "issuer_key_id": issuer_key_id, "decision_seq": selected.seq,
        "decision_hash": selected.record_hash, "authority_record_hash": authority_hash,
        "approval_certificate_digest": approval_digest, "subject_digest": subject,
        "budget_units": units, "budget_limit": limit,
    }
    if input_verifier is not None:
        retained = load_inputs_on(
            conn, selected, verifier=input_verifier, evidence_trust=recorder._trust,
            evidence_key_id=recorder._signer.key_id, evidence_verifier=evidence_verifier,
            expected_nonce=draft.nonce,
        )
        if retained.inputs.policy != policy_ref:
            raise EmissionError("retained inputs differ from the trusted preparation policy")
        deadline = min([retained.admission.expires_at_us] + [
            c.expires_at_us for c in retained.inputs.context.actor.credentials])
        if draft.expires_at_us > deadline:
            raise EmissionError("permit outlives input or identity credential authority")
        body.update(schema="regulated/preparation/v2",
                    input_companion_digest=retained.companion_digest)
    if draft.clock_domain:
        if input_verifier is None:
            raise EmissionError("clock-bound preparation requires authenticated inputs")
        body.update(schema="regulated/preparation/v3", clock_domain=draft.clock_domain,
                    issued_at_us=draft.issued_at_us)
    require_permit_clock(draft, clock, connection=conn)
    signature = recorder._signer.sign(body)
    verify_delegation_on(conn, draft, selected, verifier=delegated_verifier,
                         inputs=input_verifier, history=evidence_verifier, proof=body, approval_authority=approval_authority)
    if input_verifier is not None:
        # Signing can block; authenticate fresh host state again before retaining.
        latest = load_inputs_on(
            conn, selected, verifier=input_verifier, evidence_trust=recorder._trust,
            evidence_key_id=recorder._signer.key_id, evidence_verifier=evidence_verifier,
            expected_nonce=draft.nonce,
        )
        if latest.companion_digest != body["input_companion_digest"]:
            raise EmissionError("input authority changed during preparation")
        now = int(conn.execute(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
        ).fetchone()[0])
        if now >= draft.expires_at_us:
            raise EmissionError("draft expired during preparation input verification")
    if signature.key_id != recorder._signer.key_id or not recorder._trust.verify(body, signature):
        raise EmissionError("preparation signer is not the configured evidence authority")
    require_permit_clock(draft, clock, connection=conn)
    prepared = SignedPreparation(canonical_bytes(body).decode("utf-8"), signature)
    conn.execute(
        "INSERT INTO regulated_preparations_v1"
        " (tenant,nonce,mission,reservation_id,preparation_digest,body,signature)"
        " VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
        (draft.tenant_id, draft.nonce, draft.mission, draft.budget_reservation,
         prepared.digest(), prepared.body_json, canonical_bytes(signature).decode("utf-8")),
    )
    return prepared
