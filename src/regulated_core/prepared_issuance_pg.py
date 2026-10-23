"""Verify retained preparation and issue permits bound to its signed digest.

The store is trusted host configuration. Issuance uses its own database
connection so uncommitted preparation on a caller's connection cannot count.
Receivers must still fence and consume authority in their effect transaction.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .approval import ApprovalWorkflow
from .budget import UNBUDGETED
from .evidence import SignedDecisionEnvelope
from .delegated_effect_pg import DelegatedEffectVerifier, verify_delegation_on
from .clock import ClockError, read_clock
from .canonical import canonical_bytes
from .evidence_checkpoints_pg import PinnedVerifier
from .permit import EmissionError
from .persistence_pg import PostgresMissionBudget, _tenant
from .preparation_pg import SignedPreparation
from .retained_authority_pg import verify_retained_draft
from .signing import Signature, TrustDirectory
from .input_evidence import InputVerifier
from .input_evidence_pg import load_inputs_on
from .target import SignedTargetPermit, TargetAuthority, TargetPermit, TargetRef, require_permit_clock


def load_preparation_on(
    conn: Any, permit: TargetPermit, *, issuer_key_id: str,
    evidence_trust: TrustDirectory, current_evidence_key_id: str,
) -> SignedPreparation:
    """Authenticate the exact retained preparation, never just its existence."""
    draft = replace(permit, preparation_digest="")
    row = conn.execute(
        "SELECT preparation_digest,body,signature,mission,reservation_id"
        " FROM regulated_preparations_v1 WHERE tenant=%s AND nonce=%s",
        (permit.tenant_id, permit.nonce),
    ).fetchone()
    if row is None:
        raise EmissionError("committed preparation is missing")
    try:
        body = row[1]
        if not isinstance(body, dict):
            raise ValueError("preparation body must be an object")
        signature = Signature(**row[2])
        proof = SignedPreparation(canonical_bytes(body).decode("utf-8"), signature)
        expected_keys = {
                "schema", "draft", "issuer_key_id", "decision_seq", "decision_hash",
                "authority_record_hash", "approval_certificate_digest",
                "subject_digest", "budget_units", "budget_limit"}
        if body.get("schema") in {"regulated/preparation/v2", "regulated/preparation/v3"}:
            expected_keys.add("input_companion_digest")
        if body.get("schema") == "regulated/preparation/v3":
            expected_keys.update({"clock_domain", "issued_at_us"})
            if (not draft.clock_domain or body.get("clock_domain") != draft.clock_domain
                    or body.get("issued_at_us") != draft.issued_at_us):
                raise EmissionError("preparation clock binding differs from the draft")
        elif draft.clock_domain:
            raise EmissionError("qualified draft requires clock-bound preparation")
        if (set(body) != expected_keys or body.get("schema") not in {
                "regulated/preparation/v1", "regulated/preparation/v2", "regulated/preparation/v3"}
                or signature.key_id != current_evidence_key_id
                or signature.key_id == issuer_key_id
                or not evidence_trust.verify(body, signature)
                or body["issuer_key_id"] != issuer_key_id
                or canonical_bytes(body["draft"]) != canonical_bytes(draft.signed_body())
                or row[3:] != (draft.mission, draft.budget_reservation)
                or row[0] != proof.digest()
                or (permit.preparation_digest and permit.preparation_digest != proof.digest())):
            raise EmissionError("preparation signature, issuer or exact terms mismatch")
        return proof
    except (KeyError, TypeError, ValueError) as exc:
        raise EmissionError("retained preparation is malformed") from exc



def verify_prepared_inputs_on(
    conn: Any, proof: SignedPreparation, permit: TargetPermit, *,
    verifier: InputVerifier | None, evidence_trust: TrustDirectory,
    evidence_key_id: str, evidence_verifier: PinnedVerifier,
) -> None:
    """Require exact retained current inputs whenever either host or proof asks."""
    body = proof.signed_body()
    has_inputs = body["schema"] in {"regulated/preparation/v2", "regulated/preparation/v3"}
    if not has_inputs and verifier is None:
        return
    if not has_inputs or verifier is None:
        raise EmissionError("input-bound preparation and trusted input verifier are required")
    envelope = evidence_verifier.verify(conn, body["decision_seq"], require_current=True)
    if envelope.record_hash != permit.decision_record_hash:
        raise EmissionError("input-bound preparation decision mismatch")
    retained = load_inputs_on(
        conn, envelope, verifier=verifier, evidence_trust=evidence_trust,
        evidence_key_id=evidence_key_id, evidence_verifier=evidence_verifier,
        expected_nonce=permit.nonce,
    )
    deadline = min([retained.admission.expires_at_us] + [
        c.expires_at_us for c in retained.inputs.context.actor.credentials])
    if (retained.companion_digest != body["input_companion_digest"]
            or permit.expires_at_us > deadline):
        raise EmissionError("prepared input digest or identity deadline mismatch")
    now = int(conn.execute(
        "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
    ).fetchone()[0])
    if now >= min(permit.expires_at_us, deadline):
        raise EmissionError("prepared authority expired during input verification")


def check_preparation_authority(
    conn: Any, proof: SignedPreparation, permit: TargetPermit, *,
    decision_seq: int, authority_hash: str, approval_digest: str,
    budget: PostgresMissionBudget,
) -> None:
    """Bind freshly verified decision/approval and a live exact reservation."""
    body = proof.signed_body()
    if (body["decision_seq"] != decision_seq
            or body["decision_hash"] != permit.decision_record_hash
            or body["authority_record_hash"] != authority_hash
            or body["approval_certificate_digest"] != approval_digest
            or body["budget_units"] != permit.budget_units):
        raise EmissionError("preparation differs from current retained authority")
    budget.require_live_on(
        conn, permit.tenant_id, permit.mission, permit.budget_reservation,
        subject_digest=body["subject_digest"], units=body["budget_units"],
        limit=body["budget_limit"],
    )
    if conn.execute(
        "SELECT 1 FROM regulated_decision_uses_v1 WHERE tenant=%s AND record_hash=%s",
        (permit.tenant_id, authority_hash),
    ).fetchone():
        raise EmissionError("prepared decision already consumed")
    now = int(conn.execute(
        "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
    ).fetchone()[0])
    if now >= permit.expires_at_us:
        raise EmissionError("prepared authority expired")


@dataclass(frozen=True)
class PostgresPreparedIssuer:
    """Trusted issuer composition for budgeted, input-bound preparation.

    The evidence signer is absent. The permit key must have separate custody
    in deployment; a Python object is not an isolation boundary. Policy
    configuration is receiver-owned, not a field supplied with the request.
    """

    pool: Any
    authority: TargetAuthority
    evidence_trust: TrustDirectory
    current_evidence_key_id: str
    expected_policy_version: str
    max_decision_age_us: int
    evidence_verifier: PinnedVerifier
    approval_authority: ApprovalWorkflow | None = None
    input_verifier: InputVerifier | None = None
    delegated_verifier: DelegatedEffectVerifier | None = None

    def draft(self, envelope: SignedDecisionEnvelope, output: bytes, *, target: TargetRef, operation: str,
              expected_target_state: str, principal: str, approval_ref: str,
              qualification_digests: tuple[str, ...], ttl_us: int, nonce: str, not_after_us: int = 0,
              mission: str = "", budget_reservation: str = UNBUDGETED, budget_units: int = 0,
              policy_version: str = "", grant_digest: str = "", chain_digest: str = "",
              root_digest: str = "") -> TargetPermit:
        """Draft with the same primary database clock used for preparation and effects.

        The pool is trusted issuer configuration. The application host clock
        cannot move the draft's start or expiry. A caller's not_after_us may
        shorten, but never extend, its lifetime. Preparation and issuance
        still revalidate absolute deadlines.
        """
        with self.pool.connection() as conn:
            try:
                reading = read_clock(self.authority.clock, connection=conn)
            except ClockError as exc:
                raise EmissionError("issuer clock unavailable") from exc
            now = reading.now_us
        # The epoch callback may borrow this same bounded pool. The clock
        # sample owns no effect transaction, so release its connection first.
        return self.authority._draft_at(
            int(now), envelope, output, target=target, operation=operation,
            expected_target_state=expected_target_state, principal=principal,
            approval_ref=approval_ref, qualification_digests=qualification_digests,
            ttl_us=ttl_us, nonce=nonce, not_after_us=not_after_us, mission=mission,
            budget_reservation=budget_reservation, budget_units=budget_units,
            policy_version=policy_version, grant_digest=grant_digest,
            chain_digest=chain_digest, root_digest=root_digest, clock_reading=reading,
        )

    def verify_binding_on(self, conn: Any, signed: SignedTargetPermit) -> None:
        """Authenticate binding using the receiver's existing tenant transaction."""
        from psycopg.pq import TransactionStatus

        if conn is None or conn.info.transaction_status != TransactionStatus.INTRANS:
            raise EmissionError("preparation verification requires the receiver transaction")
        tenant, isolation = conn.execute(
            "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
        ).fetchone()
        if tenant != signed.permit.tenant_id or isolation != "read committed":
            raise EmissionError("preparation receiver transaction scope mismatch")
        if not signed.permit.preparation_digest:
            raise EmissionError("receiver requires a preparation-bound permit")
        require_permit_clock(signed.permit, self.authority.clock, connection=conn)
        proof = load_preparation_on(
            conn, signed.permit, issuer_key_id=signed.signature.key_id,
            evidence_trust=self.evidence_trust,
            current_evidence_key_id=self.current_evidence_key_id,
        )
        verify_prepared_inputs_on(
            conn, proof, signed.permit, verifier=self.input_verifier,
            evidence_trust=self.evidence_trust, evidence_key_id=self.current_evidence_key_id,
            evidence_verifier=self.evidence_verifier,
        )

        if signed.permit.grant_digest:
            selected, authority_hash, approval_digest = verify_retained_draft(
                conn, signed.permit, issuer_key_id=signed.signature.key_id,
                evidence_trust=self.evidence_trust,
                current_evidence_key_id=self.current_evidence_key_id,
                expected_policy_version=self.expected_policy_version,
                max_decision_age_us=self.max_decision_age_us,
                evidence_verifier=self.evidence_verifier,
                approval_authority=self.approval_authority, fence_grant_digests=None,
            )
            verify_delegation_on(conn, signed.permit, selected, verifier=self.delegated_verifier,
                                 inputs=self.input_verifier, history=self.evidence_verifier,
                                 proof=proof.signed_body(), approval_authority=self.approval_authority)
            check_preparation_authority(
                conn, proof, signed.permit, decision_seq=selected.seq,
                authority_hash=authority_hash, approval_digest=approval_digest,
                budget=PostgresMissionBudget(pool=None),
            )
        require_permit_clock(signed.permit, self.authority.clock, connection=conn)

    def issue(self, draft: TargetPermit) -> SignedTargetPermit:
        """Sign only after authentic preparation is visible on a new connection."""
        if draft.preparation_digest or (draft.grant_digest and self.delegated_verifier is None):
            raise EmissionError("requires an unprepared, input-bound draft")
        if self.evidence_verifier is None:
            raise EmissionError("issuer requires bounded evidence verification")
        issuer = self.authority._signer
        with self.pool.connection() as conn, conn.transaction():
            _tenant(conn, draft.tenant_id)
            require_permit_clock(draft, self.authority.clock, connection=conn)
            proof = load_preparation_on(
                conn, draft, issuer_key_id=issuer.key_id,
                evidence_trust=self.evidence_trust,
                current_evidence_key_id=self.current_evidence_key_id,
            )
            selected, authority_hash, approval_digest = verify_retained_draft(
                conn, draft, issuer_key_id=issuer.key_id,
                evidence_trust=self.evidence_trust,
                current_evidence_key_id=self.current_evidence_key_id,
                expected_policy_version=self.expected_policy_version,
                max_decision_age_us=self.max_decision_age_us,
                evidence_verifier=self.evidence_verifier,
                approval_authority=self.approval_authority,
                fence_grant_digests=None if draft.grant_digest else (),
            )
            verify_delegation_on(conn, draft, selected, verifier=self.delegated_verifier,
                                 inputs=self.input_verifier, history=self.evidence_verifier,
                                 proof=proof.signed_body(), approval_authority=self.approval_authority)
            check_preparation_authority(
                conn, proof, draft, decision_seq=selected.seq,
                authority_hash=authority_hash, approval_digest=approval_digest,
                budget=PostgresMissionBudget(pool=self.pool),
            )
            verify_prepared_inputs_on(
                conn, proof, draft, verifier=self.input_verifier,
                evidence_trust=self.evidence_trust, evidence_key_id=self.current_evidence_key_id,
                evidence_verifier=self.evidence_verifier,
            )
            permit = replace(draft, preparation_digest=proof.digest())
            signature = issuer.sign(permit.signed_body())
            if signature.key_id != issuer.key_id or not self.authority._trust.verify(
                permit.signed_body(), signature
            ):
                raise EmissionError("configured issuer returned an invalid signature")
            verify_delegation_on(conn, permit, selected, verifier=self.delegated_verifier,
                                 inputs=self.input_verifier, history=self.evidence_verifier,
                                 proof=proof.signed_body(), approval_authority=self.approval_authority)
            now = int(conn.execute(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
            ).fetchone()[0])
            require_permit_clock(permit, self.authority.clock, connection=conn)
            if now >= permit.expires_at_us:
                raise EmissionError("authority expired while signing")
            verify_prepared_inputs_on(
                conn, proof, permit, verifier=self.input_verifier,
                evidence_trust=self.evidence_trust, evidence_key_id=self.current_evidence_key_id,
                evidence_verifier=self.evidence_verifier,
            )
            require_permit_clock(permit, self.authority.clock, connection=conn)
            signed = SignedTargetPermit(permit, signature)
        return signed
