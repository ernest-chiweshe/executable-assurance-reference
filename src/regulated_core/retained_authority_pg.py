"""Retained decision and approval checks inside a database effect transaction.

This checks evidence, not the complete effect authority. The caller must also
authenticate the permit, verify delegation, fence revocation, validate budget
allocation, and commit its effect and receipt on this same connection. Policy
identity and maximum decision age come from trusted receiver configuration,
never request parameters. Database clock checks do not prove a WAL deadline.
"""
from __future__ import annotations

from dataclasses import replace
from collections.abc import Callable
from .authority_fence_pg import lock_current_authority
from typing import Any

from .approval import ApprovalWorkflow, _match_groups
from .approval_evidence import ReviewError, verified_approvals
from .delegated_effect_pg import DelegatedEffectVerifier, verify_delegation_on
from .canonical import canonical_bytes, digest_hex
from .evidence import GENESIS, SignedDecisionEnvelope, verify_envelope
from .evidence_checkpoints_pg import PinnedVerifier
from .models import DecisionKind
from .input_evidence import InputVerifier
from .permit import EmissionError
from .persistence_pg import PersistenceError, _entry_hash, decode_envelope
from .review_store import PostgresReviewStore
from .signing import TrustDirectory
from .target import TargetRef, SignedTargetPermit, TargetPermit, effect_of

SCHEMA = """
CREATE INDEX IF NOT EXISTS regulated_evidence_record_lookup_v1
 ON regulated_decision_evidence_v1 (tenant, (envelope->>'record_hash'));
CREATE TABLE IF NOT EXISTS regulated_decision_uses_v1 (
 tenant TEXT NOT NULL, record_hash TEXT NOT NULL, permit_digest TEXT NOT NULL,
 nonce TEXT NOT NULL, PRIMARY KEY (tenant,record_hash), UNIQUE (tenant,nonce));
ALTER TABLE regulated_decision_uses_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_decision_uses_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_decision_use_tenant_v1 ON regulated_decision_uses_v1;
CREATE POLICY regulated_decision_use_tenant_v1 ON regulated_decision_uses_v1
 USING (tenant=current_setting('app.tenant',true))
 WITH CHECK (tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS regulated_decision_use_immutable_v1 ON regulated_decision_uses_v1;
CREATE TRIGGER regulated_decision_use_immutable_v1 BEFORE UPDATE OR DELETE
 ON regulated_decision_uses_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_decision_use_no_truncate_v1 ON regulated_decision_uses_v1;
CREATE TRIGGER regulated_decision_use_no_truncate_v1 BEFORE TRUNCATE
 ON regulated_decision_uses_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


def _policy(envelope: SignedDecisionEnvelope) -> str:
    policy = envelope.record.policy
    return f"{policy.vertical}/{policy.policy_id}@{policy.version}" + (
        f"#{policy.digest}" if policy.digest else ""
    )


def _approval(
    conn: Any, permit: TargetPermit, issuer_key_id: str, envelope: SignedDecisionEnvelope,
    authority: ApprovalWorkflow | None, now_us: int, evidence_trust: TrustDirectory,
    verify_membership: Callable[[Any, int], SignedDecisionEnvelope] | None,
) -> tuple[str, str]:
    record = envelope.record
    requirement = record.decision.approval
    if authority is None or requirement is None or not permit.approval_ref:
        raise EmissionError("retained approval authority and certificate are required")
    if authority._signer.key_id in {issuer_key_id, envelope.signature.key_id}:
        raise EmissionError("approval authority must be distinct from permit and evidence authorities")
    row = PostgresReviewStore._latest(conn, permit.tenant_id, permit.approval_ref)
    if row is None:
        raise EmissionError("retained approval is missing")
    state = PostgresReviewStore._payload(row)
    if state.get("review_id") != permit.approval_ref:
        raise EmissionError("retained approval reference mismatch")
    approved = decode_envelope(state["envelope"])
    comparable = replace(approved.record, record_id=record.record_id,
                         decided_at_us=record.decided_at_us)
    if (approved.clock_domain != permit.clock_domain
            or canonical_bytes(comparable) != canonical_bytes(record) or approved.seq > envelope.seq
            or approved.record.decided_at_us > record.decided_at_us
            or approved.signature.key_id != envelope.signature.key_id
            or not verify_envelope(approved, evidence_trust)):
        raise EmissionError("retained approval covers different decision evidence")
    stored = conn.execute(
        "SELECT entry_hash,envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s AND seq=%s",
        (permit.tenant_id, approved.seq),
    ).fetchone()
    if (stored is None or stored[0] != _entry_hash(approved)
            or canonical_bytes(decode_envelope(stored[1])) != canonical_bytes(approved)):
        raise EmissionError("approved decision is not in the verified retained prefix")
    if verify_membership is not None and canonical_bytes(verify_membership(conn, approved.seq)) != canonical_bytes(approved):
        raise EmissionError("approved decision differs from pinned verified history")
    deadline = approved.record.decided_at_us + requirement.expires_after_us
    if not approved.record.decided_at_us <= now_us < deadline or permit.expires_at_us > deadline:
        raise EmissionError("approval validity window does not authorize this permit")
    request = authority.open(
        request_id=permit.approval_ref, requester_id=state.get("review_producer_id", "") or record.actor_id,
        tenant_id=record.tenant_id, assertion_id=record.assertion_id,
        decision_record_id=approved.record.record_id, decision_record_hash=approved.record_hash,
        requirement=requirement, now_us=approved.record.decided_at_us,
    )
    grants, certificate = verified_approvals(authority, state, approved, request, now_us=now_us)
    if certificate is None:
        raise EmissionError("retained approval has no verified certificate")
    groups = {grant.reviewer_id: set(grant.satisfied_groups) for grant in grants}
    if len(groups) < requirement.minimum_approvers or not _match_groups(groups, len(requirement.role_groups)):
        raise EmissionError("retained approval does not satisfy quorum")
    producer = state.get("review_producer_id", "")
    if not isinstance(producer, str):
        raise EmissionError("retained producer identity is invalid")
    excluded = ({producer} if producer else set())
    if not requirement.requester_may_approve:
        excluded.add(record.actor_id)
    if set(groups) & excluded:
        raise EmissionError("requester or recorded producer approved its own action")
    if any(grant.granted_at_us > certificate.finalized_at_us for grant in grants):
        raise EmissionError("approval grant is later than its certificate")
    return approved.record_hash, digest_hex(certificate)


def verify_retained_draft(
    connection: Any, p: TargetPermit, *, issuer_key_id: str, evidence_trust: TrustDirectory,
    current_evidence_key_id: str, expected_policy_version: str, max_decision_age_us: int,
    historical_evidence_key_ids: frozenset[str] = frozenset(),
    approval_authority: ApprovalWorkflow | None = None,
    evidence_verifier: PinnedVerifier | None = None,
    fence_grant_digests: tuple[str, ...] | None = None,
) -> tuple[SignedDecisionEnvelope, str, str]:
    """Check retained authority for an unsigned draft without consuming it.

    Supplying fence_grant_digests composes bounded interval verification before
    revocation locks and exact row rebinding after locks. The grant digests must
    come from a separately authenticated complete chain, never the request.
    None preserves the prior caller-owned fencing contract. No verification
    result from a caller is accepted as proof.

    No connection, transaction or signing key is created here. A refusal must
    propagate out of the caller's effect transaction so all staged writes roll
    back. Historical keys authenticate old chain links, never new authority.
    """
    from psycopg.pq import TransactionStatus

    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise EmissionError("retained authorization requires an active transaction")
    isolation, tenant = connection.execute(
        "SELECT current_setting('transaction_isolation'),current_setting('app.tenant',true)"
    ).fetchone()
    if isolation != "read committed" or tenant != p.tenant_id:
        raise EmissionError("retained authorization requires the matching READ COMMITTED tenant")
    if (not current_evidence_key_id or current_evidence_key_id == issuer_key_id
            or not evidence_trust.is_known(current_evidence_key_id)):
        raise EmissionError("current evidence authority must be trusted and distinct")
    if (not expected_policy_version or type(max_decision_age_us) is not int
            or max_decision_age_us <= 0 or not p.nonce):
        raise EmissionError("trusted policy, decision age and nonce are required")
    try:
        if fence_grant_digests is not None and evidence_verifier is None:
            raise EmissionError("composed authority fence requires bounded verification")
        verify_membership: Callable[[Any, int], SignedDecisionEnvelope] | None = (
            evidence_verifier.verify if evidence_verifier is not None else None
        )
        rows = connection.execute(
            "SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1"
            " WHERE tenant=%s AND envelope->>'record_hash'=%s"
            " AND envelope->'signature'->>'key_id'=%s ORDER BY seq LIMIT 1",
            (p.tenant_id, p.decision_record_hash, current_evidence_key_id),
        ).fetchall()
        if len(rows) != 1:
            raise EmissionError("no retained current-key decision; historical evidence cannot authorize")
        selected = decode_envelope(rows[0][2])
        if selected.clock_domain != p.clock_domain:
            raise EmissionError("retained decision and permit clock domains differ")
        if selected.signature.key_id != current_evidence_key_id:
            raise EmissionError("historical evidence cannot authorize a new effect")
        if evidence_verifier is not None:
            if (evidence_verifier.history.tenant != p.tenant_id
                    or evidence_verifier.current_key != current_evidence_key_id
                    or evidence_verifier.trust is not evidence_trust
                    or evidence_verifier.evidence_key_ids != historical_evidence_key_ids | {current_evidence_key_id}
                    or issuer_key_id in evidence_verifier.evidence_key_ids):
                raise EmissionError("checkpoint verifier differs from trusted receiver configuration")
            configuration = evidence_verifier.configuration_digest()
            if canonical_bytes(evidence_verifier.verify(connection, selected.seq)) != canonical_bytes(selected):
                raise EmissionError("selected decision differs from pinned verified history")
            if fence_grant_digests is not None:
                checked = {selected.seq: selected}
                if p.approval_ref:
                    row = PostgresReviewStore._latest(connection, p.tenant_id, p.approval_ref)
                    if row is None:
                        raise EmissionError("retained approval is missing")
                    approved = decode_envelope(PostgresReviewStore._payload(row)["envelope"])
                    if canonical_bytes(evidence_verifier.verify(connection, approved.seq)) != canonical_bytes(approved):
                        raise EmissionError("approval differs from verified retained history")
                    checked[approved.seq] = approved
                lock_current_authority(
                    connection, tenant_id=p.tenant_id, expected_epoch=p.revocation_epoch,
                    grant_digests=fence_grant_digests,
                )

                def recheck(conn: Any, seq: int) -> SignedDecisionEnvelope:
                    if (configuration != evidence_verifier.configuration_digest()
                            or seq not in checked):
                        raise EmissionError("verified authority or configuration changed before claim")
                    return evidence_verifier.recheck(conn, checked[seq])

                verify_membership = recheck
                recheck(connection, selected.seq)
        else:
            previous, next_seq = GENESIS, 0
            keys = historical_evidence_key_ids | {current_evidence_key_id}
            for seq, entry_hash, raw in connection.execute(
                "SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1"
                " WHERE tenant=%s AND seq<=%s ORDER BY seq", (p.tenant_id, selected.seq),
            ):
                entry = decode_envelope(raw)
                if (seq != next_seq or entry.seq != seq or entry.prev_hash != previous
                        or entry.record.tenant_id != p.tenant_id or _entry_hash(entry) != entry_hash
                        or entry.signature.key_id not in keys or not verify_envelope(entry, evidence_trust)):
                    raise EmissionError("retained evidence chain failed verification")
                previous, next_seq = entry_hash, seq + 1
            if next_seq != selected.seq + 1 or previous != _entry_hash(selected):
                raise EmissionError("selected evidence is not a verified chain member")
        record = selected.record
        if (record.tenant_id != p.tenant_id or record.record_id != p.decision_record_id
                or selected.record_hash != p.decision_record_hash or record.assertion_id != p.assertion_id
                or record.actor_id != p.principal or record.action.action_id != p.action_id
                or record.action.action_id != p.operation):
            raise EmissionError("decision principal or subject binding mismatch")
        if _policy(selected) != expected_policy_version or p.policy_version != expected_policy_version:
            raise EmissionError("decision policy binding mismatch")
        bound = effect_of(record.action.destination)
        if (bound is None or bound.output_digest != p.output_digest
                or bound.target.kind != p.target_kind or bound.target.digest() != p.target_digest
                or bound.target_state != p.expected_target_state or bound.mission != p.mission):
            raise EmissionError("decision effect binding mismatch")
        now_us = int(connection.execute(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
        ).fetchone()[0])
        if (not record.decided_at_us <= now_us < record.decided_at_us + max_decision_age_us
                or now_us >= p.expires_at_us
                or p.expires_at_us > record.decided_at_us + max_decision_age_us):
            raise EmissionError("decision or permit outside the configured validity window")
        authority_record_hash, approval_digest = selected.record_hash, ""
        if record.decision.kind is DecisionKind.REQUIRE_APPROVAL:
            authority_record_hash, approval_digest = _approval(
                connection, p, issuer_key_id, selected, approval_authority, now_us, evidence_trust, verify_membership,
            )
        elif not record.decision.is_allow_class or p.approval_ref:
            raise EmissionError("decision does not authorize the claimed approval")
        return selected, authority_record_hash, approval_digest
    except (PersistenceError, ReviewError, KeyError, TypeError, ValueError) as exc:
        raise EmissionError("retained authorization data failed verification") from exc


def claim_retained_authorization(
    connection: Any, signed: SignedTargetPermit, *, evidence_trust: TrustDirectory,
    current_evidence_key_id: str, expected_policy_version: str, max_decision_age_us: int,
    historical_evidence_key_ids: frozenset[str] = frozenset(),
    approval_authority: ApprovalWorkflow | None = None,
    evidence_verifier: PinnedVerifier | None = None,
    fence_grant_digests: tuple[str, ...] | None = None,
    require_preparation: bool = False,
    input_verifier: InputVerifier | None = None,
    delegated_verifier: DelegatedEffectVerifier | None = None,
    target_ref: TargetRef | None = None,
) -> SignedDecisionEnvelope:
    """Check and consume retained authority in the caller's effect transaction."""
    if target_ref is not None and (
        not signed.permit.preparation_digest
        or target_ref.kind != signed.permit.target_kind
        or target_ref.digest() != signed.permit.target_digest
    ):
        raise EmissionError("database receiver requires exact prepared target authority")
    if signed.permit.preparation_digest and (evidence_verifier is None or (fence_grant_digests is None and not signed.permit.grant_digest)):
        raise EmissionError("v4 receiver requires bounded verification and a composed fence")
    if (require_preparation or input_verifier is not None or signed.permit.grant_digest) and not signed.permit.preparation_digest:
        raise EmissionError("receiver requires a preparation-bound permit")
    selected, authority_hash, approval_digest = verify_retained_draft(
        connection, signed.permit, issuer_key_id=signed.signature.key_id,
        evidence_trust=evidence_trust, current_evidence_key_id=current_evidence_key_id,
        expected_policy_version=expected_policy_version,
        max_decision_age_us=max_decision_age_us,
        historical_evidence_key_ids=historical_evidence_key_ids,
        approval_authority=approval_authority, evidence_verifier=evidence_verifier,
        fence_grant_digests=None if signed.permit.grant_digest else fence_grant_digests,
    )
    p = signed.permit
    if p.preparation_digest:
        from .prepared_issuance_pg import (load_preparation_on, check_preparation_authority,
                                           verify_prepared_inputs_on)
        from .persistence_pg import PostgresMissionBudget

        proof = load_preparation_on(
            connection, p, issuer_key_id=signed.signature.key_id,
            evidence_trust=evidence_trust, current_evidence_key_id=current_evidence_key_id,
        )
        verify_delegation_on(connection, p, selected, verifier=delegated_verifier,
                             inputs=input_verifier, history=evidence_verifier,
                             proof=proof.signed_body(), approval_authority=approval_authority)
        if target_ref is not None:
            from .authority_fence_pg import lock_database_target

            lock_database_target(connection, tenant_id=p.tenant_id, target_digest=target_ref.digest())
            # Target contention can outlast credentials or approvals. Rebind
            # before taking the mission lock; every later callback check stays.
            selected, authority_hash, approval_digest = verify_retained_draft(
                connection, p, issuer_key_id=signed.signature.key_id,
                evidence_trust=evidence_trust, current_evidence_key_id=current_evidence_key_id,
                expected_policy_version=expected_policy_version,
                max_decision_age_us=max_decision_age_us,
                historical_evidence_key_ids=historical_evidence_key_ids,
                approval_authority=approval_authority, evidence_verifier=evidence_verifier,
                fence_grant_digests=None if p.grant_digest else fence_grant_digests,
            )
            verify_delegation_on(connection, p, selected, verifier=delegated_verifier,
                                 inputs=input_verifier, history=evidence_verifier,
                                 proof=proof.signed_body(), approval_authority=approval_authority)
        check_preparation_authority(
            connection, proof, p, decision_seq=selected.seq, authority_hash=authority_hash,
            approval_digest=approval_digest, budget=PostgresMissionBudget(pool=None),
        )
        if evidence_verifier is None:
            raise EmissionError("prepared input verification requires bounded evidence")
        verify_prepared_inputs_on(
            connection, proof, p, verifier=input_verifier, evidence_trust=evidence_trust,
            evidence_key_id=current_evidence_key_id, evidence_verifier=evidence_verifier,
        )
    verify_delegation_on(connection, p, selected, verifier=delegated_verifier,
                         inputs=input_verifier, history=evidence_verifier,
                         proof=proof.signed_body() if p.preparation_digest else None, approval_authority=approval_authority)
    claimed = connection.execute(
        "INSERT INTO regulated_decision_uses_v1 (tenant,record_hash,permit_digest,nonce)"
        " VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING nonce",
        (p.tenant_id, authority_hash, digest_hex(p.signed_body()), p.nonce),
    ).fetchone()
    if claimed is None:
        raise EmissionError("decision or permit already consumed")
    return selected
