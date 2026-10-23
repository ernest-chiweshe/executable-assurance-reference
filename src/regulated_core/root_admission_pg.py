"""Retained root-admission provenance on the existing grant and review contracts.

This module does not authorize effects. Receivers must separately authenticate
the complete current chain, evaluate its restrictions and fence revocation.
The admission timestamp is signed database-clock evidence, not a WAL timestamp.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Protocol

from .approval import ApprovalWorkflow, _match_groups
from .approval_evidence import verified_approvals
from .authority_fence_pg import lock_current_authority
from .canonical import canonical_bytes, digest_hex
from .delegation import DelegationGrant, SignedGrant, PROPOSAL_FIELD, delegation_proposal_of
from .evidence import SignedDecisionEnvelope
from .evidence_checkpoints_pg import PinnedVerifier
from .input_evidence import InputVerifier
from .input_evidence_pg import RetainedInputs, _scope, _load_inputs_on
from .models import Assertion, Action, PolicyContext, PolicyRef, Decision, DecisionKind
from .permit import EmissionError
from .persistence_pg import _decode_grant, decode_envelope
from .review_store import PostgresReviewStore
from .signing import Signer, Signature, TrustDirectory

SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_root_admissions_v1 (
 tenant TEXT NOT NULL, root_digest TEXT NOT NULL, decision_seq BIGINT NOT NULL,
 body JSONB NOT NULL, signature JSONB NOT NULL,
 PRIMARY KEY(tenant,root_digest), UNIQUE(tenant,decision_seq),
 FOREIGN KEY(tenant,root_digest) REFERENCES regulated_delegation_grants_v1(tenant,grant_digest),
 FOREIGN KEY(tenant,decision_seq) REFERENCES regulated_decision_evidence_v1(tenant,seq));
ALTER TABLE regulated_root_admissions_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_root_admissions_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS regulated_root_admission_tenant_v1 ON regulated_root_admissions_v1;
CREATE POLICY regulated_root_admission_tenant_v1 ON regulated_root_admissions_v1
 USING (tenant=current_setting('app.tenant',true))
 WITH CHECK (tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS regulated_root_admission_immutable_v1 ON regulated_root_admissions_v1;
CREATE TRIGGER regulated_root_admission_immutable_v1 BEFORE UPDATE OR DELETE
 ON regulated_root_admissions_v1 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS regulated_root_admission_no_truncate_v1 ON regulated_root_admissions_v1;
CREATE TRIGGER regulated_root_admission_no_truncate_v1 BEFORE TRUNCATE
 ON regulated_root_admissions_v1 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""


class RootSubjectAuthority(Protocol):
    """Host-owned authentication of an accountable root principal."""

    def verify_on(self, conn: Any, tenant: str, subject: str) -> str:
        """Return a nonempty identity revision or raise; no pooled connection."""
        ...


class AdmissionPolicy(Protocol):
    """Trusted version-pinned policy; never loaded from the request or proof."""

    ref: PolicyRef

    def evaluate(self, assertion: Assertion, action: Action, ctx: PolicyContext) -> Decision: ...
    def mission_budget(self, action_id: str) -> Any: ...


@dataclass(frozen=True)
class RootAdmissionVerifier:
    """Host-pinned verification authorities for admission and historical reads."""

    trust: TrustDirectory
    evidence_key_id: str
    delegation_key_id: str
    permit_key_id: str
    approvals: ApprovalWorkflow
    inputs: InputVerifier
    history: PinnedVerifier
    policy: AdmissionPolicy
    subjects: RootSubjectAuthority

    def domains(self) -> None:
        keys = (self.evidence_key_id, self.delegation_key_id, self.permit_key_id,
                self.approvals._signer.key_id, *self.approvals.credential_authority_ids,
                self.inputs.identity_key_id, self.inputs.ingress_key_id)
        if (not self.approvals.requires_credentials or not self.trust.distinct_keys(keys)
                or not all(key and self.trust.is_known(key) for key in keys if key is not None)
                or self.inputs.trust is not self.trust
                or self.approvals._trust is not self.trust
                or self.history.trust is not self.trust
                or self.inputs.delegation_key_id != self.delegation_key_id
                or self.inputs.permit_key_id != self.permit_key_id
                or self.inputs.approval_key_id != self.approvals._signer.key_id
                or self.evidence_key_id not in self.history.evidence_key_ids):
            raise EmissionError("root admission authority domains are invalid")

    def expected(
        self, envelope: SignedDecisionEnvelope, retained: RetainedInputs,
        state: dict[str, Any], at_us: int,
    ) -> DelegationGrant:
        """Reconstruct every root fact from authenticated approved inputs."""
        self.domains()
        record, inputs = envelope.record, retained.inputs
        requirement = record.decision.approval
        proposal = delegation_proposal_of(json.loads(record.action.destination).get(PROPOSAL_FIELD))
        if (proposal is None or requirement is None
                or record.decision.kind is not DecisionKind.REQUIRE_APPROVAL
                or type(at_us) is not int
                or not record.decided_at_us <= at_us < min(
                    proposal.admit_by_us, proposal.expires_at_us,
                    record.decided_at_us + requirement.expires_after_us)
                or inputs.context.actor.producer or not proposal.subject.strip()
                or proposal.subject.startswith("executor:") or not proposal.root_mission.strip()
                or self.policy.ref != record.policy or not record.policy.digest
                or canonical_bytes(decode_envelope(state["envelope"])) != canonical_bytes(envelope)):
            raise EmissionError("root proposal, admission time or policy binding invalid")
        self.inputs.verify_at(inputs, retained.admission,
                              evidence_key_id=self.evidence_key_id, now_us=at_us)
        if canonical_bytes(self.policy.evaluate(inputs.assertion, inputs.action,
                                replace(inputs.context, now_us=at_us))) != canonical_bytes(record.decision):
            raise EmissionError("root policy no longer makes the approved decision")
        budget = self.policy.mission_budget(record.action.action_id)
        if (not isinstance(budget, dict) or type(budget.get("limit")) is not int
                or budget["limit"] < 1):
            raise EmissionError("root admission requires the policy mission budget")
        request = self.approvals.open(
            request_id=state["review_id"], requester_id=record.actor_id,
            tenant_id=record.tenant_id, assertion_id=record.assertion_id,
            decision_record_id=record.record_id, decision_record_hash=envelope.record_hash,
            requirement=requirement, now_us=record.decided_at_us,
        )
        grants, cert = verified_approvals(self.approvals, state, envelope, request, now_us=at_us)
        groups = {g.reviewer_id: set(g.satisfied_groups) for g in grants}
        producer = inputs.assertion.lineage.producer if inputs.assertion.lineage else ""
        if (cert is None or len(groups) < requirement.minimum_approvers
                or not _match_groups(groups, len(requirement.role_groups))
                or any(g.granted_at_us > cert.finalized_at_us for g in grants)
                or (not requirement.requester_may_approve
                    and set(groups) & {record.actor_id, producer})):
            raise EmissionError("root approval quorum, chronology or separation invalid")
        return DelegationGrant(
            record.tenant_id, "", ",".join(sorted(cert.approver_ids)), proposal.subject,
            proposal.delegable, tuple(sorted(set(proposal.operations))),
            tuple(sorted(set(proposal.targets))),
            (f"{record.policy.vertical}/{record.policy.policy_id}@{record.policy.digest}",),
            proposal.root_mission, budget["limit"], proposal.expires_at_us,
            record.record_id, digest_hex(cert.signed_body()), record.decided_at_us,
        )


def _inputs(conn: Any, envelope: SignedDecisionEnvelope, verifier: RootAdmissionVerifier,
            nonce: str, at_us: int | None = None) -> RetainedInputs:
    return _load_inputs_on(
        conn, envelope, verifier=verifier.inputs, evidence_trust=verifier.trust,
        evidence_key_id=verifier.evidence_key_id, evidence_verifier=verifier.history,
        expected_nonce=nonce, historical_at_us=at_us,
    )


@dataclass(frozen=True)
class RootProvenance:
    """Authenticated admission metadata; not current effect authority."""

    signed: SignedGrant
    admitted_at_us: int
    proof_digest: str


def load_root_provenance_on(
    conn: Any, tenant: str, root_digest: str, *, verifier: RootAdmissionVerifier,
) -> RootProvenance:
    """Revalidate stored provenance; this alone grants no current effect authority."""
    _scope(conn, tenant)
    verifier.domains()
    row = conn.execute(
        "SELECT a.decision_seq,a.body,a.signature,g.body,g.signature "
        "FROM regulated_root_admissions_v1 a JOIN regulated_delegation_grants_v1 g "
        "ON (g.tenant,g.grant_digest)=(a.tenant,a.root_digest) "
        "WHERE a.tenant=%s AND a.root_digest=%s", (tenant, root_digest),
    ).fetchone()
    if row is None:
        raise EmissionError("root has no retained admission proof")
    try:
        body, signature = row[1], Signature(**row[2])
        if (set(body) != {"schema", "tenant", "root_digest", "decision_seq", "decision_hash",
                         "input_companion_digest", "nonce", "admitted_at_us", "review", "subject_revision"}
                or body["schema"] != "regulated/root-admission/v1"
                or body["tenant"] != tenant or body["root_digest"] != root_digest
                or body["decision_seq"] != row[0]
                or type(body["admitted_at_us"]) is not int
                or not isinstance(body["subject_revision"], str) or not body["subject_revision"]
                or body["admitted_at_us"] > verifier.inputs.now_on(conn)
                or not verifier.trust.verify(body, signature)):
            raise EmissionError("root admission proof is invalid")
        signed = _decode_grant(row[3], row[4])
        envelope = verifier.history.verify(conn, row[0], require_current=False)
        # Select the historical evidence domain only from verified retained
        # history. Retired keys require checkpoint coverage, not caller trust.
        historical = replace(verifier, evidence_key_id=envelope.signature.key_id)
        historical.domains()
        if (signature.key_id != historical.evidence_key_id
                or envelope.record.tenant_id != tenant or envelope.record_hash != body["decision_hash"]
                or signed.digest != root_digest or signed.signature.key_id != verifier.delegation_key_id
                or not verifier.trust.verify(signed.grant.body(), signed.signature)):
            raise EmissionError("root or admitting decision signature mismatch")
        retained = _inputs(conn, envelope, historical, body["nonce"], body["admitted_at_us"])
        expected = historical.expected(envelope, retained, body["review"], body["admitted_at_us"])
        if (retained.companion_digest != body["input_companion_digest"]
                or canonical_bytes(expected.body()) != canonical_bytes(signed.grant.body())):
            raise EmissionError("root differs from its authenticated admission facts")
        return RootProvenance(signed, body["admitted_at_us"],
                              digest_hex({"body": body, "signature": signature}))
    except (KeyError, TypeError, ValueError) as exc:
        raise EmissionError("root admission data is malformed") from exc


def load_root_admission_on(
    conn: Any, tenant: str, root_digest: str, *, verifier: RootAdmissionVerifier,
) -> SignedGrant:
    """Return the historically authenticated root; current authority is separate."""
    return load_root_provenance_on(conn, tenant, root_digest, verifier=verifier).signed


def _admit_root_on(
    conn: Any, tenant: str, review_id: str, *, nonce: str,
    verifier: RootAdmissionVerifier, evidence_signer: Signer, delegation_signer: Signer,
) -> SignedGrant:
    """Append root and signed provenance in the caller's admission transaction.

    Caller must let refusals abort the transaction. The trusted host owns the
    signers and pinned policy. No timestamps or root facts are caller supplied.
    No signing key is needed by load_root_admission_on.
    """
    _scope(conn, tenant)
    verifier.domains()
    if (evidence_signer.key_id != verifier.evidence_key_id
            or delegation_signer.key_id != verifier.delegation_key_id):
        raise EmissionError("root admission signer mismatch")
    row = PostgresReviewStore._latest(conn, tenant, review_id)
    if row is None:
        raise EmissionError("root admission review is missing")
    state = PostgresReviewStore._payload(row)
    if state.get("review_id") != review_id:
        raise EmissionError("root admission review reference mismatch")
    envelope = decode_envelope(state["envelope"])
    if envelope.record.tenant_id != tenant:
        raise EmissionError("root admission tenant mismatch")
    retained = _inputs(conn, envelope, verifier, nonce)
    proposal = delegation_proposal_of(json.loads(envelope.record.action.destination).get(PROPOSAL_FIELD))
    if proposal is None:
        raise EmissionError("root admission proposal is missing")
    lock_current_authority(conn, tenant_id=tenant, expected_epoch=proposal.revocation_epoch)
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                 (canonical_bytes(["root-admission", tenant, envelope.seq]).decode(),))
    verifier.inputs.verify_on(conn, retained.inputs, retained.admission,
                              evidence_key_id=verifier.evidence_key_id, now_us=verifier.inputs.now_on(conn))
    subject_revision = verifier.subjects.verify_on(conn, tenant, proposal.subject)
    if not isinstance(subject_revision, str) or not subject_revision:
        raise EmissionError("root subject has no authenticated identity revision")
    admitted_at = verifier.inputs.now_on(conn)
    grant = verifier.expected(envelope, retained, state, admitted_at)
    found = conn.execute(
        "SELECT root_digest FROM regulated_root_admissions_v1 WHERE tenant=%s AND decision_seq=%s",
        (tenant, envelope.seq),
    ).fetchone()
    if found is not None:
        existing = load_root_admission_on(conn, tenant, found[0], verifier=verifier)
        if canonical_bytes(existing.grant.body()) != canonical_bytes(grant.body()):
            raise EmissionError("decision already admitted different root facts")
        verifier.inputs.verify_on(conn, retained.inputs, retained.admission,
                                  evidence_key_id=verifier.evidence_key_id, now_us=verifier.inputs.now_on(conn))
        if verifier.subjects.verify_on(conn, tenant, proposal.subject) != subject_revision:
            raise EmissionError("root subject changed during admission")
        _fresh_deadline(conn, envelope, retained, verifier)
        return existing
    signed = SignedGrant(grant, delegation_signer.sign(grant.body()))
    body = {"schema": "regulated/root-admission/v1", "tenant": tenant,
            "root_digest": signed.digest, "decision_seq": envelope.seq,
            "decision_hash": envelope.record_hash,
            "input_companion_digest": retained.companion_digest, "nonce": nonce,
            "admitted_at_us": admitted_at, "review": state, "subject_revision": subject_revision}
    signature = evidence_signer.sign(body)
    if (signed.signature.key_id != verifier.delegation_key_id
            or signature.key_id != verifier.evidence_key_id
            or not verifier.trust.verify(grant.body(), signed.signature)
            or not verifier.trust.verify(body, signature)):
        raise EmissionError("root admission signing failed")
    conn.execute(
        "INSERT INTO regulated_delegation_grants_v1(tenant,grant_digest,parent_digest,body,signature)"
        " VALUES (%s,%s,'',%s,%s::jsonb)",
        (tenant, signed.digest, canonical_bytes(grant.body()).decode(), canonical_bytes(signed.signature).decode()),
    )
    conn.execute(
        "INSERT INTO regulated_root_admissions_v1(tenant,root_digest,decision_seq,body,signature)"
        " VALUES (%s,%s,%s,%s::jsonb,%s::jsonb)",
        (tenant, signed.digest, envelope.seq, canonical_bytes(body).decode(), canonical_bytes(signature).decode()),
    )
    verifier.inputs.verify_on(conn, retained.inputs, retained.admission,
                              evidence_key_id=verifier.evidence_key_id, now_us=verifier.inputs.now_on(conn))
    if verifier.subjects.verify_on(conn, tenant, proposal.subject) != subject_revision:
        raise EmissionError("root subject changed during admission")
    # Host callbacks, signing and inserts can block. Recheck pure deadlines last.
    if canonical_bytes(verifier.expected(envelope, retained, state, verifier.inputs.now_on(conn)).body()) != canonical_bytes(grant.body()):
        raise EmissionError("root admission changed during signing")
    _fresh_deadline(conn, envelope, retained, verifier)
    return signed


def _fresh_deadline(conn: Any, envelope: SignedDecisionEnvelope,
                    retained: RetainedInputs, verifier: RootAdmissionVerifier) -> None:
    """Recheck temporal bounds after the last potentially blocking policy call."""
    now = verifier.inputs.now_on(conn)
    requirement = envelope.record.decision.approval
    proposal = delegation_proposal_of(json.loads(envelope.record.action.destination)[PROPOSAL_FIELD])
    if requirement is None or proposal is None or now >= min(
        proposal.admit_by_us, proposal.expires_at_us,
        envelope.record.decided_at_us + requirement.expires_after_us,
    ):
        raise EmissionError("root admission expired during blocking work")
    verifier.inputs.verify_at(retained.inputs, retained.admission,
                              evidence_key_id=verifier.evidence_key_id, now_us=now)


def admit_root_on(
    conn: Any, tenant: str, review_id: str, *, nonce: str,
    verifier: RootAdmissionVerifier, evidence_signer: Signer, delegation_signer: Signer,
) -> SignedGrant:
    """Stage a validated root and proof together inside a rollback savepoint.

    The outer caller still owns commit. A refusal rolls this admission back even
    if the caller catches the exception and continues its transaction.
    """
    _scope(conn, tenant)
    with conn.transaction():
        return _admit_root_on(
            conn, tenant, review_id, nonce=nonce, verifier=verifier,
            evidence_signer=evidence_signer, delegation_signer=delegation_signer,
        )
