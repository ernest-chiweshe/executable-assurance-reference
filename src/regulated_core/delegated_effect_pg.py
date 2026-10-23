"""Current authenticated effect inputs composed with stored delegation authority."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Protocol

from .approval import ApprovalWorkflow
from .canonical import canonical_bytes
from .delegation import RELEASE_AUTHORITY_FIELD, release_authority_of
from .delegation_chain_pg import resolve_stored_chain_on, evaluate_chain_restrictions
from .evidence import SignedDecisionEnvelope
from .evidence_checkpoints_pg import PinnedVerifier
from .input_evidence import InputVerifier
from .input_evidence_pg import load_inputs_on
from .permit import EmissionError
from .registry import ConsequencePolicy, DeclaresMissionBudget
from .restrictions import RestrictionRegistry, policy_ref
from .root_admission_pg import RootAdmissionVerifier
from .target import TargetPermit


class ExecutorAuthority(Protocol):
    """Host-owned executor membership and classification, not a name prefix."""

    def verify_on(self, conn: Any, tenant: str, principal: str) -> str:
        """Return current identity revision or refuse, on the caller connection."""
        ...


@dataclass(frozen=True)
class DelegatedEffectVerifier:
    """Verify through host-configured policy, identity and retained trust."""

    root: RootAdmissionVerifier
    policy: ConsequencePolicy
    restrictions: RestrictionRegistry
    executors: ExecutorAuthority

    def verify_on(
        self, conn: Any, permit: TargetPermit, envelope: SignedDecisionEnvelope, *,
        inputs: InputVerifier | None, history: PinnedVerifier,
    ) -> tuple[int, int]:
        """Return policy units and the inherited mission limit, never an effect."""
        if (inputs is None or inputs is not self.root.inputs or history is not self.root.history
                or not all((permit.grant_digest, permit.chain_digest, permit.root_digest))
                or envelope.record_hash != permit.decision_record_hash):
            raise EmissionError("delegated effect verification configuration or decision mismatch")
        configuration = history.configuration_digest()
        retained = load_inputs_on(
            conn, envelope, verifier=inputs, evidence_trust=self.root.trust,
            evidence_key_id=self.root.evidence_key_id, evidence_verifier=history,
            expected_nonce=permit.nonce,
        )
        data = retained.inputs
        try:
            claim = release_authority_of(json.loads(data.action.destination).get(RELEASE_AUTHORITY_FIELD))
        except (TypeError, ValueError) as exc:
            raise EmissionError("delegated action authority is malformed") from exc
        if (claim is None or (claim.grant_digest, claim.chain_digest, claim.root_digest, claim.mission) !=
                (permit.grant_digest, permit.chain_digest, permit.root_digest, permit.mission)):
            raise EmissionError("delegated effect differs from authenticated action authority")
        checked = resolve_stored_chain_on(
            conn, permit.tenant_id, permit.grant_digest,
            verifier=self.root, expected_epoch=permit.revocation_epoch,
        )
        if history.configuration_digest() != configuration:
            raise EmissionError("retained evidence configuration changed while acquiring locks")
        history.recheck(conn, envelope)
        chain = checked.chain
        if (chain.digest != permit.chain_digest or chain.root.digest() != permit.root_digest
                or chain.leaf.subject != permit.principal or data.context.actor.actor_id != permit.principal
                or data.context.actor.producer or not permit.principal.startswith("executor:")
                or permit.operation not in chain.leaf.operations or data.action.action_id != permit.operation
                or permit.target_digest not in chain.leaf.targets
                or chain.root.root_mission != permit.mission
                or permit.expires_at_us > chain.expires_at_us):
            raise EmissionError("executor, scope, target, mission or expiry exceeds delegated authority")
        revision = self.executors.verify_on(conn, permit.tenant_id, permit.principal)
        if not isinstance(revision, str) or not revision:
            raise EmissionError("executor lacks authenticated host membership")
        ref = self.policy.ref
        if (canonical_bytes(ref) != canonical_bytes(data.policy)
                or canonical_bytes(ref) != canonical_bytes(envelope.record.policy)
                or not isinstance(self.policy, DeclaresMissionBudget)):
            raise EmissionError("current delegated policy differs from signed inputs")
        decision = self.policy.evaluate(data.assertion, data.action,
                                        replace(data.context, now_us=inputs.now_on(conn)))
        if canonical_bytes(decision) != canonical_bytes(envelope.record.decision):
            raise EmissionError("current delegated policy no longer authorizes recorded decision")
        # The current policy already produced the authenticated decision, whose
        # approval (if required) is checked by retained_authority_pg.
        evaluate_chain_restrictions(
            chain, restrictions=self.restrictions, assertion=data.assertion,
            action=data.action, context=replace(data.context, now_us=inputs.now_on(conn)),
            decided_policy_ref=policy_ref(self.policy),
        )
        terms = self.policy.mission_budget(permit.action_id)
        if (terms is None or set(terms) != {"units", "limit"}
                or type(terms["units"]) is not int or terms["units"] < 1
                or type(terms["limit"]) is not int
                or terms["limit"] != chain.root.budget_limit
                or type(permit.budget_units) is not int
                or terms["units"] != permit.budget_units):
            raise EmissionError("delegated budget differs from current policy or shared root ceiling")
        if (canonical_bytes(self.policy.ref) != canonical_bytes(ref)
                or self.executors.verify_on(conn, permit.tenant_id, permit.principal) != revision):
            raise EmissionError("policy or executor membership changed during verification")
        inputs.verify_on(conn, data, retained.admission,
                         evidence_key_id=self.root.evidence_key_id, now_us=inputs.now_on(conn))
        now = inputs.now_on(conn)
        inputs.verify_at(data, retained.admission, evidence_key_id=self.root.evidence_key_id, now_us=now)
        if now >= min(permit.expires_at_us, chain.expires_at_us):
            raise EmissionError("delegated authority expired during verification")
        return terms["units"], chain.root.budget_limit


def verify_delegation_on(
    conn: Any, permit: TargetPermit, envelope: SignedDecisionEnvelope, *,
    verifier: DelegatedEffectVerifier | None, inputs: InputVerifier | None,
    history: PinnedVerifier | None, proof: dict[str, Any] | None = None,
    approval_authority: ApprovalWorkflow | None = None,
) -> None:
    """Refuse delegated requests without complete configured verification."""
    if not any((permit.grant_digest, permit.chain_digest, permit.root_digest)):
        return
    if verifier is None or history is None or inputs is None:
        raise EmissionError("delegated effect requires trusted verifier and retained history")
    units, limit = verifier.verify_on(conn, permit, envelope, inputs=inputs, history=history)
    if permit.approval_ref:
        from .retained_authority_pg import _approval

        _, approval_digest = _approval(
            conn, permit, verifier.root.permit_key_id, envelope, approval_authority,
            inputs.now_on(conn), verifier.root.trust, history.verify,
        )
        if proof is not None and proof["approval_certificate_digest"] != approval_digest:
            raise EmissionError("retained approval changed after authority fencing")
    if proof is not None and canonical_bytes([proof["budget_units"], proof["budget_limit"]]) != canonical_bytes([units, limit]):
        raise EmissionError("preparation budget differs from verified delegated authority")
    # Approval verification may block after the chain/input deadline checks.
    if inputs.now_on(conn) >= permit.expires_at_us:
        raise EmissionError("delegated authority expired during approval verification")
