"""Stored delegation-chain verification on the effect's existing connection.

This authenticates retained provenance and current revocation state. It does not
issue children or permits, reserve budget, commit effects, or authenticate an
executor session. Callers must compose those boundaries before executing.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .authority_fence_pg import grant_revocation_key, lock_current_authority
from .canonical import canonical_bytes, digest_hex
from .delegation import Chain, DelegationGrant, SignedGrant, MAX_DEPTH, _narrows
from .input_evidence_pg import _scope
from .models import Assertion, Action, PolicyContext, DecisionKind
from .permit import EmissionError
from .persistence_pg import _decode_grant
from .restrictions import RestrictionRegistry, policy_ref
from .root_admission_pg import RootAdmissionVerifier, load_root_provenance_on


@dataclass(frozen=True)
class StoredChain:
    """Verified lineage and admission time; no portable authorization token."""

    chain: Chain
    root_admitted_at_us: int
    root_proof_digest: str


def _shape(grant: DelegationGrant) -> None:
    """Reject coercible numeric and empty authority fields before attenuation."""
    if not all(isinstance(v, str) for v in (grant.parent_digest, grant.decision_record_id, grant.approval_digest)):
        raise EmissionError("stored grant has invalid reference types")
    strings = (grant.tenant_id, grant.issuer_subject, grant.subject, grant.root_mission)
    if (any(not isinstance(v, str) or not v.strip() for v in strings)
            or type(grant.delegable) is not bool
            or any(type(v) is not int for v in
                   (grant.budget_limit, grant.issued_at_us, grant.expires_at_us))
            or grant.budget_limit < 1 or grant.issued_at_us < 0
            or grant.expires_at_us <= grant.issued_at_us):
        raise EmissionError("stored grant has invalid authority field types")
    for values in (grant.operations, grant.targets, grant.policy_refs):
        if (not values or any(not isinstance(v, str) or not v for v in values)
                or len(set(values)) != len(values)):
            raise EmissionError("stored grant has invalid or duplicate scope")
    for target in grant.targets:
        grant_revocation_key(grant.tenant_id, target)
    if not grant.is_root and not grant.subject.startswith("executor:"):
        raise EmissionError("child subject must be a host-authenticated executor")
    if not grant.is_root and grant.subject == "executor:":
        raise EmissionError("child executor identity is empty")


def _stored(conn: Any, tenant: str, digest: str) -> tuple[SignedGrant, bytes]:
    grant_revocation_key(tenant, digest)
    row = conn.execute(
        "SELECT parent_digest,body,signature FROM regulated_delegation_grants_v1"
        " WHERE tenant=%s AND grant_digest=%s", (tenant, digest),
    ).fetchone()
    if row is None:
        raise EmissionError("stored chain link is missing")
    try:
        signed = _decode_grant(row[1], row[2])
        raw = json.loads(row[1])
        _shape(signed.grant)
        if (canonical_bytes(raw) != canonical_bytes(signed.grant.body())
                or row[0] != signed.grant.parent_digest
                or signed.grant.tenant_id != tenant or signed.digest != digest):
            raise EmissionError("stored grant bytes or relational binding differ")
        return signed, canonical_bytes([row[0], raw, row[2]])
    except (KeyError, TypeError, ValueError) as exc:
        raise EmissionError("stored grant is malformed") from exc


def resolve_stored_chain_on(
    conn: Any, tenant: str, leaf_digest: str, *,
    verifier: RootAdmissionVerifier, expected_epoch: int,
) -> StoredChain:
    """Authenticate all ancestors before fencing, then rebind their exact bytes.

    The maximum depth is the existing product limit. Root provenance includes
    its real admitted-at time: an earlier signed decision is not a grant.
    Revocation locks remain in this caller-owned READ COMMITTED transaction.
    No pooled connection or caller-supplied verified-chain shortcut is used.
    """
    _scope(conn, tenant)
    verifier.domains()
    grant_revocation_key(tenant, leaf_digest)
    configuration = verifier.history.configuration_digest()
    lineage: list[SignedGrant] = []
    snapshots: dict[str, bytes] = {}
    cursor = leaf_digest
    while cursor:
        if cursor in snapshots or len(lineage) >= MAX_DEPTH:
            raise EmissionError("stored chain has a cycle or exceeds maximum depth")
        signed, snapshot = _stored(conn, tenant, cursor)
        if (signed.signature.key_id != verifier.delegation_key_id
                or not verifier.trust.verify(signed.grant.body(), signed.signature)):
            raise EmissionError("stored chain signature has wrong authority")
        lineage.append(signed)
        snapshots[cursor] = snapshot
        cursor = signed.grant.parent_digest
    lineage.reverse()
    chain = Chain(tuple(s.grant for s in lineage))
    root = load_root_provenance_on(conn, tenant, chain.root.digest(), verifier=verifier)
    if canonical_bytes(root.signed) != canonical_bytes(lineage[0]):
        raise EmissionError("chain root differs from its admission")
    for parent, child in zip(chain.grants, chain.grants[1:]):
        problem = _narrows(child, parent)
        if problem is not None:
            raise EmissionError(problem)
        if child.issued_at_us < max(parent.issued_at_us, root.admitted_at_us):
            raise EmissionError("child predates parent issuance or root admission")
    # Bounded history and signatures run before taking revocation locks.
    lock_current_authority(conn, tenant_id=tenant, expected_epoch=expected_epoch,
                           grant_digests=tuple(snapshots))
    if configuration != verifier.history.configuration_digest():
        raise EmissionError("historical verification configuration changed")
    for digest, snapshot in snapshots.items():
        if _stored(conn, tenant, digest)[1] != snapshot:
            raise EmissionError("stored chain changed while waiting for authority locks")
    proof = conn.execute(
        "SELECT body,signature FROM regulated_root_admissions_v1"
        " WHERE tenant=%s AND root_digest=%s", (tenant, chain.root.digest()),
    ).fetchone()
    if proof is None or digest_hex({"body": proof[0], "signature": proof[1]}) != root.proof_digest:
        raise EmissionError("root admission changed while waiting for authority locks")
    now = verifier.inputs.now_on(conn)
    if any(not grant.issued_at_us <= now < grant.expires_at_us for grant in chain.grants):
        raise EmissionError("stored chain is expired or issued in the future")
    return StoredChain(chain, root.admitted_at_us, root.proof_digest)


def evaluate_chain_restrictions(
    chain: Chain, *, restrictions: RestrictionRegistry,
    assertion: Assertion, action: Action, context: PolicyContext, decided_policy_ref: str = "",
) -> None:
    """Evaluate inherited references other than the already evaluated policy.

    This pure policy step supplies neither identity authentication nor expiry or
    revocation checks. The composed receiver must provide those in its effect
    transaction. Missing policies and separately required approvals refuse.
    """
    for ref in sorted(set(chain.leaf.policy_refs) - {decided_policy_ref}):
        policy = restrictions.get(ref)
        if policy is None or policy_ref(policy) != ref:
            raise EmissionError("inherited restriction is missing or changed")
        verdict = policy.evaluate(assertion, action, context)
        if (policy_ref(policy) != ref or verdict.kind not in
                (DecisionKind.ALLOW, DecisionKind.ALLOW_WITH_ANNOTATION)):
            raise EmissionError("inherited restriction does not authorize this action")
