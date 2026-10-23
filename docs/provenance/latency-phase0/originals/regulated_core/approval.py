"""Human approval: credential-verified, dual-control, requirement-bound, trust-anchored.

Combines the two cores' strengths:
  * role GROUPS + minimum distinct approvers (source review) with a distinct-reviewer matching so one
    person cannot fill two required groups;
  * `requirement_digest` bound into the certificate (integration review) so a genuine weaker approval cannot
    be reused for a stricter action;
  * every grant and the final certificate is signed by the APPROVAL AUTHORITY and verified
    against the trust directory by identity name (fixes source review's no-trust-anchor verify);
  * a probabilistic producer, and (by default) the requester, may not approve.
"""
from __future__ import annotations

from typing import Any
from collections.abc import Mapping
from types import MappingProxyType

import re
from dataclasses import dataclass

from .identity import IdentityVerifier
from .identity_provider import CredentialReceipt
from .evidence import SignedDecisionEnvelope
from .models import Actor, ApprovalRequirement
from .signing import Signature, Signer, TrustDirectory


class ApprovalError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    request_id: str
    tenant_id: str
    assertion_id: str
    decision_record_id: str
    decision_record_hash: str
    requirement: ApprovalRequirement
    requirement_digest: str
    requester_id: str
    expires_at_us: int


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    request_id: str
    reviewer_id: str
    satisfied_groups: tuple[int, ...]
    granted_at_us: int
    signature: Signature
    credential_receipt_digest: str = ""   # binds to the provider-verified credential receipt (if any)

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/approval-grant/v1", "request_id": self.request_id,
                "reviewer_id": self.reviewer_id, "satisfied_groups": list(self.satisfied_groups),
                "granted_at_us": self.granted_at_us, "credential_receipt_digest": self.credential_receipt_digest}


@dataclass(frozen=True, slots=True)
class ApprovalCertificate:
    request_id: str
    tenant_id: str
    assertion_id: str
    decision_record_id: str
    decision_record_hash: str
    requirement_digest: str
    approver_ids: tuple[str, ...]
    finalized_at_us: int
    signature: Signature
    credential_receipt_digests: tuple[str, ...] = ()   # the provider-verified receipts this cert binds

    def signed_body(self) -> dict[str, Any]:
        return {"schema": "regulated/approval-cert/v1", "request_id": self.request_id,
                "tenant_id": self.tenant_id, "assertion_id": self.assertion_id,
                "decision_record_id": self.decision_record_id, "decision_record_hash": self.decision_record_hash,
                "requirement_digest": self.requirement_digest, "approver_ids": list(self.approver_ids),
                "finalized_at_us": self.finalized_at_us,
                "credential_receipt_digests": list(self.credential_receipt_digests)}


@dataclass(frozen=True, slots=True)
class ApprovedDecision:
    """An approval plus the evidence-authority record the reviewer approved.

    A later release re-evaluates at its current clock and verifies that its
    complete decision still matches this signed record. Keeping the old record
    does not freeze preflight, policy evaluation or the approval window.
    """

    certificate: ApprovalCertificate
    envelope: SignedDecisionEnvelope
    credential_receipts: tuple[CredentialReceipt, ...] = ()


def _match_groups(groups_by_reviewer: dict[str, set[int]], n_groups: int) -> bool:
    """Is there an assignment of DISTINCT reviewers, one per group, each satisfying its group?
    Small bipartite matching (groups -> reviewers)."""
    match: dict[int, str] = {}

    def augment(group: int, seen: set[str]) -> bool:
        for reviewer, groups in groups_by_reviewer.items():
            if group in groups and reviewer not in seen:
                seen.add(reviewer)
                taken = next((g for g, r in match.items() if r == reviewer), None)
                if taken is None or augment(taken, seen):
                    match[group] = reviewer
                    return True
        return False

    return all(augment(g, set()) for g in range(n_groups))


#: Separates a role from the credential kind that qualifies it, as in `clinician@professional-register`.
QUALIFIER = "@"


class ApprovalWorkflow:
    def __init__(self, trust: TrustDirectory, approval_signer: Signer, identity: IdentityVerifier,
                 *, credential_authority: str | None = None,
                 credential_authorities: Mapping[str, str] | None = None,
                 credential_provider_families: Mapping[str, str] | None = None) -> None:
        self._trust = trust
        self._signer = approval_signer
        self._identity = identity
        # If set, a grant may/should present a provider-verified CredentialReceipt signed by this
        # credential-verification authority (key_id), instead of relying on self-declared roles.
        self._credential_authority = credential_authority
        mapped = credential_authorities is not None or credential_provider_families is not None
        if mapped:
            if credential_authority is not None:
                raise ValueError("choose one credential authority configuration")
            maps = []
            for config in (credential_authorities, credential_provider_families):
                if config is not None and (not isinstance(config, Mapping) or not config):
                    raise ValueError("credential providers require explicit key bindings")
                copied = dict(config) if config is not None else {}
                if any(not isinstance(provider, str) or not provider.strip() or provider == "*"
                       or not isinstance(key, str) or not key.strip() for provider, key in copied.items()):
                    raise ValueError("credential providers require explicit key bindings")
                maps.append(copied)
            exact, families = maps
            if any(re.fullmatch(r"[a-z][a-z0-9-]*", name) is None for name in families):
                raise ValueError("credential provider families require explicit family names")
            domains = (*exact.values(), *families.values(), approval_signer.key_id, identity._identity)
            if not trust.distinct_keys(domains):
                raise ValueError("credential authority domains require distinct trusted keys")
            self._credential_authorities: Mapping[str, str] | None = MappingProxyType(exact)
            self._credential_provider_families: Mapping[str, str] = MappingProxyType(families)
        else:
            self._credential_authorities = None
            self._credential_provider_families = MappingProxyType({})

    @property
    def requires_credentials(self) -> bool:
        """Whether every approval needs a verified provider receipt."""
        return self._credential_authorities is not None or self._credential_authority is not None

    @property
    def credential_authority_ids(self) -> tuple[str, ...]:
        """All configured credential keys for host authority-domain checks."""
        if self._credential_authorities is not None:
            return (*self._credential_authorities.values(), *self._credential_provider_families.values())
        return (self._credential_authority,) if self._credential_authority is not None else ()

    def verify_credential_signature(self, receipt: object) -> bool:
        """Authenticate the provider's exact configured key before using its claims."""
        if not isinstance(receipt, CredentialReceipt):
            return False
        expected = (
            self._credential_authorities.get(receipt.provider)
            if self._credential_authorities is not None else self._credential_authority
        )
        if expected is None and self._credential_provider_families and isinstance(receipt.provider, str):
            # The signed provider still binds both context digests. The domain's
            # live credential verifier must additionally revalidate their values.
            match = re.fullmatch(r"([a-z][a-z0-9-]*):[0-9a-f]{64}:[0-9a-f]{64}", receipt.provider)
            if match is not None:
                expected = self._credential_provider_families.get(match[1])
        if self._credential_authorities is not None and not self._trust.distinct_keys((
            *self.credential_authority_ids, self._signer.key_id, self._identity._identity,
        )):
            return False
        return (
            expected is not None and receipt.signature.key_id == expected
            and self._trust.verify(receipt.signed_body(), receipt.signature)
        )


    def _receipt_ok(self, receipt: object, reviewer: Actor, req: "ApprovalRequest", now_us: int) -> bool:
        return (
            self.verify_credential_signature(receipt)
            and receipt.subject_id == reviewer.actor_id                                # type: ignore[attr-defined]
            and receipt.tenant == req.tenant_id                                        # type: ignore[attr-defined]
            and receipt.status == "active"                                             # type: ignore[attr-defined]
            and receipt.verified_at_us <= now_us < receipt.expires_at_us                                         # type: ignore[attr-defined]
        )

    def open(self, *, request_id: str, requester_id: str, tenant_id: str, assertion_id: str,
             decision_record_id: str, decision_record_hash: str, requirement: ApprovalRequirement,
             now_us: int) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=request_id, tenant_id=tenant_id, assertion_id=assertion_id,
            decision_record_id=decision_record_id, decision_record_hash=decision_record_hash,
            requirement=requirement, requirement_digest=requirement.digest(),
            requester_id=requester_id, expires_at_us=now_us + requirement.expires_after_us,
        )

    def grant(self, req: ApprovalRequest, reviewer: Actor, now_us: int, *, receipt: object | None = None) -> ApprovalGrant:
        if now_us >= req.expires_at_us:
            raise ApprovalError("approval window expired")
        if reviewer.producer:
            raise ApprovalError("a probabilistic producer cannot approve")
        if reviewer.actor_id == req.requester_id and not req.requirement.requester_may_approve:
            raise ApprovalError("requester may not approve their own action")
        # Provider-backed path: roles come from a signed, provider-verified credential receipt, not
        # self-declared. Fail closed on an unsigned / mis-bound / expired / suspended receipt.
        rdigest = ""
        if receipt is not None:
            if not self._receipt_ok(receipt, reviewer, req, now_us):
                raise ApprovalError("credential receipt invalid, unsigned, or not bound to this approver/tenant")
            # A qualification is derived only here, from the verified kind: a receipt whose role or kind already
            # carries the separator could masquerade as a pre-qualified role, so it is refused (source review 3048).
            if (not receipt.role or QUALIFIER in receipt.role                         # type: ignore[attr-defined]
                    or not receipt.licence_type or QUALIFIER in receipt.licence_type):  # type: ignore[attr-defined]
                raise ApprovalError("credential receipt role or kind is malformed")
            # The receipt's role, and that role qualified by the credential kind the provider verified. A signed
            # policy may require a qualified role (for example clinician@professional-register); only a receipt of
            # exactly that kind meets it, and self-declared roles below never do (credential assurance profiles,
            # docs/ARCHITECTURE-OF-RECORD/10).
            roles = {receipt.role,                                                     # type: ignore[attr-defined]
                     f"{receipt.role}@{receipt.licence_type}"}                         # type: ignore[attr-defined]
            rdigest = receipt.digest()                                                 # type: ignore[attr-defined]
        elif self.requires_credentials:
            raise ApprovalError("provider-backed approval requires a credential receipt")
        else:
            # dev/local path: self-declared roles never carry a credential qualification (source review 3048).
            roles = {role for role in self._identity.verified_roles(reviewer, now_us) if QUALIFIER not in role}
        satisfied = tuple(i for i, g in enumerate(req.requirement.role_groups) if roles & g)
        if not satisfied:
            raise ApprovalError(f"reviewer {reviewer.actor_id} satisfies no required role group")
        body = {"schema": "regulated/approval-grant/v1", "request_id": req.request_id,
                "reviewer_id": reviewer.actor_id, "satisfied_groups": list(satisfied),
                "granted_at_us": now_us, "credential_receipt_digest": rdigest}
        return ApprovalGrant(req.request_id, reviewer.actor_id, satisfied, now_us, self._signer.sign(body), rdigest)

    def finalize(self, req: ApprovalRequest, grants: list[ApprovalGrant], now_us: int) -> ApprovalCertificate:
        if now_us >= req.expires_at_us:
            raise ApprovalError("approval window expired before quorum")
        valid = [g for g in grants if g.request_id == req.request_id and g.signature.key_id == self._signer.key_id
                 and self._trust.verify(g.signed_body(), g.signature)]
        by_reviewer: dict[str, set[int]] = {}
        for g in valid:
            by_reviewer.setdefault(g.reviewer_id, set()).update(g.satisfied_groups)
        approvers = sorted(by_reviewer)
        if len(approvers) < req.requirement.minimum_approvers:
            raise ApprovalError(f"quorum not met: {len(approvers)}/{req.requirement.minimum_approvers}")
        if not _match_groups(by_reviewer, len(req.requirement.role_groups)):
            raise ApprovalError("role groups not covered by distinct approvers (dual control)")
        # A provider-backed request must have a credential receipt from every valid grant.
        receipts = tuple(sorted(g.credential_receipt_digest for g in valid if g.credential_receipt_digest))
        if self.requires_credentials and len(receipts) < len(approvers):
            raise ApprovalError("provider-backed approval requires a credential receipt per approver")
        body = {"schema": "regulated/approval-cert/v1", "request_id": req.request_id, "tenant_id": req.tenant_id,
                "assertion_id": req.assertion_id, "decision_record_id": req.decision_record_id,
                "decision_record_hash": req.decision_record_hash, "requirement_digest": req.requirement_digest,
                "approver_ids": approvers, "finalized_at_us": now_us, "credential_receipt_digests": list(receipts)}
        return ApprovalCertificate(req.request_id, req.tenant_id, req.assertion_id, req.decision_record_id,
                                   req.decision_record_hash, req.requirement_digest, tuple(approvers), now_us,
                                   self._signer.sign(body), receipts)

    def verify_certificate(self, cert: ApprovalCertificate) -> bool:
        return (isinstance(cert, ApprovalCertificate) and cert.signature.key_id == self._signer.key_id
                and self._trust.verify(cert.signed_body(), cert.signature))
