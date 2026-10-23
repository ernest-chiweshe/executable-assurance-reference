"""Pure verification of retained human approvals and credential receipts."""
from __future__ import annotations

import json
from typing import Any

from .approval import ApprovalCertificate, ApprovalGrant, ApprovalRequest
from .canonical import canonical_bytes
from .identity_provider import CredentialReceipt
from .reviewer_sessions import decode_session_credential
from .signing import Signature


class ReviewError(ValueError):
    """Review state is missing, changed, expired, unauthorized or invalid."""


def _data(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _grant(raw: Any) -> ApprovalGrant:
    value = dict(raw)
    value["signature"] = Signature(**value["signature"])
    value["satisfied_groups"] = tuple(value["satisfied_groups"])
    result = ApprovalGrant(**value)
    if _data(result) != raw:
        raise ReviewError("invalid stored grant representation")
    return result


def _certificate(raw: Any) -> ApprovalCertificate | None:
    if raw is None:
        return None
    value = dict(raw)
    value["signature"] = Signature(**value["signature"])
    value["approver_ids"] = tuple(value["approver_ids"])
    value["credential_receipt_digests"] = tuple(value["credential_receipt_digests"])
    result = ApprovalCertificate(**value)
    if _data(result) != raw:
        raise ReviewError("invalid stored certificate representation")
    return result


def _credential(raw: Any) -> CredentialReceipt:
    if isinstance(raw, dict) and "reviewer_session" in raw:
        return decode_session_credential(raw)
    value = dict(raw)
    value["signature"] = Signature(**value["signature"])
    result = CredentialReceipt(**value)
    if _data(result) != raw:
        raise ReviewError("invalid stored credential representation")
    return result


def verified_approvals(authority: Any, state: dict[str, Any], envelope: Any, request: ApprovalRequest, *,
                       now_us: int) -> tuple[tuple[ApprovalGrant, ...], ApprovalCertificate | None]:
    """The stored grants and certificate of one review, each verified against the signed decision it approves.

    Shared by every stored human review (the release review below and the delegation-root review in
    regulated_core/delegation_review.py), so both judge grants, their bound credential receipts and the certificate
    by exactly the same rules. Raises `ReviewError` on anything that does not verify; `KeyError`/`TypeError` from
    malformed data propagate to the caller, which reports them as invalid stored data."""
    record, requirement, review_id = envelope.record, request.requirement, request.request_id
    grants = tuple(_grant(g) for g in state["grants"])
    if len({g.reviewer_id for g in grants}) != len(grants):
        raise ReviewError("duplicate stored reviewer")
    receipts = tuple(_credential(raw) for raw in state["credential_receipts"])
    by_digest = {receipt.digest(): receipt for receipt in receipts}
    if len(receipts) != len(grants) or len(by_digest) != len(receipts):
        raise ReviewError("stored grants require distinct retained credential receipts")
    for grant in grants:
        if (grant.request_id != review_id or grant.signature.key_id != authority._signer.key_id
                or not authority._trust.verify(grant.signed_body(), grant.signature)
                or not record.decided_at_us <= grant.granted_at_us <= now_us
                or grant.granted_at_us >= request.expires_at_us
                or (authority.requires_credentials and not grant.credential_receipt_digest)):
            raise ReviewError("invalid stored review grant")
        receipt = by_digest.get(grant.credential_receipt_digest)
        if (receipt is None or not authority.verify_credential_signature(receipt)
                or receipt.subject_id != grant.reviewer_id or receipt.tenant != record.tenant_id
                or not receipt.role or "@" in receipt.role
                or not receipt.licence_type or "@" in receipt.licence_type
                or receipt.status != "active" or not receipt.verified_at_us <= grant.granted_at_us < receipt.expires_at_us
                or grant.satisfied_groups != tuple(i for i, group in enumerate(requirement.role_groups) if {receipt.role, f"{receipt.role}@{receipt.licence_type}"} & group)):
            raise ReviewError("stored grant lacks its bound authoritative credential receipt")
    certificate = _certificate(state["certificate"])
    if certificate is not None:
        if (not authority.verify_certificate(certificate)
                or certificate.request_id != review_id or certificate.tenant_id != record.tenant_id
                or certificate.assertion_id != record.assertion_id
                or certificate.decision_record_id != record.record_id
                or certificate.decision_record_hash != envelope.record_hash
                or certificate.requirement_digest != requirement.digest()
                or set(certificate.approver_ids) != {g.reviewer_id for g in grants}
                or certificate.credential_receipt_digests != tuple(sorted(by_digest))
                or not record.decided_at_us <= certificate.finalized_at_us <= now_us):
            raise ReviewError("invalid stored review certificate")
    return grants, certificate
