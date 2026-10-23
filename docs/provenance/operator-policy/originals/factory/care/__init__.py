"""Customer care: the Customer Resolution Plane (design: docs/customer-care/02, 04, 05).

One durable, owned Resolution Case per customer request, bound server-side to the authenticated
workspace and to the safe references of whatever refused the customer; an append-only, hash-chained
event ledger; targets computed from a declared routing policy; remedies that are references to
governed operations elsewhere, never authority here. This package imports only value contracts
and read-only protocols from the rest of the platform (the import-boundary test refuses more).
"""
from factory.care.contracts import (
    Case,
    CaseEvent,
    CaseReference,
    CaseState,
    CareConflict,
    CareContractError,
    CareRefused,
    CareUnavailable,
    EventKind,
    EventVisibility,
    Impact,
    IssueClass,
    OwnerClass,
    ReferenceKind,
    RemedyLink,
    RoutingPolicy,
    Urgency,
    canonical_digest,
)
from factory.care.store import CaseStore, InMemoryCaseStore

__all__ = [
    "Case", "CaseEvent", "CaseReference", "CaseState", "CaseStore", "CareConflict", "CareContractError",
    "CareRefused", "CareUnavailable", "EventKind", "EventVisibility", "Impact", "InMemoryCaseStore",
    "IssueClass", "OwnerClass", "ReferenceKind", "RemedyLink", "RoutingPolicy", "Urgency", "canonical_digest",
]
