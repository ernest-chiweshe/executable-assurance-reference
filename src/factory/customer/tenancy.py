"""THE canonical customer tenant identity - one function, one formula.

The commercial boundary of the whole customer product is the subscription
workspace (`subscription_workspace_id`); every internal system - the
credential vault's AAD, the tenant-keyed Postgres tables, per-workspace state
roots, the run ledger - scopes by the OPAQUE id derived here. Four modules
had each copy-pasted the same formula (the pre-billing audit finding,
2026-09-01: correct isolation could still attribute usage to the wrong
commercial account if one copy ever drifted); they now all call this.

STABILITY CONTRACT: the mapping is `customer-<sha256(workspace_id) hex>`,
and it may NEVER change. Vault rows, Postgres primary keys and filesystem
roots already exist under these exact strings - a different derivation would
orphan every customer's data while looking like a clean refactor.
tests/test_customer_tenancy.py pins the exact vector and that no other
module re-derives the prefix.
"""
from __future__ import annotations

import hashlib

#: The visible marker of a customer-scoped tenant id. The operator is always
#: the bare installation tenant ("self"); nothing customer-facing may ever
#: run under it (the war-room architectural lesson, 2026-09-01).
CUSTOMER_TENANT_PREFIX = "customer-"


def workspace_digest(subscription_workspace_id: str) -> str:
    """The opaque, filesystem-safe digest of one subscription workspace."""
    return hashlib.sha256(subscription_workspace_id.encode("utf-8")).hexdigest()


def customer_tenant_id(subscription_workspace_id: str) -> str:
    """The canonical internal tenant id for one subscription workspace."""
    return f"{CUSTOMER_TENANT_PREFIX}{workspace_digest(subscription_workspace_id)}"
