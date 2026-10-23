"""Intact frozen source adapter over real reviewed roots and signed child grants.

Synthetic local identities and PostgreSQL only. This adapter contract does not
establish full delegation-review facade equivalence or close A08.
"""
from dataclasses import asdict

import pytest

from regulated_core.delegation import DelegationAuthority, DelegationError
from regulated_core.delegation_source import VerifiedReleaseAuthority
from regulated_core.persistence_pg import PostgresGrantStore
from test_root_admission import TENANTS, reviewed_root_fixture


def test_recovered_source_binds_reviewed_root_executor_and_expiry(tmp_path):
    fixture = reviewed_root_fixture(tmp_path)
    tenant = TENANTS[0]
    pool, clock, *_ = fixture["assemble"](tenant)
    root = fixture["roots"][tenant]
    authority = DelegationAuthority(
        fixture["signers"]["delegation"], fixture["trust"], PostgresGrantStore(pool=pool),
    )
    child = authority.issue_child(
        tenant, root.digest, actor=root.grant.subject,
        subject="executor:source-adapter-contract", operations=("course:save-draft",),
        targets=root.grant.targets, expires_at_us=fixture["expires"] - 1_000_000,
        delegable=False, clock=clock.now_us,
    )
    port = VerifiedReleaseAuthority.over(authority, clock.now_us)
    request = {
        "tenant_id": tenant, "grant_digest": child.digest, "root_digest": root.digest,
        "subject": child.grant.subject, "root_subject": root.grant.subject,
    }
    binding = port.resolve(**request)
    chain = authority.resolve(tenant, child.digest, now_us=clock.now_us())
    assert asdict(binding) == {
        "grant_digest": child.digest, "chain_digest": chain.digest,
        "root_digest": root.digest, "mission": root.grant.root_mission,
    }
    assert child.grant.budget_limit == root.grant.budget_limit == 1

    # Ordinary incorrect host expectations must refuse even for a valid signed chain.
    cases = (
        ({"root_digest": fixture["roots"][TENANTS[1]].digest},
         "the chain does not descend from the root the host admitted"),
        ({"root_subject": "different-accountable-owner"},
         "the root's subject is not the goal's accountable principal"),
        ({"subject": "executor:different-host-instance"},
         "the grant's subject is not the executor the host derived"),
    )
    for changes, reason in cases:
        with pytest.raises(DelegationError) as refusal:
            port.resolve(**(request | changes))
        assert str(refusal.value) == reason
    assert port.resolve(**request) == binding

    # An ordinary fixture clock at the exact expiry exercises the intact adapter.
    expired = VerifiedReleaseAuthority.over(authority, lambda: child.grant.expires_at_us)
    with pytest.raises(DelegationError, match="the delegated authority has expired"):
        expired.resolve(**request)
