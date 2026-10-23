"""Actual durable service construction without database or clock access."""
from types import SimpleNamespace
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from assurance_reference.roster_tenancy import tenant_roster_store

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.governance_targets import require_governance_composition
from assurance_reference.roster_authority import RosterAuthorityVerifier
from regulated_core.approval import ApprovalWorkflow
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.identity import IdentityVerifier
from regulated_core.persistence_pg import (
    PostgresDecisionRecorder, PostgresGovernanceLog, PostgresMissionBudget,
    PostgresPermitUseStore,
)
from regulated_core.permit import EmissionError
from regulated_core.review_store import PostgresReviewStore
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import TargetAuthority

from assurance_reference.epoch_withdrawal_admission import KIND, OPERATION, withdrawal_bytes
from assurance_reference.epoch_withdrawal_review import EpochWithdrawalReviewLoader
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger
from assurance_reference.epoch_withdrawal_target import epoch_withdrawal_target


class NoConnections:
    def connection(self):
        raise AssertionError("database access is forbidden in this composition contract")


class ConstructionClockSource:
    domain = "synthetic:epoch-target-construction"
    def read(self):
        raise AssertionError("clock access is forbidden")
    def read_on(self, connection):
        raise AssertionError("clock access is forbidden")
    def now_us(self):
        raise AssertionError("clock access is forbidden")


def composition(tenant="tenant", shared=None):
    pool = NoConnections()
    clock = DurableClock(ConstructionClockSource(), floor_pool=pool)
    guard = GovernanceGuard()
    store = GuardedPostgresRevocationLedger(pool=pool, clock=clock, guard=guard)
    trust = TrustDirectory()
    keys = {name: Ed25519Signer("synthetic-epoch-target:" + name)
            for name in ("target", "evidence", "approval", "identity", "roster", "bootstrap")}
    for key in keys.values():
        trust.register_signer(key)
    authority = TargetAuthority(keys["target"], trust, revocation_epoch=store.governance_epoch, clock=clock)
    if shared is not None:
        pool, clock, store, trust, keys, authority = (
            shared.pool, shared.store.clock, shared.store, shared.trust, shared.keys,
            shared.parameters["authority"])
        guard = store.governance_guard
    recorder = PostgresDecisionRecorder(keys["evidence"], trust, pool=pool, clock=clock)
    verifier = RosterAuthorityVerifier(tenant=tenant, installation="installation:" + tenant,
        authority=authority, recorder=recorder, bootstrap_trust=trust,
        bootstrap_key_ids=frozenset({keys["bootstrap"].key_id}))
    roster = tenant_roster_store(pool, guard=guard, proof_verifier=verifier)
    workflow = ApprovalWorkflow(trust, keys["approval"],
        IdentityVerifier(trust, keys["identity"].key_id),
        credential_authorities={"governance-roster:simulated": keys["roster"].key_id})
    loader = EpochWithdrawalReviewLoader(reviews=PostgresReviewStore(pool=pool),
        roster=roster, installation="installation:" + tenant, workflow=workflow, recorder=recorder, clock=clock)
    parameters = dict(tenant_id=tenant, loader=loader, authority=authority,
        uses=PostgresPermitUseStore(pool=pool), log=TenantFencedGovernanceLog(pool=pool, tenant=tenant),
        budget=PostgresMissionBudget(pool=pool))
    return SimpleNamespace(store=store, parameters=parameters, pool=pool, trust=trust, keys=keys)


def test_registered_target_uses_owned_writer_receipt_and_exact_budget_without_io():
    app = composition()
    target = epoch_withdrawal_target(app.store, **app.parameters)
    require_governance_composition(target, app.parameters["budget"])
    assert target._transact == app.store.apply
    assert target._receipt == app.store.receipt
    assert target._guard is app.store.governance_guard
    assert target._bootstrap_keys == frozenset()
    assert target.operation == OPERATION
    assert target.target.identity == KIND + ":tenant"


def test_request_declares_exact_prior_and_advances_once_without_io():
    app = composition()
    target = epoch_withdrawal_target(app.store, **app.parameters)
    request = target._request(withdrawal_bytes("tenant", prior_epoch=7, reason="Withdraw authority"))
    assert target._expect(request["change"], "7") == "8"
    with pytest.raises(EmissionError, match="current tenant epoch"):
        target._expect(request["change"], "8")


def test_target_direct_callback_refuses_without_io():
    app = composition()
    target = epoch_withdrawal_target(app.store, **app.parameters)
    with pytest.raises(EmissionError, match="owned governed transaction"):
        target._apply({"tenant": "tenant", "prior_epoch": 0, "reason": "withdraw"})


def test_other_tenant_configuration_refuses_before_binding_or_io():
    app = composition()
    app.parameters["tenant_id"] = "different-tenant"
    with pytest.raises(TypeError, match="matching tenant"):
        epoch_withdrawal_target(app.store, **app.parameters)
    assert app.store._writers == {}


def test_non_durable_budget_configuration_refuses_before_binding_or_io():
    app = composition()
    app.parameters["budget"] = object()
    with pytest.raises(TypeError, match="durable budget"):
        epoch_withdrawal_target(app.store, **app.parameters)
    assert app.store._writers == {}


def test_shared_ledger_binds_two_tenants_without_replacing_either_authority():
    first = composition()
    second = composition("second-tenant", shared=first)
    first_target = epoch_withdrawal_target(first.store, **first.parameters)
    second_target = epoch_withdrawal_target(second.store, **second.parameters)
    assert first.store is second.store
    assert first.store._services("tenant")[0] is first.parameters["loader"]
    assert first.store._services("second-tenant")[0] is second.parameters["loader"]
    assert first_target.target != second_target.target
    require_governance_composition(first_target, first.parameters["budget"])
    require_governance_composition(second_target, second.parameters["budget"])


def test_tenant_binding_is_idempotent_but_rebinding_different_loader_refuses():
    first = composition()
    epoch_withdrawal_target(first.store, **first.parameters)
    epoch_withdrawal_target(first.store, **first.parameters)
    replacement = composition("tenant", shared=first)
    with pytest.raises(TypeError, match="cannot be rebound"):
        epoch_withdrawal_target(replacement.store, **replacement.parameters)
    assert first.store._services("tenant")[0] is first.parameters["loader"]


def test_unconfigured_tenant_receipt_refuses_after_other_tenant_is_bound():
    from regulated_core.governance_guard import GovernanceRefused
    first = composition()
    epoch_withdrawal_target(first.store, **first.parameters)
    with pytest.raises(GovernanceRefused, match="this tenant"):
        first.store.receipt("unconfigured", OPERATION, "nonce", "digest")


@pytest.mark.parametrize("log", ["shared", "foreign"])
def test_epoch_scope_refuses_a_shared_or_foreign_fence_log_without_io(log):
    """B-F7b: the tenant-scoped epoch-withdrawal scope keeps its fences in the tenant-isolated table."""
    app = composition()
    wrong = (PostgresGovernanceLog(pool=app.pool) if log == "shared"
             else TenantFencedGovernanceLog(pool=app.pool, tenant="synthetic-other-tenant"))
    with pytest.raises(TypeError, match="matching tenant"):
        epoch_withdrawal_target(app.store, **{**app.parameters, "log": wrong})
