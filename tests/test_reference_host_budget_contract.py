"""Intact local contracts for mandatory reference budgets and explicit host defaults.

These use synthetic authorities and an in-memory ledger, not PostgreSQL application evidence.
"""
import hashlib

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, CoursePolicy, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry, PolicyContext,
    PolicyRegistry, PreflightAuthority, TrustDirectory, VerificationTrustStore,
)
from regulated_core.budget import InMemoryMissionBudget
from regulated_core.evidence import DecisionRecorder
from regulated_core.engine import RegulatedEngine
from regulated_core.worm import anchor_evidence_chain
from regulated_core.permit import InMemoryPermitUseStore
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination
from test_education_record_outage import CountingSigner
from test_prepermit_retention import BudgetedCoursePolicy, FixtureClock
from test_reference_retention_contract import UnusedAlertPool


def composition(tmp_path, default, *, declared=False, sibling=False, engine_type="reference"):
    clock, trust, events = FixtureClock(), TrustDirectory(), []
    keys = {role: Ed25519Signer("synthetic-budget:" + role) for role in
            ("evidence", "approval", "identity", "preflight", "alert")}

    class Signer(CountingSigner):
        def sign(self, body):
            assert "reserved" in events
            events.append("signed")
            return super().sign(body)

        def sign_bytes(self, body):
            assert "reserved" in events
            events.append("signed")
            return super().sign_bytes(body)

    emission = Signer("synthetic-budget:emission")

    class Budget(InMemoryMissionBudget):
        def reserve(self, *args, **kwargs):
            reservation = super().reserve(*args, **kwargs)
            events.append("reserved")
            return reservation

        def consume(self, *args, **kwargs):
            assert "signed" in events
            super().consume(*args, **kwargs)
            events.append("consumed")

    budget = Budget()
    for key in (*keys.values(), emission):
        trust.register_signer(key)
    recorder = DecisionRecorder(keys["evidence"], trust, clock=clock)
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    policy = BudgetedCoursePolicy() if declared else CoursePolicy()
    registry.register(policy)
    operation, tenant = "course:render-lesson", "synthetic-host-budget"
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(keys["preflight"], intended, trust)
    uses = InMemoryPermitUseStore()
    retention = LocalRetentionStore(tmp_path / "retention")
    engine_class = ReferenceEngine if engine_type == "reference" else RegulatedEngine
    extras = (dict(retention=retention, retention_us=1000,
                   alerts=AlertJournal(UnusedAlertPool(), keys["alert"], trust))
              if engine_type == "reference" else {})
    engine = engine_class(default_mission_budget=default, budget=budget, **extras,
        registry=registry, recorder=recorder, verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, keys["approval"], IdentityVerifier(trust, keys["identity"].key_id)),
        emission=EmissionAuthority(emission, trust, uses), preflight=preflight, clock=clock)
    if sibling:
        child_registry = PolicyRegistry()
        child_registry.register(policy)
        engine = engine.for_policy(registry=child_registry, preflight=preflight.for_uses(intended))
    target = FilesystemTargetAdapter(path=tmp_path / "draft.txt", tenant_id=tenant,
        authority=engine.targets, uses=uses, operation_name=operation, budget=budget)
    body = b"Synthetic reversible draft with a bounded mission."
    digest = hashlib.sha256(body).hexdigest()
    capability = preflight.authorize(tenant_id=tenant, vertical="course", action_id=operation,
        risk_tier=1, correlation_id="draft", now_us=100, ttl_us=1000, nonce="cap")
    parameters = dict(vertical="course", capability=capability,
        assertion=Assertion("draft", tenant, "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination({},
            BoundEffect(digest, target.target, target.current_state(), mission="synthetic:mission"))),
        ctx=PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft", "draft", 100),
        output=body, target=target, permit_ttl_us=1000)
    if engine_type == "core":
        def retain():
            receipt = anchor_evidence_chain(retention, recorder, tenant, retain_us=1000, now_us=100)
            assert retention.verify(receipt)
        parameters["retain_before_permit"] = retain
    return engine, parameters, emission, budget, events, uses


@pytest.mark.parametrize("sibling", [False, True])
@pytest.mark.parametrize("engine_type", ["core", "reference"])
def test_missing_terms_refuse_without_signing_or_output(tmp_path, sibling, engine_type):
    engine, request, signer, budget, events, uses = composition(
        tmp_path, None, sibling=sibling, engine_type=engine_type)
    refused = engine.authorize_for_target(**request, nonce="missing")
    assert not refused.authorized and refused.permit is None
    assert refused.envelope.record.decision.reason_codes == ("BUDGET_UNCONFIGURED",)
    assert signer.calls == 0 and events == [] and not request["target"].path.exists()
    assert not uses.used(request["ctx"].tenant_id, "missing")
    assert budget.committed(request["ctx"].tenant_id, "synthetic:mission") == 0
    assert engine._recorder.verify_chain(request["ctx"].tenant_id)


@pytest.mark.parametrize("sibling", [False, True])
@pytest.mark.parametrize("declared", [False, True])
@pytest.mark.parametrize("engine_type", ["core", "reference"])
def test_resolve_reserve_sign_commit_and_exhaust(tmp_path, sibling, declared, engine_type):
    # A stricter host fallback must not replace an explicit signed-policy declaration.
    default = {"limit": 0 if declared else 1, "units": 1}
    engine, request, signer, budget, events, uses = composition(
        tmp_path, default, declared=declared, sibling=sibling, engine_type=engine_type)
    default["limit"] = 99  # Construction snapshots configuration; later mutation cannot enlarge it.
    first = engine.authorize_for_target(**request, nonce="first")
    assert first.authorized and first.permit is not None, first.reason
    assert first.permit.permit.budget_reservation == "first"
    assert first.permit.permit.budget_units == 1
    assert events == ["reserved", "signed"]
    assert not request["target"].path.exists()
    second = engine.authorize_for_target(**request, nonce="second")
    assert not second.authorized and second.permit is None
    assert second.envelope.record.decision.reason_codes == ("BUDGET_EXCEEDED",)
    assert signer.calls == 1 and not uses.used(request["ctx"].tenant_id, "second")
    outcome = engine.commit(first, request["output"], request["target"])
    assert outcome.outcome is Outcome.COMMITTED
    assert request["target"].path.read_bytes() == request["output"]
    assert events == ["reserved", "signed", "consumed"]
    assert budget.committed(request["ctx"].tenant_id, "synthetic:mission") == 1
    # A new ordinary effect binds the target state after the first commit.
    refreshed = {**request, "action": Action(request["action"].action_id, ActionEffect.REVERSIBLE,
        destination=effect_destination({}, BoundEffect(
            hashlib.sha256(request["output"]).hexdigest(), request["target"].target,
            request["target"].current_state(), mission="synthetic:mission")))}
    third = engine.authorize_for_target(**refreshed, nonce="third")
    assert not third.authorized and third.permit is None
    assert third.envelope.record.decision.reason_codes == ("BUDGET_EXCEEDED",)
    assert signer.calls == 1 and engine._recorder.verify_chain(request["ctx"].tenant_id)


@pytest.mark.parametrize("default", [
    {}, {"limit": True, "units": 1}, {"limit": 1, "units": False},
    {"limit": -1, "units": 1}, {"limit": 1, "units": 0},
    {"limit": 1.0, "units": 1}, {"limit": 1, "units": 1, "extra": 1},
])
def test_host_terms_require_exact_integer_configuration(tmp_path, default):
    with pytest.raises(ValueError, match="host budget"):
        composition(tmp_path, default)
