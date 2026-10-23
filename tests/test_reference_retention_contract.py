"""Direct reference retention contracts with synthetic authorities, intact guards."""

import hashlib

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer,
    EmissionAuthority, IdentityVerifier, IntendedUse, IntendedUseRegistry,
    PolicyContext, PolicyRegistry, PreflightAuthority, TrustDirectory, VerificationTrustStore,
)
from regulated_core.evidence import DecisionRecorder
from regulated_core.permit import InMemoryPermitUseStore
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, effect_destination
from regulated_core.worm import WormUnavailable
from test_education_record_outage import CountingSigner
from test_prepermit_retention import BudgetedCoursePolicy, FixtureClock


class UnusedAlertPool:
    def connection(self):
        raise AssertionError("This synthetic authorization contract does not exercise alert storage")


@pytest.mark.parametrize("failure", [None, "anchor", "verification", "verification-outage"])
@pytest.mark.parametrize("policy_sibling", [False, True])
def test_direct_reference_requires_verified_retention_before_signing(tmp_path, failure, policy_sibling):
    clock, trust = FixtureClock(), TrustDirectory()
    keys = {role: Ed25519Signer("fixture:" + role) for role in
            ("evidence", "approval", "identity", "preflight", "alert")}
    emission = CountingSigner("fixture:emission")
    for key in (*keys.values(), emission):
        trust.register_signer(key)
    recorder = DecisionRecorder(keys["evidence"], trust, clock=clock)
    tenant, operation = "synthetic-direct-retention", "course:render-lesson"
    events = []

    class ObservedRetention:
        delegate = LocalRetentionStore(tmp_path / "retention")

        def anchor(self, tenant_id, data, **kwargs):
            assert emission.calls == 0
            assert recorder.entries(tenant_id) and recorder.verify_chain(tenant_id)
            events.append("record-present-at-anchor")
            if failure == "anchor":
                raise WormUnavailable("synthetic retention unavailable")
            return self.delegate.anchor(tenant_id, data, **kwargs)

        def verify(self, receipt):
            assert emission.calls == 0
            events.append("verify-before-signing")
            if failure == "verification-outage":
                raise WormUnavailable("synthetic verification unavailable")
            if failure == "verification":
                return False
            return self.delegate.verify(receipt)

    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(BudgetedCoursePolicy())
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(keys["preflight"], intended, trust)
    uses = InMemoryPermitUseStore()
    engine = ReferenceEngine(retention=ObservedRetention(), retention_us=1000,
        alerts=AlertJournal(UnusedAlertPool(), keys["alert"], trust),
        registry=registry, recorder=recorder, verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, keys["approval"], IdentityVerifier(trust, keys["identity"].key_id)),
        emission=EmissionAuthority(emission, trust, uses), preflight=preflight, clock=clock)
    if policy_sibling:
        sibling_registry, sibling_uses = PolicyRegistry(), IntendedUseRegistry()
        sibling_registry.register(BudgetedCoursePolicy())
        sibling_uses.declare(IntendedUse("course", operation, 1))
        engine = engine.for_policy(registry=sibling_registry, preflight=preflight.for_uses(sibling_uses))
    target = FilesystemTargetAdapter(path=tmp_path / "draft.txt", tenant_id=tenant,
        authority=engine.targets, uses=uses, operation_name=operation)
    body = b"Synthetic reversible draft."
    digest = hashlib.sha256(body).hexdigest()
    capability = preflight.authorize(tenant_id=tenant, vertical="course", action_id=operation,
        risk_tier=1, correlation_id="draft", now_us=100, ttl_us=1000, nonce="cap")
    parameters = dict(vertical="course", capability=capability,
        assertion=Assertion("draft", tenant, "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination({},
            BoundEffect(digest, target.target, target.current_state(), mission="fixture:mission"))),
        ctx=PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft", "draft", 100),
        output=body, target=target, permit_ttl_us=1000)
    # No callback is supplied here: exercise ReferenceEngine's actual configured callback.
    if failure is not None:
        with pytest.raises(WormUnavailable):
            engine.authorize_for_target(**parameters, nonce="unavailable")
        assert emission.calls == 0 and not target.path.exists()
        assert not uses.used(tenant, "unavailable")
        assert events[0] == "record-present-at-anchor"
        if failure != "anchor":
            assert events[-1] == "verify-before-signing"
        failure = None
    # A fresh normal request can reserve the sole budget unit after the failed dependency.
    authorized = engine.authorize_for_target(**parameters, nonce="healthy")
    assert authorized.authorized and authorized.permit is not None, authorized.reason
    assert events[-2:] == ["record-present-at-anchor", "verify-before-signing"]
    assert emission.calls == 1 and not target.path.exists()
    assert recorder.verify_chain(tenant)
