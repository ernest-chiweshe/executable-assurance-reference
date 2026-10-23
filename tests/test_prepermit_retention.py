"""Preventive issuance ordering with synthetic local authorities and retention."""

import hashlib

import pytest

from assurance_reference.local_retention import LocalRetentionStore
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, CoursePolicy,
    Ed25519Signer, EmissionAuthority, IdentityVerifier, IntendedUse,
    IntendedUseRegistry, PolicyContext, PolicyRegistry, PreflightAuthority,
    TrustDirectory, VerificationTrustStore,
)
from regulated_core.clock import ClockReading
from regulated_core.engine import RegulatedEngine, RetentionRequired
from regulated_core.evidence import DecisionRecorder
from regulated_core.permit import InMemoryPermitUseStore
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, effect_destination
from regulated_core.worm import WormUnavailable, anchor_evidence_chain
from test_education_record_outage import CountingSigner


class FixtureClock:
    domain = "fixture:retention-order"

    def read(self):
        return ClockReading(self.domain, 100)

    def now_us(self):
        return 100


class BudgetedCoursePolicy(CoursePolicy):
    def mission_budget(self, action_id):
        return {"limit": 1, "units": 1}


@pytest.mark.parametrize("failure", [None, "anchor", "verification", "missing", "noncallable"])
def test_record_and_verified_retention_precede_permit_signing(tmp_path, failure):
    clock, trust = FixtureClock(), TrustDirectory()
    keys = {role: Ed25519Signer("fixture:" + role) for role in
            ("evidence", "approval", "identity", "preflight")}
    emission = CountingSigner("fixture:emission")
    for key in (*keys.values(), emission):
        trust.register_signer(key)
    recorder = DecisionRecorder(keys["evidence"], trust, clock=clock)
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(BudgetedCoursePolicy())
    operation, tenant = "course:render-lesson", "synthetic-retention"
    intended.declare(IntendedUse("course", operation, 1))
    preflight = PreflightAuthority(keys["preflight"], intended, trust)
    uses = InMemoryPermitUseStore()
    engine = RegulatedEngine(registry=registry, recorder=recorder,
        verification_trust=VerificationTrustStore(trust),
        approvals=ApprovalWorkflow(trust, keys["approval"], IdentityVerifier(trust, keys["identity"].key_id)),
        emission=EmissionAuthority(emission, trust, uses), preflight=preflight, clock=clock)
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
    store = LocalRetentionStore(tmp_path / "retention")
    observations = []

    def retain():
        assert emission.calls == 0
        assert recorder.entries(tenant) and recorder.verify_chain(tenant)
        observations.append("record-present-before-retention")
        if failure == "anchor":
            raise WormUnavailable("synthetic anchor unavailable")
        receipt = anchor_evidence_chain(store, recorder, tenant, retain_us=1000, now_us=100)
        assert emission.calls == 0
        if failure == "verification":
            raise WormUnavailable("synthetic retention verification unavailable")
        assert store.verify(receipt)
        observations.append("retention-verified-before-signing")

    if failure is not None:
        if failure in ("missing", "noncallable"):
            supplied = {} if failure == "missing" else {"retain_before_permit": False}
            with pytest.raises(RetentionRequired, match="verified retention is required"):
                engine.authorize_for_target(**parameters, nonce="first", **supplied)
            assert observations == []
        else:
            with pytest.raises(WormUnavailable, match="synthetic"):
                engine.authorize_for_target(**parameters, nonce="first", retain_before_permit=retain)
        assert emission.calls == 0 and not target.path.exists()
        assert not uses.used(tenant, "first")
        # A distinct ordinary request can reserve the sole unit after cleanup.
        failure = None
    authorized = engine.authorize_for_target(**parameters, nonce="healthy", retain_before_permit=retain)
    assert authorized.authorized and authorized.permit is not None, authorized.reason
    assert observations[-1] == "retention-verified-before-signing"
    assert emission.calls == 1
    assert not target.path.exists()
