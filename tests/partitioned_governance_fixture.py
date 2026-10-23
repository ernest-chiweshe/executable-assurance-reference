"""Synthetic signed tier-4 approvals feeding the real restricted lifecycle.

The reporting directory and clearance retention are explicit in-memory fixture
services. They retain every original approval, signature and cooling-off check;
this is not evidence of deployed human identity or durable clearance custody.
"""
import hashlib
import time

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.durable_governance import DurableGovernedEducationPacks
from assurance_reference.engine import ReferenceEngine
from assurance_reference.recorder import ReferenceDecisionRecorder
from factory.pg_session import SessionBoundPool
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer, EmissionAuthority,
    IdentityVerifier, IntendedUse, IntendedUseRegistry, PolicyContext, PolicyRegistry,
    PreflightAuthority, TrustDirectory, VerificationTrustStore, issue_credential,
)
from regulated_core.clock_pg import DbClock
from regulated_core.approval import ApprovalError
from regulated_core.governance_targets import GOVERNANCE_CONTENT_TYPE, GovernancePolicy, change_bytes
from assurance_reference.governance_targets import pack_activation_target, pack_pin_target, pack_rollback_target
from regulated_core.persistence_pg import PostgresGovernanceLog, PostgresPermitUseStore, PostgresRevocationLedger, PostgresMissionBudget
from regulated_core.target import BoundEffect, effect_destination
from regulated_core.worm import LocalWormStore
from regulated_core.tier4 import InMemoryClearanceStore, Tier4Controls, issue_clearance


class FixtureLines:
    def reporting_line(self, tenant_id, subject_id):
        return {"reviewer-a": "line-a", "reviewer-b": "line-b"}.get(subject_id)


class GovernedFixture:
    def __init__(self, roles, *, directory=None):
        self.roles = roles
        self.clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
        self.trust = TrustDirectory()
        self.keys = {name: Ed25519Signer("fixture:partitioned-governance:" + name)
                     for name in ("evidence", "approval", "identity", "emission", "preflight", "alert", "monitor")}
        for signer in self.keys.values():
            self.trust.register_signer(signer)
        self.recorder = ReferenceDecisionRecorder(self.keys["evidence"], self.trust,
                                                   pool=roles.recorder, clock=self.clock)
        self.uses = PostgresPermitUseStore(pool=roles.receiver)
        self.approvals = ApprovalWorkflow(self.trust, self.keys["approval"],
                                           IdentityVerifier(self.trust, self.keys["identity"].key_id))
        policies = PolicyRegistry()
        policies.register(GovernancePolicy())
        intended = IntendedUseRegistry()
        for operation in ("activate", "pin", "rollback"):
            intended.declare(IntendedUse("governance", "governance:" + operation + "-pack", 4))
        intended.declare(IntendedUse("governance", "governance:change-roster", 4))
        for operation in ("governance:qualify-checker", "governance:recognise-issuer"):
            intended.declare(IntendedUse("governance", operation, 4))
        self.preflight = PreflightAuthority(self.keys["preflight"], intended, self.trust)
        self.clearances = InMemoryClearanceStore()
        self.cooling = 1_000_000
        tier4 = Tier4Controls(directory=directory if directory is not None else FixtureLines(), clearances=self.clearances, trust=self.trust,
            monitor_key_ids=frozenset({self.keys["monitor"].key_id}), cooling_off_us=self.cooling)
        alerts = AlertJournal(roles.alerts, self.keys["alert"], self.trust)
        self.budget = PostgresMissionBudget(pool=roles.allocator)
        # Explicit bounded fixture policy; not a production governance default.
        self.engine = ReferenceEngine(budget=self.budget, default_mission_budget={"limit": 8, "units": 1},alerts=alerts, registry=policies, recorder=self.recorder,
            retention=LocalWormStore(),  # Explicit synthetic retained bytes/receipt; no external custody.
            verification_trust=VerificationTrustStore(self.trust), approvals=self.approvals,
            emission=EmissionAuthority(self.keys["emission"], self.trust, self.uses), preflight=self.preflight,
            clock=self.clock, tier4=tier4, revocation=PostgresRevocationLedger(pool=roles.receiver))
        self.packs = DurableGovernedEducationPacks(pool=SessionBoundPool(roles.governor),
            clock=self.clock, alerts=alerts, partitioned_lifecycle=True)
        self.log = PostgresGovernanceLog(pool=roles.governor)
        self.serial = 0

    def enact(self, tenant, change, *, permit_ttl_us=60_000_000, before_commit=None):
        reference = change.get("activate", change.get("pin", change.get("rollback_to")))
        pack_id = reference.partition("#")[0]
        common = dict(tenant_id=tenant, authority=self.engine.targets, uses=self.uses, log=self.log, budget=self.budget)
        if "activate" in change:
            target = pack_activation_target(self.packs, reference, **common)
        elif "pin" in change:
            target = pack_pin_target(self.packs, reference, change["tenant"], **common)
        else:
            target = pack_rollback_target(self.packs, pack_id, reference, **common)
        output = change_bytes("pack-activation", pack_id, change)
        return self.enact_target(tenant, target, output, mission=f"fixture:governance:{pack_id}",
                                 permit_ttl_us=permit_ttl_us, before_commit=before_commit)

    def enact_target(self, tenant, target, output, *, mission, permit_ttl_us=60_000_000, before_commit=None):
        """Use the same two-reviewer, cooling and clearance path for a bound target."""
        self.serial += 1
        ident = str(self.serial)
        digest = hashlib.sha256(output).hexdigest()
        ctx = PolicyContext(tenant, Actor("requester", tenant, frozenset()), "fixture:governance", ident,
                            self.clock.now_us())
        assertion = Assertion("change-" + ident, tenant, GOVERNANCE_CONTENT_TYPE, digest)
        action = Action(target.operation, ActionEffect.EXTERNAL, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(), mission=mission)))
        capability = self.preflight.authorize(tenant_id=tenant, vertical="governance", action_id=target.operation,
            risk_tier=4, correlation_id=ident, now_us=self.clock.now_us(), ttl_us=120_000_000, nonce="cap-" + ident)
        params = dict(vertical="governance", capability=capability, assertion=assertion, action=action,
            ctx=ctx, output=output, target=target, permit_ttl_us=permit_ttl_us, nonce="effect-" + ident)
        refused = self.packs.authorize(self.engine, **{**params, "nonce": "review-attempt-" + ident})
        assert not refused.authorized
        assert not self.uses.used(tenant, "effect-" + ident)
        decision = next(entry for entry in reversed(self.recorder.entries(tenant))
                        if entry.record.decision.kind.value == "require-approval")
        review = self.approvals.open(request_id="review-" + ident, requester_id="requester", tenant_id=tenant,
            assertion_id=assertion.assertion_id, decision_record_id=decision.record.record_id,
            decision_record_hash=decision.record_hash, requirement=decision.record.decision.approval,
            now_us=self.clock.now_us())
        grants = []
        for principal in ("reviewer-a", "reviewer-b"):
            credential = issue_credential(self.keys["identity"], actor_id=principal, tenant_id=tenant,
                kind="role:governance-approver", expires_at_us=self.clock.now_us() + 120_000_000)
            grants.append(self.approvals.grant(review, Actor(principal, tenant, frozenset(), (credential,)),
                                                self.clock.now_us()))
        with pytest.raises(ApprovalError):
            self.approvals.finalize(review, grants[:1], self.clock.now_us())
        assert not self.uses.used(tenant, "effect-" + ident)
        certificate = self.approvals.finalize(review, grants, self.clock.now_us())
        remaining = decision.record.decided_at_us + self.cooling - self.clock.now_us()
        if remaining > 0:
            time.sleep(remaining / 1_000_000)
        self.clearances.put(issue_clearance(self.keys["monitor"], decision, cleared_at_us=self.clock.now_us()))
        authorized = self.packs.authorize(self.engine, **params, approval_cert=certificate, approval_evidence=decision)
        assert authorized.authorized, authorized.reason
        assert authorized.permit.permit.issued_at_us >= decision.record.decided_at_us + self.cooling
        if before_commit is not None:
            before_commit(authorized)
        result = self.engine.commit(authorized, output, target)
        assert self.recorder.verify_chain(tenant)
        return result, target, authorized, output
