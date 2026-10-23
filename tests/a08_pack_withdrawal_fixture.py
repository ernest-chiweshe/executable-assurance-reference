"""Lawful synthetic supervisor withdrawal through the actual pack registry.

Uses the existing restricted governance composition and unchanged withdrawal
policy. No guard is replaced, no lifecycle row is edited directly, and fixture
approval never represents an owner or deployed professional authority.
"""
import hashlib
import json

from assurance_reference.packs import FIXTURES, PUBLISHER
from factory.packs.registry import PackRegistry
from partitioned_governance_fixture import GovernedFixture
from regulated_core import (
    Action, ActionEffect, Actor, Assertion, IntendedUse, IntendedUseRegistry,
    PolicyContext, PolicyRegistry, issue_credential,
)
from regulated_core.governance_targets import (
    WITHDRAWAL_CONTENT_TYPE, GovernanceWithdrawalPolicy, change_bytes,
)
from assurance_reference.governance_targets import pack_revocation_target
from regulated_core.target import BoundEffect, Outcome, effect_destination


class PackWithdrawalFixture:
    def __init__(self, roles, bundle, *, synthetic_bundle=None, synthetic_publisher=None):
        self.governance = GovernedFixture(roles)
        g = self.governance
        for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
            g.trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
        self.registry = PackRegistry(trust=g.trust, activation=g.packs.ledger)
        if (synthetic_bundle is None) != (synthetic_publisher is None):
            raise ValueError("synthetic withdrawal fixture requires bundle and publisher")
        if synthetic_bundle is None:
            pack_path, publisher_id = FIXTURES / "bundles" / bundle, PUBLISHER
        else:
            if synthetic_publisher.key_id != "fixture:education-budget-publisher":
                raise ValueError("only the explicit synthetic budget publisher is accepted")
            g.trust.register_signer(synthetic_publisher)
            pack_path, publisher_id = synthetic_bundle, synthetic_publisher.key_id
        self.pack = self.registry.install(pack_path, publisher_key_id=publisher_id,
                                          today="2026-10-14")
        policies = PolicyRegistry()
        policies.register(GovernanceWithdrawalPolicy())
        intended = IntendedUseRegistry()
        intended.declare(IntendedUse("governance", "governance:revoke-pack", 3))
        self.preflight = g.preflight.for_uses(intended)
        self.engine = g.engine.for_policy(registry=policies, preflight=self.preflight)
        self.tenant = "synthetic-withdrawal-office"

    def withdraw(self):
        g, tenant = self.governance, self.tenant
        target = pack_revocation_target(self.registry, self.pack.reference,
            tenant_id=tenant, authority=self.engine.targets, uses=g.uses, log=g.log, budget=g.budget)
        change = {"revoke": self.pack.reference, "at": str(g.clock.now_us()),
                  "reason": "Synthetic supervised withdrawal before application delivery"}
        output = change_bytes("pack-activation", self.pack.manifest.id, change)
        digest = hashlib.sha256(output).hexdigest()
        assertion = Assertion("withdrawal", tenant, WITHDRAWAL_CONTENT_TYPE, digest)
        context = PolicyContext(tenant, Actor("requester", tenant, frozenset()),
                                "fixture:withdrawal", "withdrawal", g.clock.now_us())
        action = Action(target.operation, ActionEffect.EXTERNAL, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(), mission="fixture:withdrawal:" + self.pack.manifest.id)))
        capability = self.preflight.authorize(tenant_id=tenant, vertical="governance",
            action_id=target.operation, risk_tier=3, correlation_id="withdrawal",
            now_us=g.clock.now_us(), ttl_us=120_000_000, nonce="withdrawal-capability")
        parameters = dict(vertical="governance", capability=capability, assertion=assertion,
            action=action, ctx=context, output=output, target=target,
            permit_ttl_us=60_000_000, nonce="withdrawal-effect")
        prior = target.current_state()
        refused = self.engine.authorize_for_target(**parameters)
        assert not refused.authorized
        assert target.current_state() == prior and not g.uses.used(tenant, "withdrawal-effect")
        decision = next(entry for entry in reversed(g.recorder.entries(tenant))
                        if entry.record.decision.kind.value == "require-approval")
        review = g.approvals.open(request_id="withdrawal-review", requester_id="requester",
            tenant_id=tenant, assertion_id=assertion.assertion_id,
            decision_record_id=decision.record.record_id, decision_record_hash=decision.record_hash,
            requirement=decision.record.decision.approval, now_us=g.clock.now_us())
        credential = issue_credential(g.keys["identity"], actor_id="supervisor", tenant_id=tenant,
            kind="role:governance-supervisor", expires_at_us=g.clock.now_us() + 120_000_000)
        grant = g.approvals.grant(review, Actor("supervisor", tenant, frozenset(), (credential,)),
                                  g.clock.now_us())
        certificate = g.approvals.finalize(review, [grant], g.clock.now_us())
        authorized = self.engine.authorize_for_target(**parameters, approval_cert=certificate,
                                                      approval_evidence=decision)
        assert authorized.authorized, authorized.reason
        result = self.engine.commit(authorized, output, target)
        assert result.outcome is Outcome.COMMITTED, result.detail
        assert self.registry.ledger.is_revoked(self.pack.manifest.id, self.pack.manifest.version)
        receipt = (tenant, target.operation, authorized.permit.permit.nonce, digest)
        assert self.registry.governance_receipt(*receipt) is Outcome.COMMITTED
        state, events = target.current_state(), tuple(g.log.events(tenant))
        assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
        assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
        assert target.current_state() == state and tuple(g.log.events(tenant)) == events
        assert g.recorder.verify_chain(tenant)

