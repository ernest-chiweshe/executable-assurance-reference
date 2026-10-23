"""X-8: publication and messaging leave only through the governed egress target, exactly once.

The reference engine authorizes an exact outbound payload for a registered receipt-capable endpoint (one release
approver, mandatory durable budget); the verbatim receipt-bound HTTP transport sends it through an injected synthetic
destination (no network). Lawful delivery is exactly once with a bound receipt; a duplicate delivery of the same permit
is answered from the durable outcome; a send without a valid permit is refused at the choke point before any request;
a lost acknowledgement is UNKNOWN and is resolved by the destination's receipt, never by sending again. Guards
unchanged; fictional tenant and endpoints; isolated PostgreSQL; actual restricted logins.
"""
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os

import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.clock_floor import DurableClock
from assurance_reference.engine import ReferenceEngine
from assurance_reference.governed_egress import DuplicateSendRefused, egress_delivery_target
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.recorder import ReferenceDecisionRecorder
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from factory.governed_http import PROFILE, HttpEndpoint, HttpReply
from factory.governed_http_pg import migrate_http_attempts
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer, EmissionAuthority, IdentityVerifier,
    IntendedUse, IntendedUseRegistry, PolicyContext, PolicyRegistry, PreflightAuthority, TrustDirectory,
    VerificationTrustStore, issue_credential,
)
from regulated_core.choke_points import (EGRESS_CONTENT_TYPE, EGRESS_OPERATION, EGRESS_ROLE, EgressPolicy,
                                         egress_bytes)
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import (PostgresGovernanceLog, PostgresMissionBudget, PostgresPermitUseStore,
                                           PostgresRevocationLedger)
from regulated_core.target import BoundEffect, Outcome, SignedTargetPermit, effect_destination
from regulated_core.worm import LocalWormStore

TENANT = "synthetic-publisher"


@dataclass
class SyntheticDestination:
    """A receipt-v1 destination held in memory. It is the RequestPort; nothing leaves the process."""

    origin: str
    delivered: dict = field(default_factory=dict)
    posts: list = field(default_factory=list)
    lose_acknowledgement: bool = False
    unbound_reply: bool = False  # Answer like an ordinary webhook: 200 without the bound receipt.
    on_request: object = None  # Runs when the request arrives, before the transport's pre-send recheck.

    def __call__(self, url, *, method, body, headers, before_send):
        if method == "POST":
            if self.on_request is not None:
                self.on_request()
            if before_send is not None:
                before_send()
            key = headers["Idempotency-Key"]
            self.posts.append(key)
            self.delivered[key] = {"schema": PROFILE, "key": key,
                                   "endpoint_digest": headers["X-Factory-Endpoint-Digest"],
                                   "request_digest": headers["X-Factory-Request-Digest"],
                                   "payload_digest": sha256(body).hexdigest(), "outcome": "committed"}
            if self.lose_acknowledgement:
                raise TimeoutError("synthetic acknowledgement lost after the destination applied the delivery")
            if self.unbound_reply:
                return HttpReply(200, b'{"ok": true}')
            return HttpReply(200, json.dumps(self.delivered[key]).encode())
        key = url.rsplit("/", 1)[1]
        held = self.delivered.get(key)
        return HttpReply(200, json.dumps(held).encode()) if held else HttpReply(404, b"")


class EgressFixture:
    def __init__(self, tmp_path):
        dsn = os.environ["FACTORY_TEST_DB_URL"]
        self.roles = roles = provision_local_roles(dsn)
        owner = LocalPool(dsn, roles.schema, "migration-owner")
        try:
            migrate_http_attempts(owner)
            with owner.connection() as conn, conn.transaction():
                conn.execute(f"GRANT SELECT, INSERT ON regulated_http_attempts_v1 TO {roles.receiver.role}")
        finally:
            owner.close()
        self.clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
        self.trust = TrustDirectory()
        self.keys = {name: Ed25519Signer("fixture:x8-egress:" + name)
                     for name in ("evidence", "approval", "identity", "emission", "preflight", "alert")}
        for signer in self.keys.values():
            self.trust.register_signer(signer)
        self.recorder = ReferenceDecisionRecorder(self.keys["evidence"], self.trust, pool=roles.recorder,
                                                  clock=self.clock)
        self.uses = PostgresPermitUseStore(pool=roles.receiver)
        self.approvals = ApprovalWorkflow(self.trust, self.keys["approval"],
                                          IdentityVerifier(self.trust, self.keys["identity"].key_id))
        policies = PolicyRegistry()
        policies.register(EgressPolicy(approvers=1))
        intended = IntendedUseRegistry()
        intended.declare(IntendedUse("egress", EGRESS_OPERATION, 2))
        self.preflight = PreflightAuthority(self.keys["preflight"], intended, self.trust)
        self.budget = PostgresMissionBudget(pool=roles.allocator)
        self.engine = ReferenceEngine(
            budget=self.budget, default_mission_budget={"limit": 4, "units": 1},
            alerts=AlertJournal(roles.alerts, self.keys["alert"], self.trust), registry=policies,
            recorder=self.recorder, retention=LocalWormStore(), verification_trust=VerificationTrustStore(self.trust),
            approvals=self.approvals, emission=EmissionAuthority(self.keys["emission"], self.trust, self.uses),
            preflight=self.preflight, clock=self.clock, revocation=PostgresRevocationLedger(pool=roles.receiver))
        self.log = PostgresGovernanceLog(pool=roles.governor)
        self.serial = 0

    def endpoint(self, endpoint_id, destination):
        endpoint = HttpEndpoint(tenant_id=TENANT, endpoint_id=endpoint_id,
                                delivery_url=destination.origin + "/deliver", receipt_url=destination.origin + "/receipts")
        return egress_delivery_target(endpoint, pool=self.roles.receiver, request=destination, budget=self.budget,
                                      authority=self.engine.targets, uses=self.uses,
                                      log=TenantFencedGovernanceLog(pool=self.roles.governor, tenant=TENANT))

    def authorized(self, target, payload, *, media_type="text/plain"):
        """Request, review by one release approver, then authorize the exact outbound payload."""
        self.serial += 1
        ident = f"x8-{self.serial}"
        output = egress_bytes(target._subject, media_type=media_type, payload=payload)
        digest = sha256(output).hexdigest()
        ctx = PolicyContext(TENANT, Actor("requester", TENANT, frozenset()), "fixture:egress", ident, self.clock.now_us())
        assertion = Assertion("outbound-" + ident, TENANT, EGRESS_CONTENT_TYPE, digest)
        action = Action(EGRESS_OPERATION, ActionEffect.EXTERNAL, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(), mission="fixture:egress:" + ident)))
        capability = self.preflight.authorize(tenant_id=TENANT, vertical="egress", action_id=EGRESS_OPERATION,
            risk_tier=2, correlation_id=ident, now_us=self.clock.now_us(), ttl_us=120_000_000, nonce="cap-" + ident)
        params = dict(vertical="egress", capability=capability, assertion=assertion, action=action, ctx=ctx,
                      output=output, target=target, permit_ttl_us=60_000_000, nonce="send-" + ident)
        refused = self.engine.authorize_for_target(**{**params, "nonce": "review-attempt-" + ident})
        assert not refused.authorized and not self.uses.used(TENANT, "send-" + ident)
        decision = next(entry for entry in reversed(self.recorder.entries(TENANT))
                        if entry.record.decision.kind.value == "require-approval")
        review = self.approvals.open(request_id="review-" + ident, requester_id="requester", tenant_id=TENANT,
            assertion_id=assertion.assertion_id, decision_record_id=decision.record.record_id,
            decision_record_hash=decision.record_hash, requirement=decision.record.decision.approval,
            now_us=self.clock.now_us())
        credential = issue_credential(self.keys["identity"], actor_id="approver", tenant_id=TENANT,
            kind="role:" + EGRESS_ROLE, expires_at_us=self.clock.now_us() + 120_000_000)
        grant = self.approvals.grant(review, Actor("approver", TENANT, frozenset(), (credential,)), self.clock.now_us())
        certificate = self.approvals.finalize(review, [grant], self.clock.now_us())
        authorized = self.engine.authorize_for_target(**params, approval_cert=certificate, approval_evidence=decision)
        assert authorized.authorized, authorized.reason
        return authorized, output


@pytest.fixture
def egress(tmp_path):
    return EgressFixture(tmp_path)


@pytest.mark.parametrize("endpoint_id,payload", [("synthetic-publication", "Fictional public bulletin."),
                                                 ("synthetic-messaging", "Fictional notification to a member.")])
def test_publication_and_messaging_are_delivered_exactly_once_with_a_bound_receipt(egress, endpoint_id, payload):
    destination = SyntheticDestination("https://destination.example.org")
    target = egress.endpoint(endpoint_id, destination)
    authorized, output = egress.authorized(target, payload)
    result = egress.engine.commit(authorized, output, target)
    assert result.outcome is Outcome.COMMITTED, result
    assert len(destination.posts) == 1 and egress.uses.used(TENANT, authorized.permit.permit.nonce)
    permit = authorized.permit.permit
    assert egress.budget.committed(TENANT, permit.mission) == 1  # Spent once, with the recorded attempt.
    # A duplicate send of the same permit is refused at egress: nothing is sent, spent or recorded again.
    events = len(egress.recorder.entries(TENANT))
    with pytest.raises(DuplicateSendRefused, match="refused at egress"):
        egress.engine.commit(authorized, output, target)
    assert len(destination.posts) == 1 and egress.budget.committed(TENANT, permit.mission) == 1
    assert len(egress.recorder.entries(TENANT)) == events
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED  # The outcome stays observable.
    assert egress.recorder.verify_chain(TENANT)


def test_a_send_that_loses_the_permit_claim_to_another_holder_is_refused_at_egress(egress):
    # C060-PRE-R2: another holder claimed this permit's nonce first (through the ordinary permit-use store, as a
    # concurrent delivery would) and has not yet recorded an outcome. This send is refused, not answered UNKNOWN.
    destination = SyntheticDestination("https://destination.example.org")
    target = egress.endpoint("synthetic-publication", destination)
    authorized, output = egress.authorized(target, "Fictional bulletin claimed by a concurrent holder.")
    permit = authorized.permit.permit
    egress.uses.consume(TENANT, permit.nonce)
    with pytest.raises(DuplicateSendRefused, match="refused at egress"):
        egress.engine.commit(authorized, output, target)
    assert destination.posts == [] and egress.budget.committed(TENANT, permit.mission) == 0


def test_a_send_without_a_valid_permit_is_refused_at_the_choke_point(egress):
    destination = SyntheticDestination("https://destination.example.org")
    target = egress.endpoint("synthetic-publication", destination)
    authorized, output = egress.authorized(target, "Fictional bulletin.")
    # No permit at all, a permit presented with other bytes, and a permit under another signature.
    assert target.commit(None, output).outcome is Outcome.FAILED
    other = egress_bytes("synthetic-publication", media_type="text/plain", payload="Different bytes.")
    assert target.commit(authorized.permit, other).outcome is Outcome.FAILED
    signed = authorized.permit
    forged = SignedTargetPermit(signed.permit, type(signed.signature)(signed.signature.key_id, "AA" * 64,
                                                                       signed.signature.alg))
    assert target.commit(forged, output).outcome is Outcome.FAILED
    assert destination.posts == [] and not egress.uses.used(TENANT, signed.permit.nonce)


def test_lost_acknowledgement_is_unknown_and_resolved_by_receipt_without_sending_again(egress):
    destination = SyntheticDestination("https://destination.example.org", lose_acknowledgement=True)
    target = egress.endpoint("synthetic-publication", destination)
    authorized, output = egress.authorized(target, "Fictional bulletin whose acknowledgement is lost.")
    lost = egress.engine.commit(authorized, output, target)
    assert lost.outcome is Outcome.UNKNOWN, lost
    assert len(destination.posts) == 1
    # The target resolves from the destination's bound receipt (one GET), never by sending again.
    resolved = target.reconcile(authorized.permit)
    assert resolved.outcome is Outcome.COMMITTED, resolved
    recorded = egress.engine.reconcile(authorized, target)
    assert recorded.outcome is Outcome.COMMITTED, recorded
    with pytest.raises(DuplicateSendRefused):
        egress.engine.commit(authorized, output, target)
    assert len(destination.posts) == 1  # Never sent a second time.


def test_an_ordinary_reply_without_a_bound_receipt_stays_unknown_until_the_receipt_api_proves_it(egress):
    destination = SyntheticDestination("https://destination.example.org", unbound_reply=True)
    target = egress.endpoint("synthetic-publication", destination)
    authorized, output = egress.authorized(target, "Fictional bulletin to an ordinary webhook reply.")
    answered = egress.engine.commit(authorized, output, target)
    assert answered.outcome is Outcome.UNKNOWN, answered  # A 200 alone is not a receipt.
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED  # The bound receipt API proves it.
    assert len(destination.posts) == 1


def test_a_revocation_after_the_attempt_is_recorded_is_refused_before_the_request(egress):
    destination = SyntheticDestination("https://destination.example.org")
    target = egress.endpoint("synthetic-publication", destination)
    authorized, output = egress.authorized(target, "Fictional bulletin revoked while in flight.")
    revocations = PostgresRevocationLedger(pool=egress.roles.governor)

    def revoke_in_flight():
        # An ordinary tenant revocation that lands after the attempt and its spend are recorded.
        revocations.revoke(TENANT, actor="synthetic-operator", reason="Synthetic revocation during dispatch",
                           now_us=egress.clock.now_us())

    destination.on_request = revoke_in_flight
    result = egress.engine.commit(authorized, output, target)
    assert result.outcome is not Outcome.COMMITTED, result
    assert destination.posts == [] and destination.delivered == {}  # Nothing was delivered.
