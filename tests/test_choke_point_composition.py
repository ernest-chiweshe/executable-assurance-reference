"""Offline port composition, using original receiving controls and synthetic trust.

The preparation fixture is an exact-body allowlist, not the production retained
preparation/approval pipeline. Host ports record observations in memory: no real
credential, message, network endpoint, database, or durable receipt is created.
These contracts qualify receiver composition only, not host custody or deployment.
"""

from dataclasses import replace
from hashlib import sha256
import json
from threading import RLock

import pytest

from regulated_core.canonical import canonical_bytes
from regulated_core.choke_points import (
    channel_target, credential_issuance_target, credential_request_bytes,
    egress_bytes, egress_target, idempotency_key, message_bytes,
)
from regulated_core.clock import ClockReading
from regulated_core.governance_guard import GovernanceGuard, GovernanceRefused
from regulated_core.governance_targets import NOT_COMMITTED, FinalCheckRefused, GovernanceLog
from regulated_core.permit import EmissionError, InMemoryPermitUseStore
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory
from regulated_core.target import ABSENT, Outcome, SignedTargetPermit, TargetAuthority, TargetPermit


TENANT = "synthetic:choke-tenant"
SUBJECT = "synthetic:subject"


class FixtureClock:
    domain = "synthetic:choke-composition"
    value = 100

    def read(self):
        return ClockReading(self.domain, self.value)

    def now_us(self):
        return self.value


class ObservationPort:
    """Model the documented host transaction with an intact public guard check."""

    def __init__(self, kind, guard, clock):
        self.kind, self.guard, self.clock = kind, guard, clock
        self.state = "synthetic:registered-config" if kind == "egress" else ABSENT
        self.observations = []
        self.calls = 0
        self.state_reads = 0
        self.receipts = {}
        self.status_queries = []
        self.lock = RLock()
        self.lose_ack = False
        self.expire_before_write = False

    def lease(self, tenant, subject):
        self.state_reads += 1
        assert (tenant, subject) == (TENANT, SUBJECT)
        return self.state

    head = lease
    endpoint = lease

    def _record(self, change, key=None):
        with self.lock:
            self.calls += 1
            self.guard.require(change.kind, change.subject)
            if self.state != change.approved_prior:
                raise FinalCheckRefused("synthetic host prior state changed")
            if self.expire_before_write:
                self.clock.value = 200
            change.final_check()
            self.observations.append(dict(change.change))
            receipt_key = (change.tenant_id, change.operation, change.nonce, change.change_digest)
            self.receipts[receipt_key if key is None else (change.tenant_id, key)] = Outcome.COMMITTED
            if self.kind != "egress":
                self.state = change.change_digest
            if self.lose_ack:
                raise TimeoutError("synthetic acknowledgement unavailable")

    issue = _record
    deliver = _record
    send = _record

    def receipt(self, tenant, operation, nonce, digest):
        key = (tenant, operation, nonce, digest)
        self.status_queries.append(key)
        return self.receipts.get(key, Outcome.UNKNOWN)

    def status(self, tenant, key):
        self.status_queries.append((tenant, key))
        return self.receipts.get((tenant, key), Outcome.UNKNOWN)


class Composition:
    def __init__(self, kind):
        self.kind = kind
        self.clock = FixtureClock()
        self.guard = GovernanceGuard()
        self.port = ObservationPort(kind, self.guard, self.clock)
        self.uses = InMemoryPermitUseStore()
        self.log = GovernanceLog()
        self.signer = Ed25519Signer("synthetic:choke-issuer")
        trust = TrustDirectory()
        trust.register_signer(self.signer)
        self.preparations = {}
        self.epoch = 0

        def verify_fixture_preparation(connection, signed):
            assert connection is None
            body = canonical_bytes(signed.permit.signed_body())
            if self.preparations.get(signed.permit.preparation_digest) != body:
                raise EmissionError("exact synthetic preparation unavailable")

        authority = TargetAuthority(
            self.signer, trust, revocation_epoch=lambda tenant: self.epoch, clock=self.clock,
            preparation_verifier=verify_fixture_preparation, require_preparation=True,
        )
        factory = {"credential": credential_issuance_target, "inter-agent": channel_target,
                   "egress": egress_target}[kind]
        self.target = factory(self.port, SUBJECT, tenant_id=TENANT, authority=authority,
                              uses=self.uses, log=self.log, guard=self.guard)
        self.output = {
            "credential": credential_request_bytes(SUBJECT, holder="synthetic:holder",
                scope=("synthetic:read",), purpose="fixture only", ttl_us=100),
            "inter-agent": message_bytes(SUBJECT, sender="synthetic:one",
                recipient="synthetic:two", body="fixture message"),
            "egress": egress_bytes(SUBJECT, media_type="text/plain", payload="fixture payload"),
        }[kind]

    def authorize_fixture(self, *, nonce="synthetic:nonce", retain=True, bound_target=None,
                          operation=None):
        """Test authority approves exact synthetic bytes; no production approval claim."""
        digest = sha256(self.output).hexdigest()
        preparation = sha256(canonical_bytes({"fixture": nonce, "output": digest})).hexdigest()
        bound_target = self.target.target if bound_target is None else bound_target
        permit = TargetPermit(
            tenant_id=TENANT, principal="synthetic:principal", mission="",
            budget_reservation="synthetic:reservation", budget_units=0,
            policy_version="synthetic:policy", decision_record_id="synthetic:decision",
            decision_record_hash=sha256(b"synthetic decision").hexdigest(),
            approval_ref="synthetic:approval", assertion_id="synthetic:assertion",
            action_id="synthetic:action", operation=self.target.operation if operation is None else operation,
            target_kind=bound_target.kind, target_digest=bound_target.digest(),
            expected_target_state=self.port.state, output_digest=digest,
            qualification_digests=(sha256(b"synthetic qualification").hexdigest(),),
            revocation_epoch=0, expires_at_us=200, nonce=nonce,
            preparation_digest=preparation, clock_domain=self.clock.domain, issued_at_us=90,
        )
        if retain:
            self.preparations[preparation] = canonical_bytes(permit.signed_body())
        return SignedTargetPermit(permit, self.signer.sign(permit.signed_body()))


@pytest.fixture(params=("credential", "inter-agent", "egress"))
def composed(request):
    return Composition(request.param)


def test_authorized_observation_and_repeat_have_one_effect(composed):
    signed = composed.authorize_fixture()
    assert composed.target.commit(signed, composed.output).outcome is Outcome.COMMITTED
    assert composed.target.commit(signed, composed.output).outcome is Outcome.COMMITTED
    assert len(composed.port.observations) == 1
    assert composed.port.calls == 1
    assert len(composed.log.changes(TENANT)) == 1
    assert composed.uses.used(TENANT, signed.permit.nonce)
    with pytest.raises(GovernanceRefused):
        composed.guard.require(composed.kind, SUBJECT)


def test_missing_retained_preparation_refuses_before_nonce_or_effect(composed):
    signed = composed.authorize_fixture(retain=False)
    result = composed.target.commit(signed, composed.output)
    assert result.outcome is Outcome.FAILED
    assert result.detail == "exact synthetic preparation unavailable"
    assert not composed.uses.used(TENANT, signed.permit.nonce)
    assert composed.port.observations == [] and composed.log.events(TENANT) == ()


def test_prior_state_change_refuses_before_nonce_or_effect(composed):
    signed = composed.authorize_fixture()
    composed.port.state = "synthetic:new-state"
    result = composed.target.commit(signed, composed.output)
    assert result.outcome is Outcome.FAILED
    assert result.detail == "target state changed since authorization"
    assert not composed.uses.used(TENANT, signed.permit.nonce)
    assert composed.port.observations == [] and composed.log.events(TENANT) == ()


def test_host_final_check_refuses_expiry_before_observation(composed):
    signed = composed.authorize_fixture()
    composed.port.expire_before_write = True
    assert composed.target.commit(signed, composed.output).outcome is Outcome.FAILED
    assert composed.port.observations == []
    assert composed.uses.used(TENANT, signed.permit.nonce)
    prepared, resolved = composed.log.attempt(TENANT, signed.permit.nonce)
    assert prepared is not None and resolved.phase == NOT_COMMITTED
    assert composed.target.commit(signed, composed.output).outcome is Outcome.FAILED


def test_lost_ack_is_reconciled_by_receipt_without_resend(composed):
    signed = composed.authorize_fixture()
    composed.port.lose_ack = True
    assert composed.target.commit(signed, composed.output).outcome is Outcome.UNKNOWN
    assert composed.target.commit(signed, composed.output).outcome is Outcome.UNKNOWN
    other = composed.authorize_fixture(nonce="synthetic:second-nonce")
    assert composed.target.commit(other, composed.output).outcome is Outcome.FAILED
    assert len(composed.port.observations) == 1
    assert composed.target.reconcile(signed).outcome is Outcome.COMMITTED
    assert composed.target.commit(signed, composed.output).outcome is Outcome.COMMITTED
    assert len(composed.port.observations) == 1
    if composed.kind == "egress":
        expected = (TENANT, idempotency_key(TENANT, signed.permit.operation,
                                          signed.permit.nonce, signed.permit.output_digest))
    else:
        expected = (TENANT, signed.permit.operation, signed.permit.nonce, signed.permit.output_digest)
    assert composed.port.status_queries == [expected]


def test_unregistered_egress_never_reaches_transport():
    composed = Composition("egress")
    composed.port.state = ABSENT
    signed = composed.authorize_fixture()
    result = composed.target.commit(signed, composed.output)
    assert result.outcome is Outcome.FAILED
    assert result.detail == "the endpoint is not registered; nothing was sent"
    assert composed.port.calls == 0
    assert composed.port.observations == [] and composed.port.receipts == {}


def test_preparation_fixture_binds_entire_body(composed):
    signed = composed.authorize_fixture()
    changed = replace(signed.permit, action_id="synthetic:different-action")
    separately_signed = SignedTargetPermit(changed, composed.signer.sign(changed.signed_body()))
    result = composed.target.commit(separately_signed, composed.output)
    assert result.outcome is Outcome.FAILED
    assert result.detail == "exact synthetic preparation unavailable"
    assert composed.port.observations == []


@pytest.mark.parametrize("case,detail", [
    ("invalid-signature", "permit signature invalid or untrusted"),
    ("foreign-signer", "permit signature invalid or untrusted"),
    ("other-boundary", "permit is for a different target"),
    ("other-subject", "permit is for a different target"),
    ("other-operation", "permit is for a different operation"),
    ("different-payload", "output does not match the authorized digest"),
    ("revoked", "permit revoked: the tenant's revocation epoch has moved"),
])
def test_receiving_refusal_precedes_nonce_receipt_and_observation(composed, case, detail):
    """Negative authorization fixtures against unchanged controls, entirely offline."""
    target = composed.target.target
    if case == "other-boundary":
        target = replace(target, kind="synthetic:other-boundary")
    elif case == "other-subject":
        target = replace(target, identity="synthetic:other-subject")
    operation = "synthetic:other-operation" if case == "other-operation" else None
    signed = composed.authorize_fixture(bound_target=target, operation=operation)
    output = composed.output
    if case == "invalid-signature":
        signed = replace(signed, signature=Signature(composed.signer.key_id, "00" * 64))
    elif case == "foreign-signer":
        foreign = Ed25519Signer("synthetic:untrusted-fixture-signer")
        signed = replace(signed, signature=foreign.sign(signed.permit.signed_body()))
    elif case == "different-payload":
        request = json.loads(output)
        field = {"credential": "purpose", "inter-agent": "body", "egress": "payload"}[composed.kind]
        request["change"][field] = "different synthetic content"
        output = canonical_bytes(request)
    elif case == "revoked":
        composed.epoch = 1
    prior = composed.port.state
    result = composed.target.commit(signed, output)
    assert result.outcome is Outcome.FAILED and result.detail == detail
    assert not composed.uses.used(TENANT, signed.permit.nonce)
    assert composed.port.state == prior
    assert composed.port.calls == 0
    assert composed.port.observations == [] and composed.port.receipts == {}
    assert composed.log.events(TENANT) == ()


@pytest.mark.parametrize("missing", [None, "synthetic:not-a-permit", object()],
                         ids=["absent", "text", "object"])
def test_missing_or_wrong_outer_permit_returns_typed_refusal(composed, missing):
    """Reject the outer input shape before reaching any host or nonce operation."""
    prior = composed.port.state
    result = composed.target.commit(missing, composed.output)
    assert result.outcome is Outcome.FAILED
    assert result.detail == "a signed target permit is required"
    assert composed.port.state == prior
    assert composed.port.state_reads == 0
    assert composed.port.calls == 0
    assert composed.port.observations == [] and composed.port.receipts == {}
    assert composed.log.events(TENANT) == ()
    assert not composed.uses.used(TENANT, "synthetic:nonce")
