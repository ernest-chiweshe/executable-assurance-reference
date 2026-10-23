"""Preventive receiving-boundary contracts with intact authentication controls.

All keys, permits and observations are synthetic. PostgreSQL is never opened;
its sentinel pool proves authentication refusal precedes connection acquisition.
Filesystem locking may create its directory/lock, but no effect or receipt may
be created. These tests do not claim database transaction qualification.
"""

from hashlib import sha256

import pytest

from regulated_core.clock import ClockReading
from regulated_core.database_receiver_pg import PostgresTargetReceiver, ReceiverAuthority
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer, Signature, TrustDirectory
from regulated_core.target import (
    ABSENT, FilesystemTargetAdapter, Outcome, SignedTargetPermit, TargetAuthority,
    TargetPermit, TargetRef,
)


class SyntheticClock:
    domain = "synthetic:receiving-signatures"

    def read(self):
        return ClockReading(self.domain, 100)

    def now_us(self):
        return 100


class NoEffectPorts:
    """Record forbidden downstream calls, without any credentials or SQL."""

    tenant_id = "synthetic:tenant"
    target = TargetRef("synthetic:database", "fixture-only")
    operation = "synthetic:update"

    def __init__(self):
        self.calls = []

    def connection(self):
        self.calls.append("connection")
        raise RuntimeError("synthetic connection boundary reached")

    def consume(self, *args):
        self.calls.append("consume")
        raise AssertionError("unauthenticated permit reached nonce consumption")

    def current_state_on(self, conn):
        self.calls.append("state")
        raise AssertionError("unauthenticated permit reached database state")

    def apply_on(self, conn, output):
        self.calls.append("effect")
        raise AssertionError("unauthenticated permit reached database effect")


def fixture_permit(target, operation):
    return TargetPermit(
        tenant_id="synthetic:tenant", principal="synthetic:principal", mission="",
        budget_reservation="synthetic:reservation", budget_units=0,
        policy_version="synthetic:policy", decision_record_id="synthetic:decision",
        decision_record_hash="a" * 64, approval_ref="synthetic:approval",
        assertion_id="synthetic:assertion", action_id="synthetic:action",
        operation=operation, target_kind=target.kind, target_digest=target.digest(),
        expected_target_state=ABSENT, output_digest=sha256(b"synthetic output").hexdigest(),
        qualification_digests=("b" * 64,), revocation_epoch=0,
        expires_at_us=200, nonce="synthetic:nonce", preparation_digest="c" * 64,
        clock_domain=SyntheticClock.domain, issued_at_us=90,
    )


@pytest.fixture
def keys():
    issuer = Ed25519Signer("synthetic:issuer")
    foreign = Ed25519Signer("synthetic:other-authority")
    different_key = Ed25519Signer(issuer.key_id)
    trust = TrustDirectory()
    trust.register_signer(issuer)
    trust.register_signer(foreign)
    return issuer, foreign, different_key, trust


def signature_fixture(kind, permit, keys):
    issuer, foreign, different_key, _ = keys
    if kind == "invalid-bytes":
        return Signature(issuer.key_id, "00" * 64)
    if kind == "unknown-identity":
        return Signature("synthetic:unknown", "00" * 64)
    if kind == "different-authority":
        return foreign.sign(permit.signed_body())
    if kind == "same-label-different-key":
        return different_key.sign(permit.signed_body())
    raise AssertionError(kind)


KINDS = ("invalid-bytes", "unknown-identity", "different-authority", "same-label-different-key")


def filesystem_fixture(tmp_path, keys):
    ports = NoEffectPorts()
    preparation_calls = []

    def require_synthetic_preparation(connection, signed):
        preparation_calls.append(signed.permit.nonce)
        raise EmissionError("synthetic preparation deliberately unavailable")

    authority = TargetAuthority(
        keys[0], keys[3], revocation_epoch=lambda tenant: 0, clock=SyntheticClock(),
        preparation_verifier=require_synthetic_preparation, require_preparation=True,
    )
    adapter = FilesystemTargetAdapter(
        tmp_path / "target" / "effect.txt", "synthetic:tenant", authority, ports,
    )
    return adapter, ports, preparation_calls


@pytest.mark.parametrize("kind", KINDS)
def test_filesystem_refuses_signature_at_receiving_boundary(tmp_path, keys, kind):
    adapter, ports, preparation_calls = filesystem_fixture(tmp_path, keys)
    permit = fixture_permit(adapter.target, adapter.operation)
    before = adapter.current_state()
    result = adapter.commit(SignedTargetPermit(permit, signature_fixture(kind, permit, keys)), b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "permit signature invalid or untrusted"
    assert adapter.current_state() == before == ABSENT
    assert not adapter.path.exists()
    assert ports.calls == preparation_calls == []
    assert not (adapter.path.parent / ".commit-receipts").exists()


def test_filesystem_authentic_signature_reaches_preparation_boundary(tmp_path, keys):
    adapter, ports, preparation_calls = filesystem_fixture(tmp_path, keys)
    permit = fixture_permit(adapter.target, adapter.operation)
    result = adapter.commit(SignedTargetPermit(permit, keys[0].sign(permit.signed_body())), b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "synthetic preparation deliberately unavailable"
    assert preparation_calls == [permit.nonce]
    assert ports.calls == []
    assert not adapter.path.exists()


def database_fixture(keys):
    ports = NoEffectPorts()
    authority = ReceiverAuthority(
        trust=keys[3], issuer_key_id=keys[0].key_id, evidence_key_id="synthetic:evidence",
        policy_version="synthetic:policy", max_decision_age_us=100,
        history=ports, inputs=ports,
    )
    return PostgresTargetReceiver(pool=ports, effect=ports, authority=authority), ports


@pytest.mark.parametrize("kind", KINDS)
def test_database_refuses_signature_before_connection_acquisition(keys, kind):
    receiver, ports = database_fixture(keys)
    permit = fixture_permit(receiver.target, receiver.operation)
    result = receiver.commit(SignedTargetPermit(permit, signature_fixture(kind, permit, keys)), b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "database permit authentication or target binding failed"
    assert ports.calls == []


def test_database_authentic_signature_reaches_connection_boundary(keys):
    receiver, ports = database_fixture(keys)
    permit = fixture_permit(receiver.target, receiver.operation)
    with pytest.raises(RuntimeError, match="synthetic connection boundary reached"):
        receiver.commit(SignedTargetPermit(permit, keys[0].sign(permit.signed_body())), b"synthetic output")
    assert ports.calls == ["connection"]
