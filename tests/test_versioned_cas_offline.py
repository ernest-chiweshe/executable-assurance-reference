"""Offline intact contracts only; synthetic transaction observations, no PostgreSQL.

These checks do not qualify SQL, RLS, approval integration or actual rollback.
They keep the admission and CAS guards intact and exercise their public methods.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from assurance_reference.versioned_cas import (
    AdmittedVersionedRowEffect, TransactionBoundAdmission, VersionedRowEffect,
    compose_versioned_receiver, state_digest,
)
from regulated_core.permit import EmissionError
from regulated_core.signing import Ed25519Signer
from regulated_core.target import SignedTargetPermit, TargetRef
from test_receiving_signature_contracts import fixture_permit

BODY = b"synthetic output"
TARGET = TargetRef("postgres", "synthetic:versioned-row")
TENANT = "synthetic:tenant"
OPERATION = "synthetic:update"


class Row:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return self.value


class Transaction:
    """Ordinary synthetic observations; implements no database security."""
    def __init__(self, transaction_id="101", revision=3, body=b"old", now_us=100):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.INTRANS)
        self.transaction_id = transaction_id
        self.now_us = now_us
        self.revision, self.body = revision, body
        self.writes = []
        self.calls = []

    def execute(self, statement, args=()):
        self.calls.append(statement)
        if statement == "SELECT pg_current_xact_id()::text":
            return Row((self.transaction_id,))
        if statement == "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint":
            return Row((self.now_us,))
        if statement.startswith("SELECT revision,body"):
            return Row((self.revision, self.body))
        if statement.startswith("UPDATE reference_versioned_state_v1"):
            output, tenant, target, expected = args
            assert tenant == TENANT and target == TARGET.digest()
            if self.revision != expected:
                return Row(None)
            self.revision += 1
            self.body = output
            self.writes.append((self.revision, output))
            return Row((self.revision, self.body))
        raise AssertionError("unexpected synthetic statement")


def fixture():
    signer = Ed25519Signer("synthetic:admission")
    permit = replace(fixture_permit(TARGET, OPERATION),
                     expected_target_state=state_digest(3, b"old"))
    signed = SignedTargetPermit(permit, signer.sign(permit.signed_body()))
    observed = []

    def verifier(conn, request, target):
        # Synthetic trusted-host callback, not a retained approval qualification.
        assert request == signed and target == TARGET
        observed.append((conn, request.permit.nonce))
        return 190

    admission = TransactionBoundAdmission(
        tenant_id=TENANT, target=TARGET, operation=OPERATION, verify_on=verifier)
    return admission, signed, observed


def effect(admission, revision=3):
    return AdmittedVersionedRowEffect(TENANT, TARGET, OPERATION, revision, admission)


def test_lawful_admission_consumes_once_with_exact_cas_state():
    admission, signed, observed = fixture()
    conn = Transaction()
    target = effect(admission)
    assert target.current_state_on(conn) == signed.permit.expected_target_state
    assert admission.lock_current_on(conn, signed, TARGET) == 190
    assert target.apply_on(conn, BODY) == state_digest(4, BODY)
    assert observed == [(conn, signed.permit.nonce)]
    assert conn.writes == [(4, BODY)]
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        target.apply_on(conn, BODY)
    assert conn.writes == [(4, BODY)]


def test_uncomposed_default_refuses_before_sql():
    conn = Transaction()
    target = VersionedRowEffect(TENANT, TARGET, OPERATION, 3)
    with pytest.raises(EmissionError, match="requires composed admission"):
        target.apply_on(conn, BODY)
    assert conn.calls == conn.writes == []


def test_other_connection_has_no_proof_even_with_same_observed_transaction_id():
    admission, signed, _ = fixture()
    original, other = Transaction(), Transaction()
    admission.lock_current_on(original, signed, TARGET)
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        effect(admission).apply_on(other, BODY)
    assert other.calls == other.writes == []
    assert effect(admission).apply_on(original, BODY) == state_digest(4, BODY)


def test_same_connection_new_transaction_cannot_use_old_proof():
    admission, signed, _ = fixture()
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    conn.transaction_id = "102"  # A synthetic next transaction on this connection.
    with pytest.raises(EmissionError, match="another transaction"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == []
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        effect(admission).apply_on(conn, BODY)


def test_other_output_is_refused_and_retires_proof():
    admission, signed, _ = fixture()
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    with pytest.raises(EmissionError, match="exact effect bytes"):
        effect(admission).apply_on(conn, b"different synthetic output")
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == []


def test_stale_cas_revision_refuses_without_write():
    admission, signed, _ = fixture()
    conn = Transaction(revision=4)
    admission.lock_current_on(conn, signed, TARGET)
    with pytest.raises(EmissionError, match="revision changed or row absent"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == [] and conn.revision == 4 and conn.body == b"old"


@pytest.mark.parametrize("status", [TransactionStatus.IDLE, TransactionStatus.INERROR])
def test_inactive_transaction_refuses_before_verifier(status):
    admission, signed, observed = fixture()
    conn = Transaction()
    conn.info.transaction_status = status
    with pytest.raises(EmissionError, match="active receiver transaction"):
        admission.lock_current_on(conn, signed, TARGET)
    assert observed == conn.calls == conn.writes == []


@pytest.mark.parametrize("deadline", [None, True, 0, -1, "190"])
def test_invalid_deadline_never_creates_proof(deadline):
    _, signed, _ = fixture()
    admission = TransactionBoundAdmission(
        tenant_id=TENANT, target=TARGET, operation=OPERATION,
        verify_on=lambda *_: deadline)
    conn = Transaction()
    with pytest.raises(EmissionError, match="invalid deadline"):
        admission.lock_current_on(conn, signed, TARGET)
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == []


def test_configured_effect_mismatch_refuses_before_verifier():
    admission, signed, observed = fixture()
    conn = Transaction()
    with pytest.raises(EmissionError, match="configured effect"):
        admission.lock_current_on(conn, signed, TargetRef("postgres", "synthetic:other"))
    assert observed == conn.calls == []
    with pytest.raises(ValueError, match="configuration differ"):
        AdmittedVersionedRowEffect(TENANT, TARGET, "synthetic:other", 3, admission)


def test_two_connections_keep_their_own_single_use_proofs():
    admission, signed, observed = fixture()
    a, b = Transaction("101"), Transaction("102")
    admission.lock_current_on(a, signed, TARGET)
    admission.lock_current_on(b, signed, TARGET)
    admission.require_effect_on(a, BODY)
    admission.require_effect_on(b, BODY)
    assert len(observed) == 2
    for conn in (a, b):
        with pytest.raises(EmissionError, match="one-use database admission proof required"):
            admission.require_effect_on(conn, BODY)
        assert conn.writes == []
    # This is proof lifecycle only. Durable permit replay remains the core receiver's job.


def test_factory_pins_admission_without_altering_existing_receiver():
    _, signed, _ = fixture()
    receiver = compose_versioned_receiver(
        pool=object(), authority=object(), tenant_id=TENANT, target=TARGET,
        operation=OPERATION, expected_revision=3, verify_on=lambda *_: 190)
    conn = Transaction()
    receiver._admission.lock_current_on(conn, signed, TARGET)
    assert receiver._effect.apply_on(conn, BODY) == state_digest(4, BODY)
    assert conn.writes == [(4, BODY)]

def test_refused_new_admission_retires_prior_proof():
    _, signed, _ = fixture()
    current = [True]

    def verify(*_):
        if not current[0]:
            raise EmissionError("synthetic approval no longer current")
        return 190

    admission = TransactionBoundAdmission(
        tenant_id=TENANT, target=TARGET, operation=OPERATION, verify_on=verify)
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    current[0] = False
    with pytest.raises(EmissionError, match="approval no longer current"):
        admission.lock_current_on(conn, signed, TARGET)
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == []


def retained_verifier_fixture(*, signature_valid=True, approval_ref="synthetic:review"):
    from assurance_reference.versioned_cas import RetainedCasApprovalVerifier
    from regulated_core.signing import TrustDirectory
    signer = Ed25519Signer("synthetic:issuer")
    foreign = Ed25519Signer("synthetic:foreign")
    trust = TrustDirectory()
    trust.register_signer(signer)
    permit = replace(fixture_permit(TARGET, OPERATION), approval_ref=approval_ref)
    selected = signer if signature_valid else foreign
    signed = SignedTargetPermit(permit, selected.sign(permit.signed_body()))
    authority = SimpleNamespace(
        issuer_key_id=signer.key_id, trust=trust, approvals=object(), history=object())
    calls = []

    def authenticate(*args):
        calls.append(args)
        return 190

    return RetainedCasApprovalVerifier(
        authority=authority, authenticate_and_lock_on=authenticate), signed, calls


def test_retained_verifier_requires_configured_approval_and_history():
    from assurance_reference.versioned_cas import RetainedCasApprovalVerifier
    for approval, history in ((None, object()), (object(), None)):
        with pytest.raises(ValueError, match="approval authority and pinned history"):
            RetainedCasApprovalVerifier(
                authority=SimpleNamespace(approvals=approval, history=history),
                authenticate_and_lock_on=lambda *_: 190)
    with pytest.raises(ValueError, match="host authentication boundary"):
        RetainedCasApprovalVerifier(
            authority=SimpleNamespace(approvals=object(), history=object()),
            authenticate_and_lock_on=None)


def test_retained_verifier_refuses_untrusted_signature_before_host_or_sql():
    verifier, signed, calls = retained_verifier_fixture(signature_valid=False)
    conn = Transaction()
    with pytest.raises(EmissionError, match="permit authentication failed"):
        verifier(conn, signed, TARGET)
    assert calls == conn.calls == conn.writes == []


def test_retained_verifier_refuses_missing_review_before_host_or_sql():
    verifier, signed, calls = retained_verifier_fixture(approval_ref="")
    conn = Transaction()
    with pytest.raises(EmissionError, match="explicit approval reference"):
        verifier(conn, signed, TARGET)
    assert calls == conn.calls == conn.writes == []


@pytest.mark.parametrize("deadline", [False, 0, "190"])
def test_retained_verifier_requires_valid_host_deadline_before_review_sql(deadline):
    from assurance_reference.versioned_cas import RetainedCasApprovalVerifier
    template, signed, _ = retained_verifier_fixture()
    conn = Transaction()
    verifier = RetainedCasApprovalVerifier(
        authority=template.authority, authenticate_and_lock_on=lambda *_: deadline)
    with pytest.raises(EmissionError, match="invalid deadline"):
        verifier(conn, signed, TARGET)
    assert conn.calls == conn.writes == []

@pytest.mark.parametrize("observed_now", [190, 191])
def test_exclusive_admission_deadline_refuses_before_cas_write(observed_now):
    admission, signed, _ = fixture()
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    conn.now_us = observed_now  # Synthetic ordinary elapsed time, guards intact.
    with pytest.raises(EmissionError, match="expired before effect"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == [] and conn.revision == 3 and conn.body == b"old"
    with pytest.raises(EmissionError, match="one-use database admission proof required"):
        admission.require_effect_on(conn, BODY)


def test_one_tick_before_deadline_can_apply_exact_cas():
    admission, signed, _ = fixture()
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    conn.now_us = 189
    assert effect(admission).apply_on(conn, BODY) == state_digest(4, BODY)
    assert conn.writes == [(4, BODY)]


@pytest.mark.parametrize("reading", [None, True, "100", -1])
def test_invalid_database_clock_observation_refuses_before_write(reading):
    admission, signed, _ = fixture()
    conn = Transaction()
    admission.lock_current_on(conn, signed, TARGET)
    conn.now_us = reading
    with pytest.raises(EmissionError, match="clock unavailable"):
        effect(admission).apply_on(conn, BODY)
    assert conn.writes == []
