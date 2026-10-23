"""Synthetic recorder dependency failures; authority controls remain intact."""

from contextlib import contextmanager
import os

import psycopg
import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.signing import Ed25519Signer
from test_education_session_release import reviewed_context


class CountingSigner:
    """Observe signing calls without retaining authority-bearing payloads."""

    def __init__(self, key_id):
        self.delegate = Ed25519Signer(key_id)
        self.key_id, self.alg, self.kind = key_id, self.delegate.alg, self.delegate.kind
        self.calls = 0

    @property
    def public_key_bytes(self):
        return self.delegate.public_key_bytes

    def sign(self, body):
        self.calls += 1
        return self.delegate.sign(body)

    def sign_bytes(self, body):
        self.calls += 1
        return self.delegate.sign_bytes(body)


class RecordFailurePool:
    """Fail the storage dependency inside its real transaction, before commit."""

    def __init__(self, delegate, phase):
        self.delegate, self.phase = delegate, phase
        self.failures = 0
        self.inserts = 0

    @contextmanager
    def connection(self):
        with self.delegate.connection() as connection:
            yield RecordFailureConnection(connection, self)


class RecordFailureConnection:
    def __init__(self, connection, fault):
        self.connection, self.fault = connection, fault
        self.inserted = False

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, query, *args, **kwargs):
        if isinstance(query, str) and query.startswith("INSERT INTO regulated_decision_evidence_v1 "):
            self.fault.inserts += 1
            if self.fault.phase == "insert":
                self.fault.failures += 1
                raise psycopg.OperationalError("synthetic recorder insert unavailable")
            self.inserted = True
        return self.connection.execute(query, *args, **kwargs)

    @contextmanager
    def transaction(self, *args, **kwargs):
        with self.connection.transaction(*args, **kwargs):
            yield
            if self.inserted and self.fault.phase == "before-commit":
                self.fault.failures += 1
                # Raise within the real transaction so the inserted row rolls
                # back. This does not model an ambiguous post-commit timeout.
                raise psycopg.OperationalError("synthetic recorder commit unavailable")


@pytest.mark.parametrize("phase", ["insert", "before-commit"])
def test_durable_record_failure_prevents_permit_signing_and_output(tmp_path, phase):
    signers = {}

    def signer_factory(key_id):
        signer = CountingSigner(key_id)
        signers[key_id.rsplit(":", 1)[1]] = signer
        return signer

    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path, signer_factory=signer_factory)
    context = reviewed_context(app)
    gate = app.gates["requester"]
    recorder = app.stores.recorder
    original_pool = recorder._pool
    before = recorder.entries("school-a")
    emission_calls = signers["emission"].calls
    fault = RecordFailurePool(original_pool, phase)
    recorder._pool = fault  # Explicit storage dependency fault, no guard replacement.
    try:
        with pytest.raises(psycopg.OperationalError, match="synthetic recorder"):
            gate.authorize_release(spec=app.spec, contract=app.contract,
                out_path=str(app.path), context=context, artifact=app.body)
    finally:
        recorder._pool = original_pool
    assert fault.failures == 1 and fault.inserts == 1
    assert signers["emission"].calls == emission_calls
    assert not app.path.exists()
    assert recorder.entries("school-a") == before
    assert recorder.verify_chain("school-a")
    assert not app.stores.permits.used("school-a", context.nonce)
    # Availability recovery is the positive control: the same reviewed request
    # can still receive a permit and produce exactly its approved artifact.
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert decision.allowed and decision.permit is not None, decision.reason
    result = gate.commit_release(spec=app.spec, contract=app.contract,
        decision=decision, out_path=str(app.path), context=context, artifact=app.body)
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert signers["emission"].calls > emission_calls
    assert recorder.verify_chain("school-a")
