"""Synthetic transaction-lifetime contracts, not PostgreSQL floor qualification."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from psycopg import OperationalError
from psycopg.pq import TransactionStatus

from assurance_reference.generation_floor_admission import GenerationFloorAdmission
from factory.customer.generation_floor_pg import GenerationFloorVerifier
from factory.pg_session import SessionBoundPool
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.target import ReleaseAdmissionUnavailable


class SyntheticConnection:
    def __init__(self):
        self.events = []
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.autocommit = True
        self.binding = ("factory_test", "receiver", "receiver")
        self.domain, self.recovery = "pg:123", False
        self.close_error = False

    def execute(self, statement):
        assert self.info.transaction_status == TransactionStatus.INTRANS
        if statement == "SELECT current_database(), current_user, session_user":
            return SimpleNamespace(fetchone=lambda: self.binding)
        assert "pg_control_system" in statement
        return SimpleNamespace(fetchall=lambda: [(self.domain, 10, self.recovery)])

    @contextmanager
    def transaction(self):
        self.info.transaction_status = TransactionStatus.INTRANS
        self.events.append("begin")
        try:
            yield
        finally:
            self.info.transaction_status = TransactionStatus.IDLE
            self.events.append("end")
            if self.close_error:
                raise OperationalError("synthetic transaction close uncertainty")


class SyntheticPool:
    def __init__(self, connection):
        self.conn = connection

    @contextmanager
    def connection(self):
        self.conn.events.append("checkout")
        try:
            yield self.conn
        finally:
            self.conn.events.append("return")


class SyntheticVerifier(GenerationFloorVerifier):
    # Detached contract double: no original runtime verifier or guard is changed.
    def __init__(self):
        self.refused = False

    def require_on(self, connection):
        assert connection.info.transaction_status == TransactionStatus.INTRANS
        connection.events.append("floor")
        if self.refused:
            raise CredentialError("synthetic unqualified floor")


def fixture():
    connection, verifier = SyntheticConnection(), SyntheticVerifier()
    guard = GenerationFloorAdmission(verifier, SyntheticPool(connection), "pg:123", "factory_test", "receiver")
    return guard, connection, verifier


def test_floor_is_rechecked_and_transaction_spans_effect():
    guard, connection, _ = fixture()
    with guard.hold() as check:
        check()
        connection.events.append("synthetic-effect")
        assert connection.info.transaction_status == TransactionStatus.INTRANS
    assert connection.events == ["checkout", "begin", "floor", "floor", "synthetic-effect", "end", "return"]
    with pytest.raises(EmissionError, match="scope has ended"):
        check()
    assert connection.events[-1] == "return"


def test_initial_floor_refusal_does_not_enter_effect_body():
    guard, connection, verifier = fixture()
    verifier.refused = True
    with pytest.raises(CredentialError):
        with guard.hold():
            pytest.fail("refused floor must not enter the body")
    assert connection.events == ["checkout", "begin", "floor", "end", "return"]


def test_final_floor_refusal_is_target_compatible_and_scope_closes():
    guard, connection, verifier = fixture()
    with pytest.raises(EmissionError):
        with guard.hold() as check:
            verifier.refused = True
            check()
            pytest.fail("refused final check must not reach an effect")
    assert connection.info.transaction_status == TransactionStatus.IDLE


@pytest.mark.parametrize("binding", [("other", "receiver", "receiver"),
                                     ("factory_test", "owner", "receiver"),
                                     ("factory_test", "receiver", "owner")])
def test_wrong_database_or_either_login_refuses_before_floor(binding):
    guard, connection, _ = fixture()
    connection.binding = binding
    with pytest.raises(CredentialError, match="differs"):
        with guard.hold():
            pytest.fail("wrong binding must not enter body")
    assert "floor" not in connection.events


@pytest.mark.parametrize("domain,recovery", [("pg:999", False), ("pg:123", True)])
def test_wrong_cluster_or_replica_refuses_before_floor(domain, recovery):
    guard, connection, _ = fixture()
    connection.domain, connection.recovery = domain, recovery
    with pytest.raises(ReleaseAdmissionUnavailable):
        with guard.hold():
            pytest.fail("wrong primary must not enter body")
    assert "floor" not in connection.events


@pytest.mark.parametrize("active", [False, True])
def test_non_idle_or_non_autocommit_connection_refuses(active):
    guard, connection, _ = fixture()
    if active:
        connection.info.transaction_status = TransactionStatus.INTRANS
    else:
        connection.autocommit = False
    with pytest.raises(CredentialError, match="idle autocommit"):
        with guard.hold():
            pytest.fail("invalid connection must not enter body")
    assert connection.events == ["checkout", "return"]


def test_close_uncertainty_after_effect_is_not_a_no_effect_verdict():
    guard, connection, _ = fixture()
    with pytest.raises(ReleaseAdmissionUnavailable, match="reconcile any possible effect"):
        with guard.hold() as check:
            check()
            connection.events.append("synthetic-effect")
            connection.close_error = True
    assert "synthetic-effect" in connection.events
    with pytest.raises(EmissionError, match="scope has ended"):
        check()


def test_constructor_refuses_session_bound_pool_without_io():
    guard, connection, verifier = fixture()
    with pytest.raises(ValueError, match="independent"):
        GenerationFloorAdmission(verifier, SessionBoundPool(guard.pool), "pg:123", "factory_test", "receiver")
    assert not connection.events


@pytest.mark.parametrize("domain,database,login", [("", "factory_test", "receiver"),
    ("pg:123", "", "receiver"), ("pg:123", "factory_test", "receiver\n"),
    ("pg:123", "x" * 64, "receiver")])
def test_constructor_requires_explicit_host_binding(domain, database, login):
    guard, connection, verifier = fixture()
    with pytest.raises(ValueError):
        GenerationFloorAdmission(verifier, guard.pool, domain, database, login)
    assert not connection.events
