"""Retained database tests for the new clock floor, without changing host time."""

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from regulated_core.clock import ClockError, ClockReading
from regulated_core.clock_pg import DbClock
from regulated_core import Ed25519Signer, TrustDirectory
from regulated_core.permit import EmissionError
from regulated_core.target import SignedTargetPermit, TargetAuthority, TargetPermit, TargetRef


class SampleClock:
    domain = "test:durable-floor"

    def __init__(self, value=100):
        self.value = value
        self.samples = []

    def read(self):
        value = self.samples.pop(0) if self.samples else self.value
        return ClockReading(self.domain, value)

    def read_on(self, connection):
        return self.read()

    def now_us(self):
        return self.read().now_us


@pytest.fixture
def floor_case(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped database qualification"
    assert conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        assert connection.execute("SELECT current_database()").fetchone()[0] == "factory_test"
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    (tmp_path / "retained-schema.json").write_text(json.dumps({"schema": schema}), encoding="utf-8")
    pool = SchemaConnections(dsn, schema)
    source = SampleClock()
    provision_floor(pool, source)
    return pool, source, DurableClock(source, floor_pool=pool)


def test_floor_survives_reconstruction_and_reprovisioning(floor_case):
    pool, source, clock = floor_case
    source.value = 200
    assert clock.read().now_us == 200
    source.value = 150
    provision_floor(pool, source)
    restored = DurableClock(source, floor_pool=pool)
    with pytest.raises(ClockError, match="regressed"):
        restored.read()
    source.value = 201
    assert restored.read().now_us == 201


def test_caller_rollback_cannot_erase_returned_floor(floor_case):
    pool, source, clock = floor_case

    class RollBackCaller(Exception):
        pass

    with pytest.raises(RollBackCaller):
        with pool.connection() as caller, caller.transaction():
            source.value = 200
            assert clock.read_on(caller).now_us == 200
            raise RollBackCaller
    source.value = 199
    with pytest.raises(ClockError, match="regressed"):
        DurableClock(source, floor_pool=pool).read()


def test_later_sample_regression_keeps_larger_observation(floor_case):
    pool, source, clock = floor_case
    source.samples = [200, 199]
    with pool.connection() as caller:
        with pytest.raises(ClockError, match="regressed"):
            clock.read_on(caller)
    with pool.connection() as connection:
        stored = connection.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s", (source.domain,)
        ).fetchone()[0]
    assert stored == 200


def test_primary_readers_share_a_durable_floor(floor_case):
    pool, _, _ = floor_case
    with pool.connection() as connection:
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    source = DbClock(None, domain)
    provision_floor(pool, source)

    def sample(_):
        return DurableClock(source, floor_pool=pool).read().now_us

    with ThreadPoolExecutor(max_workers=4) as workers:
        readings = list(workers.map(sample, range(8)))
    with pool.connection() as connection:
        retained = connection.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s", (domain,)
        ).fetchone()[0]
    assert retained == max(readings)
    assert DurableClock(source, floor_pool=pool).read().now_us >= retained


def test_runtime_read_does_not_create_missing_domain(floor_case):
    pool, _, _ = floor_case
    source = SampleClock()
    source.domain = "test:unprovisioned-domain"
    with pytest.raises(ClockError, match="not been explicitly provisioned"):
        DurableClock(source, floor_pool=pool).read()
    with pool.connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM reference_clock_floor_v1 WHERE domain = %s", (source.domain,)
            ).fetchone()[0]
            == 0
        )


@pytest.fixture
def authority_case(floor_case):
    pool, source, clock = floor_case
    signer = Ed25519Signer("test:clock-authority")
    trust = TrustDirectory()
    trust.register_signer(signer)
    authority = TargetAuthority(signer, trust, revocation_epoch=lambda tenant: 0, clock=clock)
    target = TargetRef("test", "no-effect-fixture")
    permit = TargetPermit(
        tenant_id="synthetic-school",
        principal="instructor",
        mission="",
        budget_reservation="UNBUDGETED",
        budget_units=0,
        policy_version="test:1",
        decision_record_id="fixture",
        decision_record_hash="a" * 64,
        approval_ref="fixture",
        assertion_id="fixture",
        action_id="fixture",
        operation="test:clock-check",
        target_kind=target.kind,
        target_digest=target.digest(),
        expected_target_state="ABSENT",
        output_digest="b" * 64,
        qualification_digests=(),
        revocation_epoch=0,
        expires_at_us=1000,
        nonce=uuid.uuid4().hex,
        clock_domain=clock.domain,
        issued_at_us=100,
    )
    signed = SignedTargetPermit(permit, signer.sign(permit.signed_body()))
    authority.authenticate(
        signed, tenant_id="synthetic-school", target=target, operation="test:clock-check"
    )
    # Establish that the fixture is live before testing the new defense. There
    # is no target adapter and no write or other external effect in these tests.
    source.value = 200
    authority.current(signed, at_effect=True)
    assert authority.completed_before_expiry(signed) is True
    source.value = 199  # Still inside the permit window, but below the retained floor.
    return authority, signed, pool


def test_regressed_floor_refuses_completion_certificate(authority_case):
    authority, signed, _ = authority_case
    assert authority.completed_before_expiry(signed) is False


def test_regressed_floor_refuses_effect_entry(authority_case):
    authority, signed, _ = authority_case
    with pytest.raises(EmissionError, match="clock"):
        authority.current(signed, at_effect=True)


def test_locked_floor_timeout_does_not_sample_or_publish(floor_case):
    pool, source, clock = floor_case
    source.samples = [200]
    with pool.connection() as holder, holder.transaction():
        holder.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE",
            (source.domain,),
        ).fetchone()
        with pytest.raises(ClockError, match="unavailable"):
            clock.read()
        assert source.samples == [200]
        assert holder.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s",
            (source.domain,),
        ).fetchone()[0] == 100
    assert clock.read().now_us == 200


def test_exact_database_clock_missing_floor_refuses_without_creating_row(floor_case):
    pool, _, _ = floor_case
    with pool.connection() as connection:
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    source = DbClock(None, domain)
    with pytest.raises(ClockError, match="not been explicitly provisioned"):
        DurableClock(source, floor_pool=pool).read()
    with pool.connection() as connection:
        assert connection.execute(
            "SELECT count(*) FROM reference_clock_floor_v1 WHERE domain = %s", (domain,)
        ).fetchone()[0] == 0


def test_exact_database_clock_lock_timeout_retains_floor(floor_case):
    pool, _, _ = floor_case
    with pool.connection() as connection:
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    source = DbClock(None, domain)
    provision_floor(pool, source)
    with pool.connection() as holder, holder.transaction():
        floor = holder.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE",
            (domain,),
        ).fetchone()[0]
        with pytest.raises(ClockError, match="unavailable"):
            DurableClock(source, floor_pool=pool).read()
        assert holder.execute(
            "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s", (domain,)
        ).fetchone()[0] == floor
    assert DurableClock(source, floor_pool=pool).read().now_us >= floor


def test_database_clock_subclass_keeps_custom_read_semantics(floor_case):
    pool, _, _ = floor_case
    with pool.connection() as connection:
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]

    class CustomDatabaseClock(DbClock):
        def read_on(self, connection):
            raise ClockError("custom database clock refuses")

    provision_floor(pool, DbClock(None, domain))
    with pytest.raises(ClockError, match="custom database clock refuses"):
        DurableClock(CustomDatabaseClock(None, domain), floor_pool=pool).read()


def test_exact_database_clock_samples_after_waiting_for_floor_lock(floor_case):
    import time
    pool, _, _ = floor_case
    with pool.connection() as connection:
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    source = DbClock(None, domain)
    provision_floor(pool, source)
    with ThreadPoolExecutor(max_workers=1) as workers:
        with pool.connection() as holder, holder.transaction():
            holder.execute(
                "SELECT highwater_us FROM reference_clock_floor_v1 WHERE domain = %s FOR UPDATE",
                (domain,),
            ).fetchone()
            future = workers.submit(DurableClock(source, floor_pool=pool).read)
            deadline = time.monotonic() + 3
            with pool.connection() as observer:
                while not observer.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()"
                    " AND wait_event_type='Lock' AND query LIKE 'SELECT highwater_us, hold_at_us, hold_reason%')"
                ).fetchone()[0]:
                    assert time.monotonic() < deadline, "reader did not reach the held floor lock"
                    time.sleep(0.01)
            assert not future.done()
            before_release = source.read_on(holder).now_us
        reading = future.result(timeout=5)
    assert reading.now_us >= before_release
