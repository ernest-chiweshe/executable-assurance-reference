"""I-6 on every application path: Education, Health and the product vertical decide inside the per-tenant lane.

Each application's public ``authorize_release`` reaches ``ReferenceEngine.authorize_for_target``, which opens
``locked_decision_transaction``: it takes the tenant's evidence lock and only then samples decision time. Here an
ordinary concurrent holder owns that tenant's lane; the application's release waits on that exact lock key (not on
anything else), and once the lane is released the recorded decision time is at or after the release, so a race can
never record an earlier timestamp after a later one. The delegated intake lane has its own contract
(test_intake_lane_serialization_pg.py).

On the same three paths, after that lawful decision: the application's own recorder refuses a record stamped before
its durable evidence head, and a clock sample below the durable floor this application's decisions advanced is
refused on its own floor row (an ordinary regressing source of the same domain). Fictional data; isolated PostgreSQL;
actual restricted logins; guards unchanged.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import time

import psycopg
import pytest

from assurance_reference.clock_floor import DurableClock
from regulated_core.clock import ClockError, ClockReading
from regulated_core.models import Decision

from assurance_reference.engine import ReferenceEngine
from factory.projectos.governed_release import PREPARATION_FIELD
from factory.tenant import TenantContext
from regulated_core.models import Actor
from test_clinical_finalisation import clinical, roles  # noqa: F401
from test_education_session_release import education, reviewed_context  # noqa: F401
from test_product_spec_authority import approve, product  # noqa: F401

LANE = "regulated-evidence-v1:"
OBSERVE_S = 20  # Well inside every lock and statement timeout on these paths.


def _waiters(conn, tenant):
    return conn.execute(
        "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objsubid=1"
        " AND ((classid::bigint << 32) | objid::bigint) = hashtextextended(%s,0)", (LANE + tenant,)).fetchone()[0]


def _decides_in_the_lane(gate, tenant, release):
    engine = gate._engine
    assert isinstance(engine, ReferenceEngine)  # authorize_for_target opens locked_decision_transaction.
    clock = engine._recorder.clock
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    with ThreadPoolExecutor(max_workers=1) as worker, psycopg.connect(dsn, autocommit=True) as observer,             psycopg.connect(dsn) as holder:
        with holder.transaction():  # An ordinary concurrent decision holding this tenant's lane.
            holder.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (LANE + tenant,))
            pending = worker.submit(release)
            deadline = time.monotonic() + OBSERVE_S
            while _waiters(observer, tenant) != 1:
                assert not pending.done(), pending.result()
                assert time.monotonic() < deadline, "the release never waited on its tenant's lane"
                time.sleep(0.05)
            released_at = clock.now_us()
        # Leaving the holder's transaction (also on any failure above) releases the lane.
        decision = pending.result(timeout=60)
    assert decision.allowed, decision.reason
    record = decision.permit.envelope.record
    assert record.decided_at_us >= released_at, (record.decided_at_us, released_at)
    times = [entry.record.decided_at_us for entry in engine._recorder.entries(tenant)]
    assert times == sorted(times) and engine._recorder.verify_chain(tenant)
    _refuses_backdating_and_regression(engine, decision.permit, tenant)


class _RegressedSource:
    """An ordinary connection-bound clock source of the application's domain whose sample is behind the floor."""

    def __init__(self, domain, now_us):
        self.domain, self._now = domain, now_us

    def read(self):
        return ClockReading(self.domain, self._now)

    def read_on(self, connection):
        return self.read()

    def now_us(self):
        return self._now


def _refuses_backdating_and_regression(engine, authorization, tenant):
    recorder, clock = engine._recorder, engine._recorder.clock
    assert isinstance(clock, DurableClock) and engine.targets.clock is clock  # One floor-bound authority clock.
    head = recorder.entries(tenant)[-1]
    count = len(recorder.entries(tenant))
    backdated = replace(authorization.ctx, now_us=head.record.decided_at_us - 1)
    with pytest.raises(ClockError):
        recorder.record(authorization.assertion, authorization.action, backdated, authorization.policy,
                        Decision.deny("SYNTHETIC_BACKDATED", "a record stamped before the durable head"))
    assert len(recorder.entries(tenant)) == count and recorder.verify_chain(tenant)
    floor = clock.now_us()  # Advances and returns this application's durable floor.
    regressed = DurableClock(_RegressedSource(clock.domain, floor - 1), floor_pool=clock.floor_pool)
    with pytest.raises(ClockError, match="regressed below the durable floor"):
        regressed.read()
    assert clock.now_us() >= floor


def test_education_release_decides_inside_the_tenant_lane(education):  # noqa: F811
    app = education
    approved = reviewed_context(app)
    gate = app.gates["requester"]
    _decides_in_the_lane(gate, "school-a", lambda: gate.authorize_release(
        spec=app.spec, contract=app.contract, out_path=str(app.path),
        context=replace(approved, now_us=app.clock.now_us()), artifact=app.body))


def test_health_release_decides_inside_the_tenant_lane(clinical):  # noqa: F811
    c = clinical
    gate = c.finaliser._gate
    record, context, contract, content = c.finaliser._prepare_finalisation(c.session, c.document, c.clinician)
    certificate = gate.request_approval(
        contract, context, (Actor(c.clinician.user_id, c.finaliser._workspace, frozenset({"clinician"})),))
    approved = replace(context, approval=certificate, now_us=c.finaliser._now_us())
    _decides_in_the_lane(gate, approved.tenant, lambda: gate.authorize_release(
        spec=c.finaliser._spec, contract=contract, out_path=c.finaliser._target(record), context=approved,
        artifact=content))


def test_product_release_decides_inside_the_tenant_lane(product):  # noqa: F811
    c = product
    gate = c.gates["requester"]
    approved = approve(c)
    contract = c.engine.governed_contract("inventory", tenant=c.tenant, context=c.context)
    stored = c.state.load("inventory")[PREPARATION_FIELD]
    body = c.engine._artifact_store.get(TenantContext(tenant_id=c.tenant, display_name=c.tenant),
                                        stored["artifact_address"])
    _decides_in_the_lane(gate, c.tenant, lambda: gate.authorize_release(
        spec=c.spec, contract=contract, out_path=str(c.path),
        context=replace(approved, now_us=c.clock.now_us()), artifact=body))
