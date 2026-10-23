"""I-6 intake lane in isolation: one per-tenant lane serializes timestamp-producing admissions.

The first admission is paused inside its trusted admission callback (which reads the chain, stamps inputs and
issues the admission). A second admission for the same tenant cannot enter its callback until the first leaves
the lane, and waits on the lane's own advisory lock; another tenant's admission is not delayed. The race outcome is
therefore ordering, not a budget refusal: both admissions run, in lane order, and every recorded decision of the
tenant keeps a non-decreasing decision time. Actual reviewed roots and children; isolated PostgreSQL.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import Event, current_thread
import time

import test_delegated_draft as delegated
from test_root_admission import TENANTS

# The production lane lock waits at most 30 s (delegated_draft lock_timeout) and then fails closed as UNKNOWN. The
# test observes while the first admission is held and releases it within OBSERVE_S, inside that unchanged deadline.
# The paused callback's own hold (HOLD_S) outlasts the observation, so it never lapses before the release.
LANE_LOCK_TIMEOUT_S, OBSERVE_S = 30, 20
HOLD_S = 120
assert OBSERVE_S < LANE_LOCK_TIMEOUT_S < HOLD_S


def _waiting_on_lane(pool, tenant):
    """Sessions waiting for exactly this tenant's intake-lane key (a bigint advisory lock: classid high word,
    objid low word, objsubid 1)."""
    with pool.connection() as conn:
        return conn.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objsubid=1"
            " AND ((classid::bigint << 32) | objid::bigint) = hashtextextended(%s,0)",
            ("reference-delegated-intake:" + tenant,)).fetchone()[0]


def test_same_tenant_admissions_serialize_and_other_tenants_proceed(tmp_path, monkeypatch):
    f, assemble, authorize = delegated.delegated_draft_fixture(tmp_path)
    entered, first_in, release = [], Event(), Event()

    class PausingAuthority(delegated.DelegationAuthority):
        def resolve(self, tenant_id, *args, **kwargs):
            entered.append((tenant_id, current_thread().name))
            if len(entered) == 1:
                first_in.set()
                assert release.wait(HOLD_S)
            return super().resolve(tenant_id, *args, **kwargs)

    monkeypatch.setattr(delegated, "DelegationAuthority", PausingAuthority)
    pool = assemble(TENANTS[0])[0]
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="intake") as workers:
        first = workers.submit(authorize, TENANTS[0], "alpha")
        assert first_in.wait(30)
        second = workers.submit(authorize, TENANTS[0], "beta")
        other = workers.submit(authorize, TENANTS[1], "alpha")
        try:
            # While the first admission holds tenant 0's lane: the same-tenant admission waits on that lane key (not
            # in its callback), and the other tenant's admission enters its own callback, undelayed. Release as soon
            # as both are observed, so the waiter is never held near the production lane deadline.
            deadline = time.monotonic() + OBSERVE_S
            while _waiting_on_lane(pool, TENANTS[0]) != 1 or len(entered) < 2:
                assert time.monotonic() < deadline, ("lane state not observed while held", entered)
                time.sleep(0.05)
            assert [tenant for tenant, _ in entered] == [TENANTS[0], TENANTS[1]], entered
            assert _waiting_on_lane(pool, TENANTS[1]) == 0  # The other tenant's lane has no waiter.
        finally:
            release.set()
        first_result, second_result = first.result(timeout=60), second.result(timeout=60)
        other_result = other.result(timeout=60)
    assert [tenant for tenant, _ in entered] == [TENANTS[0], TENANTS[1], TENANTS[0]]
    assert first_result[0].status == "authorized", first_result[0].detail
    assert other_result[0].status == "authorized", other_result[0].detail
    assert second_result[0].status in {"authorized", "refused"}
    _, clock, _, recorder, *_ = assemble(TENANTS[0])
    times = [entry.record.decided_at_us for entry in recorder.entries(TENANTS[0])]
    assert times == sorted(times)
    assert recorder.verify_chain(TENANTS[0])
