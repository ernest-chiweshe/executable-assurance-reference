"""Bounded ordinary application traffic with intact retention/reconcile guards.

No connections are artificially held to force a wait cycle. Observed occupancy
is diagnostic; this is not a universal saturation or deadlock-freedom proof.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import fields, replace
import os
from threading import Barrier, Lock
import time

from a16_supervisor_fixture import SupervisorWithdrawalFixture
from assurance_reference.epoch_withdrawal_retention import retain_approved_withdrawal
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from regulated_core.target import Outcome
from test_education_session_release import approved_request


def test_concurrent_retention_reconcile_and_ordinary_education_delivery(tmp_path, monkeypatch, record_property):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        education = build_education_fixture(roles, tmp_path)
        governance = SupervisorWithdrawalFixture(
            roles, "school-a", shared_ledger=education.stores.revocation,
            shared_recorder=education.stores.recorder, principal_prefix="epoch-")
        reconciliation = []
        retained = []
        for _ in range(4):
            pending = governance.begin()
            reconciliation.append((pending, governance.authorize(pending, governance.approve(pending))))
            review = governance.begin()
            retained.append((review, governance.approve(review)))
        # The fixture context predates the new governance evidence above.
        # Start a fresh ordinary request at current authority time.
        education.context = replace(education.context, now_us=education.clock.now_us())
        context, decision = approved_request(education)
        barrier, counts_lock = Barrier(9), Lock()
        active = {"receiver": 0, "governor": 0}
        peak = dict(active)
        connection = LocalPool.connection

        @contextmanager
        def observed(pool):
            role = ("receiver" if pool is roles.receiver else
                    "governor" if pool is roles.governor else None)
            with connection(pool) as current:
                if role:
                    with counts_lock:
                        active[role] += 1
                        peak[role] = max(peak[role], active[role])
                try:
                    yield current
                finally:
                    if role:
                        with counts_lock:
                            active[role] -= 1

        # Observe actual leases only; no guard, SQL, timeout or ordering replaced.
        monkeypatch.setattr(LocalPool, "connection", observed)

        def work(item):
            kind, index = item
            barrier.wait(timeout=15)
            if kind == "retain":
                pending, approved = retained[index]
                return retain_approved_withdrawal(
                    governance.loader, tenant_id=governance.tenant,
                    change=pending.change, requester_id=governance.requester,
                    approved=approved)
            if kind == "reconcile":
                return governance.target.reconcile(reconciliation[index][1].permit).outcome
            return education.gates["requester"].commit_release(
                spec=education.spec, contract=education.contract, decision=decision,
                artifact=education.body, out_path=str(education.path), context=context).state

        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=9) as workers:
            jobs = [("retain", i) for i in range(4)] + [("reconcile", i) for i in range(4)] + [("deliver", 0)]
            results = list(workers.map(work, jobs, timeout=20))
        assert time.monotonic() - started < 20
        assert results == [item.review_id for item, _ in retained] + [Outcome.NOT_COMMITTED] * 4 + ["committed"]
        assert education.path.read_bytes() == education.body
        assert governance.ledger.epoch(governance.tenant) == pending.change["prior_epoch"]
        for _, authorized in reconciliation:
            assert not governance.uses.used(governance.tenant, authorized.permit.permit.nonce)
            assert governance.budget.committed(governance.tenant, authorized.permit.permit.mission) == 0
        assert governance.recorder.verify_chain(governance.tenant)
        assert active == {"receiver": 0, "governor": 0}
        assert roles.receiver._pool.max_size == roles.governor._pool.max_size == 3
        assert 1 <= peak["receiver"] <= 3 and 1 <= peak["governor"] <= 3
        record_property("observed_peak_receiver_leases", peak["receiver"])
        record_property("observed_peak_governor_leases", peak["governor"])
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
