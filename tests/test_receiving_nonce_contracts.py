"""Preventive single-use receiving contracts with intact guards and live stores.

The spent-claim case sets up an explicit synthetic claim through the public
store API. It never erases a target, receipt, nonce or guard. Concurrency uses
two normal adapters for one path; counting delegates to the original writer.
These cases do not qualify restored database targets or cross-process races.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from threading import Barrier

import pytest

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.target import ABSENT, FilesystemTargetAdapter, Outcome
from test_reference_host import render_request


def request_fixture(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, report, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    _, authorization, target, body = render_request(host, tmp_path)
    assert authorization.authorized, authorization.reason
    assert authorization.permit.permit.qualification_digests == (report.digest(),)
    return roles, stores, authorization.permit, target, body


@pytest.mark.parametrize("prior_claim", [False, True], ids=["unused", "synthetic-spent"])
def test_receiving_nonce_claim_survives_reopened_store_before_any_effect(tmp_path, prior_claim):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    permit = signed.permit
    if prior_claim:
        stores.permits.consume(permit.tenant_id, permit.nonce)
    reopened = PostgresPermitUseStore(pool=roles.receiver)
    assert reopened.used(permit.tenant_id, permit.nonce) is prior_claim
    receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority, reopened,
                                        operation_name=target.operation, budget=target.budget)
    # All signature, preparation, clock, epoch and exact-output checks pass.
    receiving.authority.verify(signed, body, tenant_id=receiving.tenant_id,
        target=receiving.target, operation=receiving.operation, current_target_state=ABSENT)
    result = receiving.commit(signed, body)
    if prior_claim:
        assert result.outcome is Outcome.FAILED
        assert result.detail == "permit already used (single-use)"
        assert receiving.current_state() == ABSENT and not receiving.path.exists()
        assert not (receiving.path.parent / ".commit-receipts").exists()
    else:
        assert result.outcome is Outcome.COMMITTED, result.detail
        assert receiving.path.read_bytes() == body
    assert reopened.used(permit.tenant_id, permit.nonce)
    assert stores.recorder.verify_chain(permit.tenant_id)


def test_two_normal_receivers_share_one_nonce_and_perform_one_write(tmp_path):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    writes, start = [], Barrier(2)

    class CountedReceiver(FilesystemTargetAdapter):
        def _write(self, signed, output):
            writes.append(signed.permit.nonce)
            return super()._write(signed, output)

    receivers = [CountedReceiver(target.path, target.tenant_id, target.authority,
        PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation, budget=target.budget) for _ in range(2)]

    def commit(receiver):
        start.wait(timeout=15)
        return receiver.commit(signed, body)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(commit, receivers))
    assert sum(result.outcome is Outcome.COMMITTED for result in results) == 1
    assert sum(result.outcome is Outcome.FAILED for result in results) == 1
    assert writes == [signed.permit.nonce]
    assert target.path.read_bytes() == body
    assert stores.permits.used(signed.permit.tenant_id, signed.permit.nonce)
    assert stores.recorder.verify_chain(signed.permit.tenant_id)
