"""R-2b stage 4: a database restore that reopens a nonce row cannot reopen a filesystem effect.

The adapter's on-disk receipts survive the restore; any receipt for the nonce decides, so a replay of a permit whose
nonce row was lost gets the recorded outcome and no second effect (A -> B -> A: the target is back in the permit's
expected state). The lost nonce row is emulated as a restore writes rows: triggers bypassed.
"""
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.target import FilesystemTargetAdapter, Outcome
from test_a19_permit_expiry_isolated_pg import _short_lived_permit


def _lose_nonce_row(roles, tenant, nonce):
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(roles.schema)))
        admin.execute("SET session_replication_role = replica")
        deleted = admin.execute("DELETE FROM regulated_permit_uses_v1 WHERE tenant = %s AND nonce = %s"
                                " RETURNING nonce", (tenant, nonce)).fetchall()
        assert deleted == [(nonce,)]


def test_replay_after_a_lost_nonce_row_has_no_second_effect(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    signed, target, body = _short_lived_permit(host, tmp_path)
    permit = signed.permit
    receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                        PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation,
                                        budget=target.budget)
    first = receiving.commit(signed, body)
    assert first.outcome is Outcome.COMMITTED, first
    # The target goes back to the permit's expected state (A -> B -> A) and a restore loses the nonce row.
    receiving.path.unlink()
    _lose_nonce_row(roles, permit.tenant_id, permit.nonce)
    assert not stores.permits.used(permit.tenant_id, permit.nonce)
    replay = receiving.commit(signed, body)
    assert replay.outcome is not Outcome.FAILED or "already handled" in replay.detail, replay
    assert not receiving.path.exists(), "a second effect was produced"


@pytest.mark.parametrize("kind", ["prepared", "aborted", "certificate"])
def test_any_single_receipt_kind_blocks_a_replay_after_a_lost_nonce_row(tmp_path, kind):
    # The first attempt stopped after writing only this receipt kind; the restore then lost the nonce row. The
    # adapter's own writer produces the receipt; its body is the genuine prepared record of this permit.
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    signed, target, body = _short_lived_permit(host, tmp_path)
    permit = signed.permit
    receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                        PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation,
                                        budget=target.budget)
    assert receiving.commit(signed, body).outcome is Outcome.COMMITTED
    prepared = {k: v for k, v in receiving._read_receipt(permit.nonce, "prepared").items() if k != "kind"}
    receiving.path.unlink()
    for path in receiving._receipts().glob(receiving._receipt_path(permit.nonce, "x").name.split(".")[0] + ".*"):
        path.unlink()
    receiving._write_receipt(permit.nonce, kind, prepared)
    _lose_nonce_row(roles, permit.tenant_id, permit.nonce)
    replay = receiving.commit(signed, body)
    assert replay.outcome is not Outcome.COMMITTED, replay
    assert not receiving.path.exists(), "a second effect was produced"
