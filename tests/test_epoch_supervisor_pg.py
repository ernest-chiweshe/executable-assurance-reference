"""Ordinary authenticated local workflow, restricted roles and durable epoch receipt."""
import os
from dataclasses import fields

import pytest

from a16_supervisor_fixture import SupervisorWithdrawalFixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.role_contract import collect_access_matrix
from regulated_core.identity_provider import CredentialError
from regulated_core.permit import EmissionError
from regulated_core.target import Outcome


@pytest.fixture
def app():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        yield SupervisorWithdrawalFixture(roles)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()


def test_authenticated_supervisor_withdrawal_commits_once_and_receipt_survives_own_epoch(app):
    pending = app.begin()
    approved = app.approve(pending)
    assert approved.certificate.approver_ids == ("supervisor",)
    assert len(approved.credential_receipts) == 1
    authorized = app.authorize(pending, approved)
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    result = app.engine.commit(authorized, pending.output, app.target)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"] + 1
    receipt = (app.tenant, app.target.operation, authorized.permit.permit.nonce, pending.digest)
    assert app.ledger.receipt(*receipt) is Outcome.COMMITTED
    assert app.target.commit(authorized.permit, pending.output).outcome is Outcome.COMMITTED
    assert app.target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"] + 1
    assert app.budget.committed(app.tenant, authorized.permit.permit.mission) == 1
    assert app.recorder.verify_chain(app.tenant)


@pytest.mark.parametrize("reviewer", ["ordinary", "requester"])
def test_authenticated_non_supervisor_and_self_approval_refuse_without_epoch_effect(app, reviewer):
    pending = app.begin()
    expected = CredentialError if reviewer == "ordinary" else EmissionError
    match = "holds no" if reviewer == "ordinary" else "cannot approve"
    with pytest.raises(expected, match=match):
        app.approve(pending, reviewer)
    assert app.ledger.epoch(app.tenant) == pending.change["prior_epoch"]
    assert not app.uses.used(app.tenant, pending.params["nonce"])


def test_runtime_roles_match_explicit_receipt_and_review_privileges(app):
    report = collect_access_matrix(app.roles, partitioned_lifecycle=True)  # every schema is partitioned since 060
    assert report["privilege_contract_matches"], report["errors"]
