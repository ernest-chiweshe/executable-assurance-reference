"""A15 named interruption points inside the filesystem receiving adapter; intact guards, live PostgreSQL stores.

A process crash is simulated by a non-recoverable exception raised at exactly one named point of a normal
adapter; the guards themselves are unchanged. After each crash a fresh adapter resolves the outcome from receipts
and file identity alone (never by resending), and the spent nonce refuses any retry, so there is never a second
effect. Fictional request; isolated cluster.
"""
import pytest

from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.target import FilesystemTargetAdapter, Outcome
from test_receiving_nonce_contracts import request_fixture


class Crash(BaseException):
    """Stands in for process death at a named point; deliberately not an Exception the adapter could handle."""


def _adapter(roles, target, cls=FilesystemTargetAdapter, **extra):
    return cls(target.path, target.tenant_id, target.authority, PostgresPermitUseStore(pool=roles.receiver),
               operation_name=target.operation, budget=target.budget, **extra)


class AfterClaimBeforeStage(FilesystemTargetAdapter):
    def _write(self, signed, output):
        raise Crash("after-claim-before-stage")


class AfterRenameBeforeCommittedReceipt(FilesystemTargetAdapter):
    def _committed(self, p, before_expiry):
        raise Crash("after-rename-before-committed-receipt")


def _crash_before_rename():
    raise Crash("after-prepared-before-rename")


@pytest.mark.parametrize("point", ["after-claim-before-stage", "after-prepared-before-rename"])
def test_crash_before_the_effect_never_resolves_committed_and_retry_is_refused(tmp_path, point):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    if point == "after-claim-before-stage":
        crashing = _adapter(roles, target, AfterClaimBeforeStage)
    else:
        crashing = _adapter(roles, target, effect_check=_crash_before_rename)
    with pytest.raises(Crash, match=point):
        crashing.commit(signed, body)
    assert not target.path.exists()
    recovered = _adapter(roles, target)
    status = recovered.status(signed)
    if point == "after-claim-before-stage":
        assert status.outcome is Outcome.NOT_COMMITTED
    else:
        # A prepared receipt without the rename is never guessed: UNKNOWN until the authorised procedure resolves it.
        assert status.outcome is Outcome.UNKNOWN and "prepared but not proven committed" in status.detail
    retry = recovered.commit(signed, body)
    assert retry.outcome is Outcome.FAILED and retry.detail == "permit already used (single-use)"
    assert not target.path.exists()


def test_crash_after_the_effect_before_its_receipt_resolves_committed_by_file_identity(tmp_path):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    with pytest.raises(Crash, match="after-rename-before-committed-receipt"):
        _adapter(roles, target, AfterRenameBeforeCommittedReceipt).commit(signed, body)
    assert target.path.read_bytes() == body
    recovered = _adapter(roles, target)
    assert recovered.status(signed).outcome is Outcome.COMMITTED
    before = target.path.stat().st_mtime_ns
    assert recovered.commit(signed, body).outcome is Outcome.FAILED
    assert target.path.read_bytes() == body and target.path.stat().st_mtime_ns == before


def test_lost_acknowledgement_after_commit_is_unknown_then_resolved_by_receipt(tmp_path):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    lost = _adapter(roles, target, fail_after_write=True).commit(signed, body)
    assert lost.outcome is Outcome.UNKNOWN and "acknowledgement lost" in lost.detail
    recovered = _adapter(roles, target)
    assert recovered.status(signed).outcome is Outcome.COMMITTED
    before = target.path.stat().st_mtime_ns
    assert recovered.commit(signed, body).outcome is Outcome.FAILED
    assert target.path.stat().st_mtime_ns == before
