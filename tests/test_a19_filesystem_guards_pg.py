"""A19 intact guard contracts on the filesystem receiving boundary (revocation, mandatory signed path).

The reference host issues a genuine permit for a fictional request; the shared receiving authority then refuses it
at the target when the tenant's revocation epoch has moved and when the permit is not the authority's signature.
No effect, no nonce claim. Guards unchanged; the revocation is recorded by the governor login, the runtime holder
of that grant. Filesystem expiry is evidenced by test_education_faults (ordinary elapsed time). Isolated PostgreSQL.
"""
from regulated_core.persistence_pg import PostgresPermitUseStore, PostgresRevocationLedger
from regulated_core.signing import Signature
from regulated_core.target import FilesystemTargetAdapter, Outcome, SignedTargetPermit
from test_receiving_nonce_contracts import request_fixture


def _receiver(roles, target):
    return FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                   PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation,
                                   budget=target.budget)


def test_revoked_tenant_epoch_refuses_at_the_filesystem_target(tmp_path):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    ledger = PostgresRevocationLedger(pool=roles.governor)
    assert ledger.epoch(target.tenant_id) == signed.permit.revocation_epoch
    ledger.revoke(target.tenant_id, actor="synthetic-operator", reason="Synthetic revocation before delivery",
                  now_us=target.authority.clock.now_us())
    result = _receiver(roles, target).commit(signed, body)
    assert result.outcome is Outcome.FAILED and "revoked" in result.detail, result
    assert not target.path.exists() and not stores.permits.used(signed.permit.tenant_id, signed.permit.nonce)


def test_forged_permit_never_reaches_the_filesystem_effect(tmp_path):
    roles, stores, signed, target, body = request_fixture(tmp_path)
    forged = SignedTargetPermit(signed.permit, Signature(signed.signature.key_id, "AAAA", signed.signature.alg))
    result = _receiver(roles, target).commit(forged, body)
    assert result.outcome is Outcome.FAILED and "signature" in result.detail, result
    assert not target.path.exists() and not stores.permits.used(signed.permit.tenant_id, signed.permit.nonce)
