"""Preventive exact-byte contracts with every receiving guard intact.

Filesystem cases use the qualified reference host and restricted local roles.
Database cases use synthetic signed permits and a connection sentinel: they
qualify refusal before I/O, not PostgreSQL transaction behavior. No authority
check is removed, replaced or weakened, and no peer probe code is imported.
"""
import os
from dataclasses import replace

import pytest

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core.signing import Ed25519Signer, TrustDirectory
from regulated_core.target import ABSENT, FilesystemTargetAdapter, Outcome, SignedTargetPermit, TargetRef
from test_receiving_signature_contracts import database_fixture, fixture_permit
from test_reference_host import render_request


def different_bytes(body, case):
    if case == "appended":
        return body + b"extra fixture text\n"
    if case == "truncated":
        return body[:-1]
    if case == "same-length":
        return bytes([body[0] ^ 1]) + body[1:]
    if case == "empty":
        return b""
    raise AssertionError(case)


CASES = ("appended", "truncated", "same-length", "empty", "authorized")


@pytest.mark.parametrize("case", CASES)
def test_filesystem_checks_exact_authorized_bytes_before_nonce_or_effect(tmp_path, case):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, report, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    _, authorization, target, body = render_request(host, tmp_path)
    assert authorization.authorized, authorization.reason
    signed = authorization.permit
    permit = signed.permit
    assert permit.qualification_digests == (report.digest(),)
    assert not stores.permits.used(permit.tenant_id, permit.nonce)
    if case != "authorized":
        result = target.commit(signed, different_bytes(body, case))
        assert result.outcome is Outcome.FAILED
        assert result.detail == "output does not match the authorized digest"
        assert target.current_state() == ABSENT and not target.path.exists()
        assert not (target.path.parent / ".commit-receipts").exists()
        assert not stores.permits.used(permit.tenant_id, permit.nonce)
    # The exact authorized bytes still commit with the same unspent permit.
    # This positive control also rules out an earlier blanket refusal.
    result = target.commit(signed, body)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert target.path.read_bytes() == body
    assert stores.permits.used(permit.tenant_id, permit.nonce)
    assert stores.recorder.verify_chain(permit.tenant_id)


@pytest.mark.parametrize("case", CASES)
def test_database_checks_exact_bytes_before_connection_or_effect(case):
    issuer = Ed25519Signer("synthetic:payload-contract-issuer")
    trust = TrustDirectory()
    trust.register_signer(issuer)
    receiver, ports = database_fixture((issuer, None, None, trust))
    permit = fixture_permit(receiver.target, receiver.operation)
    signed = SignedTargetPermit(permit, issuer.sign(permit.signed_body()))
    body = b"synthetic output"
    if case != "authorized":
        result = receiver.commit(signed, different_bytes(body, case))
        assert result.outcome is Outcome.FAILED
        assert result.detail == "database effect bytes differ from the permit"
        assert ports.calls == []
    # Authentic exact bytes reach the explicit sentinel, proving the refusal
    # cases passed signature validation and were checked at the payload gate.
    with pytest.raises(RuntimeError, match="synthetic connection boundary reached"):
        receiver.commit(signed, body)
    assert ports.calls == ["connection"]


@pytest.mark.parametrize("binding", ["kind", "address"])
def test_database_refuses_authentic_permit_for_another_target(binding):
    issuer = Ed25519Signer("synthetic:target-contract-issuer")
    trust = TrustDirectory()
    trust.register_signer(issuer)
    receiver, ports = database_fixture((issuer, None, None, trust))
    permit = fixture_permit(receiver.target, receiver.operation)
    other = TargetRef("synthetic:other-kind", "fixture-only") if binding == "kind" else TargetRef(
        receiver.target.kind, "synthetic:other-address",
    )
    other_permit = replace(permit, target_kind=other.kind, target_digest=other.digest())
    signed_other = SignedTargetPermit(other_permit, issuer.sign(other_permit.signed_body()))
    assert trust.verify(other_permit.signed_body(), signed_other.signature)
    result = receiver.commit(signed_other, b"synthetic output")
    assert result.outcome is Outcome.FAILED
    assert result.detail == "database permit authentication or target binding failed"
    assert ports.calls == []
    signed_here = SignedTargetPermit(permit, issuer.sign(permit.signed_body()))
    with pytest.raises(RuntimeError, match="synthetic connection boundary reached"):
        receiver.commit(signed_here, b"synthetic output")
    assert ports.calls == ["connection"]


@pytest.mark.parametrize("condition", ["current", "other-target", "changed-state"])
def test_filesystem_checks_target_and_state_before_nonce_or_effect(tmp_path, condition):
    from test_receiving_nonce_contracts import request_fixture

    _, stores, signed, target, body = request_fixture(tmp_path)
    receiving = target
    if condition == "other-target":
        receiving = FilesystemTargetAdapter(
            tmp_path / "other" / "draft.txt", target.tenant_id, target.authority,
            stores.permits, operation_name=target.operation,
        )
    elif condition == "changed-state":
        target.path.parent.mkdir(parents=True, exist_ok=True)
        target.path.write_bytes(b"Synthetic intervening revision.\n")
    before = receiving.current_state()
    result = receiving.commit(signed, body)
    if condition == "current":
        assert result.outcome is Outcome.COMMITTED, result.detail
        assert target.path.read_bytes() == body
        assert stores.permits.used(signed.permit.tenant_id, signed.permit.nonce)
    else:
        assert result.outcome is Outcome.FAILED
        assert result.detail == (
            "permit is for a different target" if condition == "other-target"
            else "target state changed since authorization"
        )
        assert receiving.current_state() == before
        assert not stores.permits.used(signed.permit.tenant_id, signed.permit.nonce)
        assert not (receiving.path.parent / ".commit-receipts").exists()
        if condition == "other-target":
            assert not receiving.path.exists() and not target.path.exists()
        else:
            assert target.path.read_bytes() == b"Synthetic intervening revision.\n"
    assert stores.recorder.verify_chain(signed.permit.tenant_id)


@pytest.mark.parametrize("condition", ["current", "changed-revision", "revoked-epoch"])
def test_database_rechecks_revision_and_epoch_before_effect(tmp_path, condition):
    from regulated_core.persistence_pg import PostgresRevocationLedger
    from test_delegated_draft import BODY, TENANTS, delegated_draft_fixture

    _, assemble, authorize = delegated_draft_fixture(tmp_path)
    tenant = TENANTS[0]
    authorization, _ = authorize(tenant, "alpha")
    assert authorization.status == "authorized", authorization
    signed = authorization.permit
    pool, clock, _, _, _, receiver, budget, _ = assemble(tenant)
    prior_body = b"Synthetic intervening database revision."
    if condition == "changed-revision":
        with pool.connection() as conn, conn.transaction():
            conn.execute("INSERT INTO reference_prepared_drafts_v1 VALUES (%s,%s,%s)",
                         (tenant, receiver.target.digest(), prior_body))
    elif condition == "revoked-epoch":
        epoch = PostgresRevocationLedger(pool=pool)
        assert epoch.epoch(tenant) == signed.permit.revocation_epoch
        epoch.revoke(tenant, actor="synthetic-host-operator",
                     reason="Synthetic revoke before delivery", now_us=clock.now_us())
        assert epoch.epoch(tenant) == signed.permit.revocation_epoch + 1
    result = receiver.commit(signed, BODY)
    with pool.connection() as conn:
        bodies = [bytes(row[0]) for row in conn.execute(
            "SELECT body FROM reference_prepared_drafts_v1 WHERE tenant=%s",
            (tenant,)).fetchall()]
        used = conn.execute(
            "SELECT count(*) FROM regulated_permit_uses_v1 WHERE tenant=%s AND nonce=%s",
            (tenant, signed.permit.nonce)).fetchone()[0]
        outcomes = [row[0] for row in conn.execute(
            "SELECT outcome FROM regulated_database_receipts_v1 WHERE tenant=%s AND nonce=%s",
            (tenant, signed.permit.nonce)).fetchall()]
    if condition == "current":
        assert result.outcome is Outcome.COMMITTED, result
        assert bodies == [BODY] and used == 1
        assert outcomes == [Outcome.COMMITTED.value]
        assert budget.committed(tenant, "one-draft") == 1
    else:
        assert result.outcome is Outcome.FAILED, result
        assert result.detail == (
            "database target revision changed" if condition == "changed-revision"
            else "permit revoked in durable tenant authority state"
        )
        assert bodies == ([prior_body] if condition == "changed-revision" else [])
        assert used == 0 and budget.committed(tenant, "one-draft") == 0
        # A failed durable attempt retains a terminal reconciliation receipt;
        # absence of an effect must not erase this required audit record.
        assert outcomes == [Outcome.NOT_COMMITTED.value]
