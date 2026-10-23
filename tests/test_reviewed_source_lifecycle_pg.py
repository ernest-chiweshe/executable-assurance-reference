"""Intact retained-source lifecycle on an explicitly provisioned local test cluster."""
from dataclasses import fields, replace
import os
import uuid

import pytest

from assurance_reference.local_roles import provision_local_roles
from assurance_reference.reviewed_evidence import RetainedEvidence, source_payload
from assurance_reference.reviewed_evidence_support import CurrentSnapshotVerifier, EvidenceUnavailable
from factory.packs.demonstration_checks import EvidenceSnapshot
from factory.packs.demonstrations import USES
from factory.pg_session import SessionBoundPool
from factory.projectos.regulated import EmissionContext
from regulated_core.models import Outcome
from regulated_core.signing import Ed25519Signer, TrustDirectory


@pytest.fixture(scope="module")
def roles():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "Explicit isolated local factory_test is required; no skipped qualification"
    configured = provision_local_roles(dsn)
    try:
        yield configured
    finally:
        for field in fields(configured):
            pool = getattr(configured, field.name)
            if callable(getattr(pool, "close", None)):
                pool.close()


@pytest.mark.parametrize("use", tuple(USES))
def test_retained_source_revision_and_withdrawal(roles, use):
    tenant = "synthetic-x25-" + uuid.uuid4().hex
    reviewer = Ed25519Signer("synthetic:x25-source-reviewer")
    trust = TrustDirectory()
    trust.register_signer(reviewer)
    source = RetainedEvidence(
        pool=SessionBoundPool(roles.receiver), trust=trust,
        authorities={use: frozenset({reviewer.key_id})},
    )
    with roles.receiver.connection() as conn:
        assert conn.execute("SELECT session_user").fetchone() == (roles.receiver.role,)
        assert conn.execute(
            "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user"
        ).fetchone() == (False, False)
        now = int(conn.execute(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint"
        ).fetchone()[0])
    snapshot = EvidenceSnapshot(
        tenant, "synthetic-case", "revision-1", "Fictional reviewed packet",
        (("fixture-source", "edition-1", "This is synthetic source material."),),
        (("fixture-source", "This is synthetic source material."),),
        ("Synthetic local contract; no professional qualification.",),
        now - 1_000_000, now + 60_000_000,
    )
    payload = source_payload(snapshot, use, 1)
    source.retain(payload, reviewer.sign(payload), expected_sequence=0)
    assert source.current(tenant, use, snapshot.case_id) == snapshot
    verifier = CurrentSnapshotVerifier(source, use)
    context = EmissionContext(tenant=tenant, actor_id="synthetic-reader",
                              now_us=now, nonce="synthetic-observation")
    assert verifier.verify_context(snapshot.render(), snapshot.contract(), context) == (Outcome.PASS, ())
    # Ordinary source revision supersedes the earlier rendered packet.
    revised = replace(snapshot, revision="revision-2")
    payload = source_payload(revised, use, 2)
    source.retain(payload, reviewer.sign(payload), expected_sequence=1)
    assert source.current(tenant, use, snapshot.case_id) == revised
    assert verifier.verify_context(snapshot.render(), snapshot.contract(), context) == (
        Outcome.FAIL, ("EVIDENCE_REVISION_MISMATCH",),
    )
    assert verifier.verify_context(revised.render(), revised.contract(), context) == (Outcome.PASS, ())
    # Synthetic observation of the exact exclusive expiry boundary.
    expired = replace(context, now_us=revised.valid_until_us)
    assert verifier.verify_context(revised.render(), revised.contract(), expired) == (
        Outcome.FAIL, ("SOURCE_OUTSIDE_REVIEW_WINDOW",),
    )
    withdrawal = source_payload(revised, use, 3, withdrawn=True)
    source.retain(withdrawal, reviewer.sign(withdrawal), expected_sequence=2)
    with pytest.raises(EvidenceUnavailable, match="withdrew"):
        source.current(tenant, use, revised.case_id)
    assert verifier.verify_context(revised.render(), revised.contract(), context) == (
        Outcome.FAIL, ("HOST_EVIDENCE_UNAVAILABLE",),
    )
    # A retained withdrawal is an ordinary later version, not deletion of history.
    with roles.receiver.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
        versions = conn.execute(
            "SELECT version FROM regulated_reviews_v1 WHERE tenant=%s AND review_id=%s ORDER BY version",
            (tenant, source._id(tenant, use, revised.case_id)),
        ).fetchall()
    assert versions == [(0,), (1,), (2,)]
