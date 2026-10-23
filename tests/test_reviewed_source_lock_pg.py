"""Intact source-lock serialization using ordinary signed synthetic revisions."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
import os
from queue import Queue
import time
import uuid

import pytest

from assurance_reference.local_roles import provision_local_roles
from assurance_reference.reviewed_evidence import RetainedEvidence, source_payload
from factory.packs.demonstration_checks import EvidenceSnapshot
from factory.packs.demonstrations import USES
from factory.pg_session import SessionBoundPool
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
def test_ordinary_source_revision_waits_for_existing_reader_guard(roles, use):
    tenant = "synthetic-x25-lock-" + uuid.uuid4().hex
    reviewer = Ed25519Signer("synthetic:x25-lock-reviewer")
    trust = TrustDirectory()
    trust.register_signer(reviewer)
    pool = SessionBoundPool(roles.receiver)
    source = RetainedEvidence(
        pool=pool, trust=trust, authorities={use: frozenset({reviewer.key_id})})
    snapshot = EvidenceSnapshot(
        tenant, "synthetic-lock-case", "revision-1", "Fictional reviewed packet",
        (("fixture-source", "edition-1", "Synthetic source material."),),
        (("fixture-source", "Synthetic source material."),),
        ("Synthetic lock observation; no professional qualification.",),
        1_000_000, 2_000_000,
    )
    original = source_payload(snapshot, use, 1)
    source.retain(original, reviewer.sign(original), expected_sequence=0)
    revised = replace(snapshot, revision="revision-2")
    next_payload = source_payload(revised, use, 2)
    next_signature = reviewer.sign(next_payload)
    writer_pid = Queue()

    def retain_revision():
        with pool.session() as connection:
            # Bound a failed test's lock wait; settings reset by the existing pool.
            connection.execute("SET lock_timeout = '10s'")
            connection.execute("SET statement_timeout = '12s'")
            writer_pid.put(connection.execute("SELECT pg_backend_pid()").fetchone()[0])
            source.retain(next_payload, next_signature, expected_sequence=1)

    # Separate thread means a distinct physical session in the unchanged adapter.
    with ThreadPoolExecutor(max_workers=1) as executor:
        with pool.session() as reader:
            with source.guard(tenant, use, snapshot.case_id):
                assert source.current(tenant, use, snapshot.case_id) == snapshot
                future = executor.submit(retain_revision)
                pid = writer_pid.get(timeout=5)
                deadline = time.monotonic() + 5
                waiting = False
                while time.monotonic() < deadline:
                    waiting = reader.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_locks "
                        "WHERE pid=%s AND locktype='advisory' AND NOT granted)", (pid,)
                    ).fetchone()[0]
                    if waiting or future.done():
                        break
                    time.sleep(0.02)
                assert waiting, "No observed advisory-lock wait for the ordinary writer"
                assert not future.done()
                assert source.current(tenant, use, snapshot.case_id) == snapshot
            # The real guard exits normally; only then may the real writer commit.
            future.result(timeout=10)
            assert source.current(tenant, use, snapshot.case_id) == revised
            assert reader.execute(
                "SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() "
                "AND locktype='advisory'"
            ).fetchone() == (0,)
