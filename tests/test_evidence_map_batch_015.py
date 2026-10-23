"""Intact PostgreSQL contracts for bounded map writes and authenticated readback."""
import os
from contextlib import contextmanager
from hashlib import sha256
from uuid import uuid4

import psycopg
import pytest

from regulated_core.evidence_map import EMPTY, MapNode, MemorySparseMap, node_digest
from regulated_core.evidence_service import EvidenceError
from regulated_core.evidence_service_pg import MAP_SCHEMA, MapBatch, insert_map_batch_on, read_map_proof_on
from regulated_core.persistence_pg import SCHEMA


@pytest.fixture(scope="module")
def database():
    assert os.environ.get("REFERENCE_ISOLATED_PG_DATA")
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    with psycopg.connect(dsn) as conn:
        name, port = conn.execute("SELECT current_database(),inet_server_port()").fetchone()
        assert name == "factory_test" and port == int(os.environ["REFERENCE_ISOLATED_PG_PORT"])
        conn.execute(SCHEMA)
        conn.execute(MAP_SCHEMA)
        conn.execute("CREATE ROLE evidence_batch015_writer NOLOGIN NOSUPERUSER NOBYPASSRLS")
        conn.execute("GRANT SELECT,INSERT ON regulated_evidence_map_v2,regulated_evidence_keys_v1 TO evidence_batch015_writer")
    return dsn


@contextmanager
def transaction(database, tenant):
    with psycopg.connect(database) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL ROLE evidence_batch015_writer")
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            yield conn


def leaves(count):
    nodes = [MapNode(key=sha256(str(i).encode()).digest(), value=b"batch015") for i in range(count)]
    return tuple((node_digest(n), n) for n in nodes)


def test_multiple_chunks_identical_conflicts_and_exact_proofs(database):
    tenant = "batch015-equivalence-" + uuid4().hex
    memory = MemorySparseMap()
    keys = [sha256(str(i).encode()).digest() for i in range(130)]
    for key in keys:
        memory.update(key, b"batch015")
    batch = MapBatch(tenant, 1, memory.root, tuple(memory._nodes.items()), ())
    assert len(batch.nodes) > 256
    with transaction(database, tenant) as conn:
        insert_map_batch_on(conn, batch)
        # All writes now conflict, but every stored node must still be read back.
        insert_map_batch_on(conn, batch)
        for key in keys[::17] + [b"z" * 32]:
            assert read_map_proof_on(conn, tenant=tenant, tree_size=1, root=batch.root, key=key) == memory.prove(key)
        assert conn.execute("SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s", (tenant,)).fetchone()[0] == len(batch.nodes)


def test_later_chunk_conflicting_bytes_fail_and_outer_transaction_rolls_back(database):
    tenant = "batch015-conflict-" + uuid4().hex
    nodes = leaves(300)
    digest, wanted = nodes[-1]
    with transaction(database, tenant) as conn:
        # Valid database shape, invalid content address: detached storage fixture.
        conn.execute("INSERT INTO regulated_evidence_map_v2 VALUES(%s,%s,'leaf',NULL,NULL,%s,%s)",
                     (tenant, digest, wanted.key, b"different"))
    with pytest.raises(EvidenceError, match="digest mismatch"):
        with transaction(database, tenant) as conn:
            insert_map_batch_on(conn, MapBatch(tenant, 1, EMPTY[0], nodes, ()))
    with transaction(database, tenant) as conn:
        rows = conn.execute("SELECT hash,value FROM regulated_evidence_map_v2 WHERE tenant=%s", (tenant,)).fetchall()
        assert [(bytes(h), bytes(v)) for h, v in rows] == [(digest, b"different")]


def test_batch_tenant_guard_and_same_digest_other_tenant_stay_isolated(database):
    tenant = "batch015-scope-" + uuid4().hex
    nodes = leaves(300)
    with transaction(database, tenant) as conn:
        insert_map_batch_on(conn, MapBatch(tenant, 1, EMPTY[0], nodes, ()))
    other = "other-" + tenant
    with transaction(database, other) as conn:
        with pytest.raises(EvidenceError, match="scope mismatch"):
            insert_map_batch_on(conn, MapBatch(tenant, 1, EMPTY[0], nodes, ()))
        assert conn.execute("SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s", (tenant,)).fetchone()[0] == 0
        insert_map_batch_on(conn, MapBatch(other, 1, EMPTY[0], nodes, ()))
        assert conn.execute("SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s", (other,)).fetchone()[0] == 300


def test_invalid_staged_digest_refused_before_any_batch_write(database):
    tenant = "batch015-invalid-" + uuid4().hex
    nodes = leaves(300)
    bad = nodes[:-1] + ((b"x" * 32, nodes[-1][1]),)
    with transaction(database, tenant) as conn:
        with pytest.raises(EvidenceError, match="invalid staged node"):
            insert_map_batch_on(conn, MapBatch(tenant, 1, EMPTY[0], bad, ()))
        assert conn.execute("SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s", (tenant,)).fetchone()[0] == 0
