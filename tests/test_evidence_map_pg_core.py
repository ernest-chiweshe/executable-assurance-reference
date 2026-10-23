"""Real isolated PostgreSQL map contracts; no application caller migration."""
import json
import os
from contextlib import contextmanager
from hashlib import sha256
from uuid import uuid4

import psycopg
import pytest

from regulated_core.evidence_map import MemorySparseMap, key_digest, EMPTY, MapNode, node_digest
from regulated_core.evidence_service import EvidenceError, KeySummary, occurrence_bytes
from regulated_core.evidence_service_pg import (
    MAP_SCHEMA, MAP_PROOF_SQL, KEY_VALUE_SQL, insert_map_batch_on, proof_prefixes,
    read_map_proof_on, stage_map_update_on,
)
from regulated_core.merkle import MemoryMerkleLog
from regulated_core.persistence_pg import SCHEMA


@pytest.fixture(scope="module")
def database():
    assert os.environ.get("REFERENCE_ISOLATED_PG_DATA"), "requires owned isolated PostgreSQL cluster"
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    with psycopg.connect(dsn) as conn:
        database, port = conn.execute("SELECT current_database(),inet_server_port()").fetchone()
        assert database == "factory_test" and port == int(os.environ["REFERENCE_ISOLATED_PG_PORT"])
        conn.execute(SCHEMA)
        conn.execute(MAP_SCHEMA)
        conn.execute("CREATE ROLE evidence_map_test_writer NOLOGIN NOSUPERUSER NOBYPASSRLS")
        conn.execute("CREATE ROLE evidence_map_test_reader NOLOGIN NOSUPERUSER NOBYPASSRLS")
        conn.execute("GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON regulated_evidence_map_v2,"
                     "regulated_evidence_keys_v1 TO evidence_map_test_writer")
        conn.execute("GRANT SELECT ON regulated_evidence_map_v2,regulated_evidence_keys_v1 TO evidence_map_test_reader")
    return dsn


@contextmanager
def transaction(database, tenant, reader=False):
    with psycopg.connect(database) as conn:
        with conn.transaction():
            role = "evidence_map_test_reader" if reader else "evidence_map_test_writer"
            conn.execute("SET LOCAL ROLE " + role)  # test-only fixed roles, no input identifier
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            yield conn


def changes(tenant, seq, trees):
    result = {}
    for label in ("repeat", f"distinct-{seq}", f"bucket-{seq % 5}"):
        key = key_digest(tenant, "record_id", label)
        tree, first = trees.setdefault(key, (MemoryMerkleLog(), seq))
        tree.append(occurrence_bytes(seq))
        result[key] = ("record_id", KeySummary(tree.frontier.size, first, seq, tree.root().hex()))
    return result


def test_pg_memory_roots_and_all_proof_bytes_match_at_historical_versions(database):
    tenant = "map-equivalence-" + uuid4().hex
    memory, trees, roots = MemorySparseMap(), {}, []
    with transaction(database, tenant) as conn:
        for seq in range(64):
            updates = changes(tenant, seq, trees)
            batch = stage_map_update_on(conn, tenant=tenant, tree_size=seq + 1,
                                        previous_root=memory.root, updates=updates)
            assert len(batch.nodes) <= len(updates) * 257
            for key, (_, value) in updates.items():
                memory.update(key, value.bytes())
            assert batch.root == memory.root
            insert_map_batch_on(conn, batch)
            roots.append(memory.root)
        for size in (1, 2, 7, 31, 64):
            for label in ("repeat", "distinct-0", "distinct-63", "never-present", "bucket-3"):
                key = key_digest(tenant, "record_id", label)
                observed = read_map_proof_on(conn, tenant=tenant, tree_size=size, root=roots[size - 1], key=key)
                assert observed == memory.prove(key, roots[size - 1])
        # The 256 prefix probes must be distinct, including at zero and all-one keys.
        for key in (b"\0" * 32, b"\xff" * 32):
            depths, prefixes = proof_prefixes(key)
            assert len(set(zip(depths, prefixes))) == 256


def test_pg_rollback_keeps_map_and_values_atomic(database):
    tenant = "map-rollback-" + uuid4().hex
    updates = changes(tenant, 0, {})
    with pytest.raises(RuntimeError, match="after rows"):
        with transaction(database, tenant) as conn:
            batch = stage_map_update_on(conn, tenant=tenant, tree_size=1, previous_root=EMPTY[0], updates=updates)
            insert_map_batch_on(conn, batch)
            raise RuntimeError("injected after rows before enclosing commit")
    with transaction(database, tenant) as conn:
        assert conn.execute("SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s", (tenant,)).fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM regulated_evidence_keys_v1 WHERE tenant=%s", (tenant,)).fetchone()[0] == 0
        key = next(iter(updates))
        assert read_map_proof_on(conn, tenant=tenant, tree_size=0, root=EMPTY[0], key=key).value is None


def seed(database, tenant):
    with transaction(database, tenant) as conn:
        batch = stage_map_update_on(conn, tenant=tenant, tree_size=1, previous_root=EMPTY[0], updates=changes(tenant, 0, {}))
        insert_map_batch_on(conn, batch)
    return batch


def test_rls_scope_reader_privileges_and_forced_policy(database):
    tenant = "map-rls-" + uuid4().hex
    batch = seed(database, tenant)
    with transaction(database, "other-" + tenant) as conn:
        for table in ("regulated_evidence_map_v2", "regulated_evidence_keys_v1"):
            assert conn.execute("SELECT count(*) FROM " + table + " WHERE tenant=%s", (tenant,)).fetchone()[0] == 0
        with pytest.raises(EvidenceError, match="scope"):
            read_map_proof_on(conn, tenant=tenant, tree_size=1, root=batch.root, key=batch.values[0][0])
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with transaction(database, "other-" + tenant) as conn:
            conn.execute("INSERT INTO regulated_evidence_map_v2 VALUES(%s,%s,'leaf',NULL,NULL,%s,%s)",
                         (tenant, b"\0" * 32, b"a" * 32, b"value"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with transaction(database, tenant, reader=True) as conn:
            conn.execute("INSERT INTO regulated_evidence_map_v2 VALUES(%s,%s,'leaf',NULL,NULL,%s,%s)",
                         (tenant, b"\0" * 32, b"a" * 32, b"value"))
    with transaction(database, tenant, reader=True) as conn:
        assert read_map_proof_on(conn, tenant=tenant, tree_size=1, root=batch.root, key=batch.values[0][0]).value
        flags = conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname IN "
                             "('regulated_evidence_map_v2','regulated_evidence_keys_v1')").fetchall()
        assert flags == [(True, True), (True, True)]


@pytest.mark.parametrize("table", ["regulated_evidence_map_v2", "regulated_evidence_keys_v1"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_immutable_rows_refuse_even_when_fixture_role_has_dml_grant(database, table, operation):
    tenant = "map-immutable-" + uuid4().hex
    seed(database, tenant)
    statement = (f"UPDATE {table} SET tenant=tenant WHERE tenant=%s" if operation == "UPDATE"
                 else f"DELETE FROM {table} WHERE tenant=%s" if operation == "DELETE" else f"TRUNCATE {table}")
    with pytest.raises(psycopg.Error):
        with transaction(database, tenant) as conn:
            conn.execute(statement, (tenant,) if operation != "TRUNCATE" else None)


def test_duplicate_version_and_wrong_pinned_root_refuse(database):
    tenant = "map-version-" + uuid4().hex
    batch = seed(database, tenant)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with transaction(database, tenant) as conn:
            insert_map_batch_on(conn, batch)
    with transaction(database, tenant) as conn:
        with pytest.raises(EvidenceError, match="pinned root"):
            read_map_proof_on(conn, tenant=tenant, tree_size=1, root=b"x" * 32, key=batch.values[0][0])
    with psycopg.connect(database, autocommit=True) as conn:
        with pytest.raises(EvidenceError, match="active"):
            read_map_proof_on(conn, tenant=tenant, tree_size=1, root=batch.root, key=batch.values[0][0])


def walk(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from walk(child)


@pytest.mark.parametrize("statistics", ["fresh_load", "analyzed"])
def test_exact_query_plans_content_address_and_key_at_1k_and_10k(database, statistics):
    # Detached map-storage fixtures, not authorized evidence or a service benchmark.
    tenant = "map-plans-" + uuid4().hex
    key = sha256(b"proof-target").digest()
    depths, paths = proof_prefixes(key)
    evidence = []
    with transaction(database, tenant) as conn:
        for size in (1000, 10000):
            low = 1 if size == 1000 else 1001
            with conn.cursor() as cursor:
                cursor.executemany("INSERT INTO regulated_evidence_map_v2 VALUES(%s,%s,'leaf',NULL,NULL,%s,%s)",
                    [(tenant, node_digest(MapNode(key=sha256(str(i).encode()).digest(),value=b'fixture')),
                      sha256(str(i).encode()).digest(),b'fixture') for i in range(low,size+1)])
                cursor.executemany("INSERT INTO regulated_evidence_keys_v1 VALUES(%s,%s,'record_id',%s,%s,0,%s,%s,'occurrences',NULL)",
                                   [(tenant, key, i, i, i - 1, b"a" * 32) for i in range(low, size + 1)])
            # SPEC018: collect fresh statistics as the isolated fixture owner,
            # then measure as the original non-owner FORCE-RLS application role.
            if statistics == "analyzed":
                conn.execute("SET LOCAL ROLE NONE")
                for table in ("regulated_evidence_map_v2", "regulated_evidence_keys_v1"):
                    conn.execute("ANALYZE " + table)
                conn.execute("SET LOCAL ROLE evidence_map_test_writer")
            for position in (1, size // 2, size):
                # Normal planner settings; do not force an index or disable a scan.
                for label, query, parameters, expected_loops in (
                    ("node", MAP_PROOF_SQL, (tenant, node_digest(MapNode(key=sha256(str(position).encode()).digest(),value=b'fixture'))), 1),
                    ("value", KEY_VALUE_SQL, (tenant, key, position), 1),
                ):
                    for repeat in range(3):
                        plan = conn.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, parameters).fetchone()[0][0]
                        nodes = list(walk(plan["Plan"]))
                        scans = [n for n in nodes if "Scan" in n["Node Type"]]
                        assert scans
                        assert sum(n["Actual Rows"] * n["Actual Loops"] for n in scans) <= expected_loops * 2
                        assert sum(n.get("Rows Removed by Filter", 0) * n["Actual Loops"] for n in scans) == 0
                        # Count both index and heap visits for bitmap plans; names
                        # do not decide the gate. B-tree depth remains in buffers.
                        assert sum(n.get("Shared Hit Blocks", 0) + n.get("Shared Read Blocks", 0) for n in scans) <= expected_loops * 8
                        evidence.append(dict(statistics=statistics, size=size, position=position, query=label, repeat=repeat, plan=plan))
    path = os.environ.get("EVIDENCE_MAP_PLAN_OUTPUT")
    if path:
        from pathlib import Path
        Path(path + "." + statistics).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
