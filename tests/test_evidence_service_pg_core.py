"""Isolated durable core contracts; no caller activation or production resources."""
import json
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest

from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence_service import EvidenceError, MemoryEvidenceService, lookup_key, verify_lookup
from regulated_core import evidence_service_pg as pg
from regulated_core.merkle import Frontier, verify_consistency
from regulated_core.persistence_pg import SCHEMA, PostgresDecisionRecorder
from test_evidence_service_formats import case, Clock


class TransactionClock(Clock):
    def __init__(self):
        super().__init__()
        self.contexts = []

    def read(self):
        self.contexts.append("independent")
        return super().read()

    def read_on(self, connection):
        assert connection.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
        self.contexts.append("transaction")
        return super().read()

NEW_TABLES = ("regulated_evidence_tree_v1", "regulated_evidence_frontier_v1", "regulated_evidence_heads_v1",
              "regulated_evidence_key_tree_v1", "regulated_evidence_key_frontier_v1", "regulated_evidence_key_occurrences_v1")
ALL_TABLES = NEW_TABLES + ("regulated_evidence_map_v2", "regulated_evidence_keys_v1", "regulated_decision_evidence_v1")


class TestDatabase(str):
    __test__ = False


@pytest.fixture(scope="module")
def database():
    assert os.environ.get("REFERENCE_ISOLATED_PG_DATA"), "requires owned isolated PostgreSQL cluster"
    dsn = TestDatabase(os.environ["FACTORY_TEST_DB_URL"])
    # Imported module fixtures may execute once per consuming module. Each
    # invocation owns fresh roles; no preexisting role privileges are trusted.
    dsn.writer = "evidence_writer_" + uuid4().hex
    dsn.reader = "evidence_reader_" + uuid4().hex
    with psycopg.connect(dsn) as conn:
        name, port = conn.execute("SELECT current_database(),inet_server_port()").fetchone()
        assert name == "factory_test" and port == int(os.environ["REFERENCE_ISOLATED_PG_PORT"])
        conn.execute(SCHEMA); conn.execute(pg.MAP_SCHEMA); conn.execute(pg.SERVICE_SCHEMA)
        conn.execute(psycopg.sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(psycopg.sql.Identifier(dsn.writer)))
        conn.execute(psycopg.sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(psycopg.sql.Identifier(dsn.reader)))
        for table in ALL_TABLES:
            conn.execute(psycopg.sql.SQL("GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON {} TO {}").format(psycopg.sql.Identifier(table), psycopg.sql.Identifier(dsn.writer)))
            conn.execute(psycopg.sql.SQL("GRANT SELECT ON {} TO {}").format(psycopg.sql.Identifier(table), psycopg.sql.Identifier(dsn.reader)))
    return dsn


@contextmanager
def transaction(database, tenant, *, reader=False, isolation=None):
    with psycopg.connect(database) as conn:
        with conn.transaction():
            if isolation:
                conn.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)  # fixed test values only
            conn.execute(psycopg.sql.SQL("SET LOCAL ROLE {}").format(psycopg.sql.Identifier(database.reader if reader else database.writer)))
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
            yield conn


@pytest.fixture
def service(case):
    original_clock, signer, _, trust, keys, _, _, envelopes = case
    clock = TransactionClock()
    clock.value = original_clock.value
    tenant = "service-" + uuid4().hex
    kwargs = dict(tenant=tenant, signer=signer, clock=clock, trust=trust, signing_keys=keys,
                  historical_head_keys={}, envelope_keys_allowed=keys,
                  envelope_domains=frozenset({clock.domain}))
    recorder = PostgresDecisionRecorder(signer, trust, pool=None, clock=clock)
    record = replace(envelopes[0].record, tenant_id=tenant, record_id="duplicate")
    return pg.PostgresEvidenceService(**kwargs), recorder, record, kwargs


def append(conn, service, record=None):
    store, recorder, original, _ = service
    record = original if record is None else record
    return store.append_record_on(conn, recorder, record, digest_hex(record))


def counts(conn, tenant):
    return tuple(conn.execute("SELECT count(*) FROM " + table + " WHERE tenant=%s", (tenant,)).fetchone()[0]
                 for table in ALL_TABLES)


def test_pg_and_memory_full_heads_roots_and_lookup_proofs_are_identical(database, service):
    store, _, record, kwargs = service
    memory = MemoryEvidenceService(**kwargs)
    heads, envelopes = [], []
    with transaction(database, store.tenant) as conn:
        for i in range(33):
            variant = replace(record, assertion_id=f"variant-{i % 3}")
            calls = store.clock.calls
            envelope, head = append(conn, service, variant)
            # Two unchanged recorder samples and a distinct new head sample.
            assert store.clock.calls == calls + 3
            assert store.clock.contexts[-3:] == ["transaction", "transaction", "independent"]
            assert memory.append(envelope) == head
            heads.append(head); envelopes.append(envelope)
        for index in (0, 1, 7, 16, 32):
            head = heads[index]
            for kind, key in (("record_id", "duplicate"), ("record_id", "absent"),
                              ("record_hash", envelopes[0].record_hash),
                              ("record_id_hash", ("duplicate", envelopes[1].record_hash))):
                for selection, ordinal in (("count", None), ("absent", None), ("first", None),
                                            ("latest", None), ("ordinal", 1), ("ordinal", 34)):
                    params = dict(head=head, key_type=kind, key=key, selection=selection, ordinal=ordinal)
                    assert store.lookup_on(conn, **params) == memory.lookup(**params)
            proof = store.consistency_on(conn, heads[0], head)
            assert verify_consistency(1, head.tree_size, bytes.fromhex(heads[0].tree_root), bytes.fromhex(head.tree_root), proof)
        assert store.head_on(conn) == heads[-1]
    # A fresh connection sees exactly the committed bytes and head, not process-local state.
    with transaction(database, store.tenant, reader=True) as conn:
        assert store.head_on(conn) == heads[-1]
        row = conn.execute(pg.ENVELOPE_SQL, (store.tenant, 32)).fetchone()
        assert canonical_bytes(row[2]) == canonical_bytes(envelopes[-1])


@pytest.mark.parametrize("failure", ["head_signer", "after_all_rows", "key_policy", "outer_rollback"])
def test_atomic_envelope_and_companion_rows_with_caught_inner_failure(database, service, monkeypatch, failure):
    store, recorder, _, _ = service
    with transaction(database, store.tenant) as conn:
        append(conn, service)
    with transaction(database, store.tenant) as conn:
        before, prior = counts(conn, store.tenant), store.head_on(conn)
        if failure == "head_signer":
            original = store.signer.sign
            def fail_head(body):
                if body.get("schema") == "regulated/evidence-sth/v2": raise RuntimeError("head outage")
                return original(body)
            monkeypatch.setattr(store.signer, "sign", fail_head)
        elif failure == "after_all_rows":
            original = store._insert_append_on
            def fail_after(*args):
                original(*args)
                raise RuntimeError("after all rows")
            monkeypatch.setattr(store, "_insert_append_on", fail_after)
        elif failure == "key_policy":
            store.envelope_keys_allowed = frozenset({"unapproved-key"})
        if failure != "outer_rollback":
            with pytest.raises((EvidenceError, RuntimeError)):
                append(conn, service)
        else:
            with pytest.raises(RuntimeError):
                with conn.transaction():
                    append(conn, service)
                    raise RuntimeError("outer caller refusal")
        assert counts(conn, store.tenant) == before
        assert store.head_on(conn) == prior
    # Committing the caller after catching the failure still cannot publish a partial append.
    with transaction(database, store.tenant) as conn:
        assert counts(conn, store.tenant) == before


def test_unindexed_legacy_tail_refuses_without_history_scan_or_partial_append(database, service):
    store, recorder, record, _ = service
    with transaction(database, store.tenant) as conn:
        recorder._append_on(conn, record, digest_hex(record))
        before = counts(conn, store.tenant)
        with pytest.raises(EvidenceError, match="authenticated history"):
            append(conn, service)
        assert counts(conn, store.tenant) == before
        assert store.head_on(conn) is None


def test_two_concurrent_transactions_append_contiguously(database, service):
    store = service[0]
    barrier = Barrier(2)
    def worker():
        with transaction(database, store.tenant) as conn:
            barrier.wait(timeout=10)
            return append(conn, service)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: worker(), range(2)))
    results.sort(key=lambda pair: pair[0].seq)
    assert [env.seq for env, _ in results] == [0, 1]
    assert results[1][0].prev_hash == results[0][0].chain_hash()
    assert results[1][1].previous_sth_digest == results[0][1].digest()
    with transaction(database, store.tenant, reader=True) as conn:
        proof = store.lookup_on(conn, head=results[1][1], key_type="record_id", key="duplicate", selection="count")
        assert json.loads(proof.map_proof.value)["count"] == 2


def test_required_transaction_isolation_scope_and_head_pin(database, service):
    store = service[0]
    with psycopg.connect(database, autocommit=True) as conn:
        with pytest.raises(EvidenceError, match="active"):
            append(conn, service)
    with transaction(database, "different") as conn:
        with pytest.raises(EvidenceError, match="scope"):
            append(conn, service)
    with transaction(database, store.tenant, isolation="REPEATABLE READ") as conn:
        with pytest.raises(EvidenceError, match="READ COMMITTED"):
            append(conn, service)
    with transaction(database, store.tenant) as conn:
        _, head = append(conn, service)
        wrong = replace(head, issued_at_us=head.issued_at_us + 1)
        wrong = replace(wrong, signature=store.signer.sign(wrong.body()))
        with pytest.raises(EvidenceError, match="caller pin"):
            store.lookup_on(conn, head=wrong, key_type="record_id", key="duplicate", selection="count")
        with pytest.raises(EvidenceError, match="missing"):
            store.head_on(conn, 999)
        with pytest.raises(EvidenceError, match="range"):
            store.head_on(conn, 1 << 63)


@pytest.mark.parametrize("table", NEW_TABLES)
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_new_tables_are_immutable_even_with_test_dml_privileges(database, service, table, operation):
    store = service[0]
    with transaction(database, store.tenant) as conn:
        append(conn, service)
    sql = (f"UPDATE {table} SET tenant=tenant WHERE tenant=%s" if operation == "UPDATE"
           else f"DELETE FROM {table} WHERE tenant=%s" if operation == "DELETE" else f"TRUNCATE {table}")
    with pytest.raises(psycopg.Error):
        with transaction(database, store.tenant) as conn:
            conn.execute(sql, None if operation == "TRUNCATE" else (store.tenant,))


def test_new_tables_force_rls_and_reader_cannot_append(database, service):
    store = service[0]
    with transaction(database, store.tenant) as conn:
        append(conn, service)
        flags = conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname=ANY(%s)", (list(NEW_TABLES),)).fetchall()
        assert len(flags) == 6 and all(row == (True, True) for row in flags)
    with transaction(database, "other") as conn:
        assert counts(conn, store.tenant) == (0,) * len(ALL_TABLES)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with transaction(database, "other") as conn:
            conn.execute("INSERT INTO regulated_evidence_heads_v1 VALUES(%s,999,'{}')", (store.tenant,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with transaction(database, store.tenant, reader=True) as conn:
            append(conn, service)


@pytest.mark.parametrize("damage", ["missing_frontier", "wrong_root", "bad_slots", "wrong_size"])
def test_authenticated_head_requires_matching_frontier_before_append(database, service, case, damage):
    # Detached corruption fixture: insert validly signed outer state, no guard removal.
    store, _, _, _ = service
    head = replace(case[6][0], tenant=store.tenant)
    head = replace(head, signature=store.signer.sign(head.body()))
    document = {"schema": "regulated/evidence-frontier/v1", "size": 1,
                "slots": [head.tree_root]}
    if damage == "wrong_root": document["slots"] = ["f" * 64]
    elif damage == "bad_slots": document["slots"] = [None]
    elif damage == "wrong_size": document["size"] = True
    with transaction(database, store.tenant) as conn:
        conn.execute("INSERT INTO regulated_evidence_heads_v1 VALUES(%s,1,%s::jsonb)",
                     (store.tenant, canonical_bytes(head.document()).decode()))
        if damage != "missing_frontier":
            conn.execute("INSERT INTO regulated_evidence_frontier_v1 VALUES(%s,1,%s::jsonb)",
                         (store.tenant, json.dumps(document)))
        before = counts(conn, store.tenant)
        with pytest.raises(EvidenceError, match="frontier"):
            append(conn, service)
        assert counts(conn, store.tenant) == before


def walk(plan):
    yield plan
    for child in plan.get("Plans", []): yield from walk(child)


@pytest.mark.parametrize("statistics", ["fresh_load", "analyzed"])
def test_exact_new_queries_have_index_work_bounds_at_1k_and_10k(database, statistics):
    # Storage-only detached fixtures: neither signed evidence nor latency benchmarks.
    tenant, key = "service-plans-" + uuid4().hex, b"k" * 32
    evidence = []
    with transaction(database, tenant) as conn:
        for size in (1000, 10000):
            low = 0 if size == 1000 else 1000
            with conn.cursor() as cursor:
                cursor.executemany("INSERT INTO regulated_evidence_tree_v1 VALUES(%s,0,%s,%s)",
                                   [(tenant, i, b"a" * 32) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_evidence_key_tree_v1 VALUES(%s,%s,0,%s,%s)",
                                   [(tenant, key, i, b"a" * 32) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_evidence_frontier_v1 VALUES(%s,%s,'{}')",
                                   [(tenant, i + 1) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_evidence_key_frontier_v1 VALUES(%s,%s,%s,'{}')",
                                   [(tenant, key, i + 1) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_evidence_heads_v1 VALUES(%s,%s,'{}')",
                                   [(tenant, i + 1) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_evidence_key_occurrences_v1 VALUES(%s,%s,%s,%s,%s)",
                                   [(tenant, key, i, i, i + 1) for i in range(low, size)])
                cursor.executemany("INSERT INTO regulated_decision_evidence_v1 VALUES(%s,%s,%s,'{}')",
                                   [(tenant, i, f"{i:064x}") for i in range(low, size)])
            # SPEC018: collect fresh statistics as the isolated fixture owner,
            # then measure as the original non-owner FORCE-RLS application role.
            if statistics == "analyzed":
                conn.execute("SET LOCAL ROLE NONE")
                for table in ALL_TABLES:
                    conn.execute("ANALYZE " + table)
                conn.execute(psycopg.sql.SQL("SET LOCAL ROLE {}").format(psycopg.sql.Identifier(database.writer)))
            for position in (1, size // 2, size):
                cases = (("head", pg.HEAD_SQL, (tenant, position)), ("latest_head", pg.LATEST_HEAD_SQL, (tenant,)),
                         ("frontier", pg.FRONTIER_SQL, (tenant, position)), ("key_frontier", pg.KEY_FRONTIER_SQL, (tenant, key, position)),
                         ("tree_node", pg.TREE_NODE_SQL, (tenant, 0, position - 1)),
                         ("key_node", pg.KEY_NODE_SQL, (tenant, key, 0, position - 1)),
                         ("occurrence", pg.OCCURRENCE_SQL, (tenant, key, position - 1)),
                         ("envelope", pg.ENVELOPE_SQL, (tenant, position - 1)))
                for label, query, args in cases:
                    for repeat in range(3):
                        plan = conn.execute("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, args).fetchone()[0][0]
                        evidence.append(dict(statistics=statistics, size=size, position=position, query=label, repeat=repeat, plan=plan))
                        if os.environ.get("EVIDENCE_SERVICE_PLAN_OUTPUT"):
                            from pathlib import Path
                            Path(os.environ["EVIDENCE_SERVICE_PLAN_OUTPUT"] + "." + statistics).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
                        scans = [node for node in walk(plan["Plan"]) if "Scan" in node["Node Type"]]
                        assert scans
                        # Count index and heap visits if a bitmap plan has both;
                        # method names alone never decide this phase's work gate.
                        assert sum(n["Actual Rows"] * n["Actual Loops"] for n in scans) <= 2
                        assert sum(n.get("Rows Removed by Filter", 0) * n["Actual Loops"] for n in scans) == 0, (label, plan)
                        assert sum(n.get("Shared Hit Blocks", 0) + n.get("Shared Read Blocks", 0) for n in scans) <= 8
    if os.environ.get("EVIDENCE_SERVICE_PLAN_OUTPUT"):
        from pathlib import Path
        Path(os.environ["EVIDENCE_SERVICE_PLAN_OUTPUT"] + "." + statistics).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize("damage", ["missing", "next_ordinal", "future_seq", "wrong_version"])
def test_untrusted_occurrence_reply_cannot_substitute_the_next_row(database, service, damage):
    store = service[0]
    with transaction(database, store.tenant) as conn:
        _, head = append(conn, service)
        digest = lookup_key(store.tenant, "record_id", "duplicate")
        actual = conn.execute(pg.OCCURRENCE_SQL, (store.tenant, digest, 0)).fetchone()
        assert actual == (0, 0, 1)
        bad = {"missing": None, "next_ordinal": (1, 0, 1), "future_seq": (0, 1, 2),
               "wrong_version": (0, 0, 2)}[damage]
        class Reply:
            def fetchone(self): return bad
        class UntrustedReplyConnection:
            # Isolated adversarial storage reply; production verification stays intact.
            info = conn.info
            def execute(self, query, params=None):
                return Reply() if query == pg.OCCURRENCE_SQL else conn.execute(query, params)
        with pytest.raises(EvidenceError, match="association"):
            store.lookup_on(UntrustedReplyConnection(), head=head, key_type="record_id", key="duplicate", selection="first")
