"""Bounded frontier prefetch preserves actual PG checks and append rollback."""
from contextlib import contextmanager
from dataclasses import replace
import psycopg
import pytest
from regulated_core import evidence_service_pg as pg
from regulated_core.evidence_service import EvidenceError, envelope_keys
from regulated_core.models import Annotation
from test_evidence_service_formats import case
from test_evidence_service_pg_core import database, service, transaction, append, counts


@pytest.mark.parametrize("fault", [None, "missing", "shape", "size", "root", "network"])
def test_frontier_batches_keep_binding_checks_and_atomicity(database, service, fault):
    store, recorder, record, kwargs = service
    # More than one protocol chunk, with distinct keys and different frontier sizes.
    record = replace(record, decision=replace(record.decision,
        annotations=record.decision.annotations + tuple(
            Annotation("outcome-of-decision", f"frontier020-{i}") for i in range(19))))
    with transaction(database, store.tenant) as conn:
        append(conn, service)
        envelope, prior = append(conn, service, record)
    expected_keys = set(envelope_keys(envelope))
    assert len(expected_keys) > 8

    class Probe:
        def __init__(self, conn):
            self.conn = conn
            self.batches = []
            self.active = None
            self.seen = []
            self.fetched = 0
        def __getattr__(self, name):
            return getattr(self.conn, name)
        @contextmanager
        def pipeline(self):
            assert self.active is None
            self.active = []
            try:
                with self.conn.pipeline():
                    yield
            finally:
                if self.active:
                    self.batches.append(tuple(self.active))
                self.active = None
        def execute(self, query, params=None):
            reply = self.conn.execute(query, params)
            if query != pg.KEY_FRONTIER_SQL:
                return reply
            assert self.active is not None
            assert params[0] == store.tenant and params[2] == prior.tree_size
            assert params[1] in expected_keys
            self.active.append(params[1]); self.seen.append(params[1])
            probe = self
            class Reply:
                def fetchone(self):
                    row = reply.fetchone()
                    assert probe.active is None and row is not None
                    probe.fetched += 1
                    # Detached reply faults only: stored evidence and guards intact.
                    if fault == "network":
                        raise psycopg.OperationalError("isolated frontier read failure")
                    if fault == "missing": return None
                    if fault == "shape": return ({"unexpected": True},)
                    if fault == "size": return ({**row[0], "size": row[0]["size"] + 1},)
                    if fault == "root":
                        import copy
                        value = copy.deepcopy(row[0])
                        value["slots"] = ["0" * 64 if slot is not None else None for slot in value["slots"]]
                        return (value,)
                    return row
            return Reply()

    with transaction(database, store.tenant) as conn:
        before = counts(conn, store.tenant)
        probe = Probe(conn)
        if fault is None:
            result, head = append(probe, service, record)
            assert head.tree_size == prior.tree_size + 1
            assert set(probe.seen) == expected_keys
            assert len(probe.seen) == len(expected_keys) == probe.fetched
            assert len(probe.batches) > 1
        else:
            with pytest.raises((EvidenceError, psycopg.OperationalError)):
                append(probe, service, record)
            assert counts(conn, store.tenant) == before
            assert store.head_on(conn) == prior
        assert probe.batches and all(1 <= len(batch) <= 8 for batch in probe.batches)
    if fault is not None:
        with transaction(database, store.tenant) as conn:
            assert counts(conn, store.tenant) == before
            assert store.head_on(conn) == prior
