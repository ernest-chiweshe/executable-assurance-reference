"""Defensive append-local cache tests; external readbacks remain mandatory."""
from collections import Counter
from contextlib import contextmanager
from contextvars import copy_context
from dataclasses import replace
import pytest
from regulated_core import evidence_service_pg as pg
from regulated_core.evidence_map import MapNode,node_digest
from regulated_core.evidence_service import EvidenceError
from regulated_core.canonical import digest_hex
from test_evidence_service_pg_core import database,service,transaction
from test_evidence_service_formats import case


def leaf(i=0):
    node=MapNode(key=i.to_bytes(32,'big'),value=b'value')
    return node_digest(node),node


def row(node):return ('leaf',None,None,node.key,node.value)


class Fake:
    def __init__(self,rows):self.rows=rows;self.calls=[]
    def execute(self,query,params):
        assert query==pg.MAP_PROOF_SQL
        self.calls.append(params)
        value=self.rows[params[1]]
        class Reply:
            def fetchone(self):return value
        return Reply()


def test_reuses_only_verified_nodes_and_never_outlives_append():
    digest,node=leaf();conn=Fake({digest:row(node)});read=pg._map_reader(conn,'a')
    with pg._map_read_scope(conn,'a'):
        assert read(digest)==read(digest)==node
        assert len(conn.calls)==1
        inherited=copy_context()
    assert pg._MAP_READ_SCOPE.get() is None
    assert inherited.run(read,digest)==node
    assert inherited.run(read,digest)==node
    assert read(digest)==node
    assert len(conn.calls)==4


def test_cache_never_crosses_connection_tenant_or_nested_scope():
    digest,node=leaf();one=Fake({digest:row(node)});two=Fake({digest:row(node)})
    with pg._map_read_scope(one,'a'):
        read=pg._map_reader(one,'a');read(digest)
        pg._map_reader(one,'b')(digest);pg._map_reader(one,'b')(digest)
        pg._map_reader(two,'a')(digest);pg._map_reader(two,'a')(digest)
        with pg._map_read_scope(one,'a'):read(digest)
        read(digest)
    assert len(one.calls)==4 and len(two.calls)==2


@pytest.mark.parametrize('bad',[None,('invalid',None,None,None,None),('leaf',None,None,b'x'*32,b'changed')])
def test_missing_malformed_and_wrong_digest_replies_are_not_cached(bad):
    digest,node=leaf();conn=Fake({digest:bad});read=pg._map_reader(conn,'a')
    with pg._map_read_scope(conn,'a'):
        for _ in range(2):
            with pytest.raises((EvidenceError,ValueError,TypeError)):read(digest)
        conn.rows[digest]=row(node)
        assert read(digest)==read(digest)==node
    assert len(conn.calls)==3


def test_cache_cap_evicts_verified_nodes_without_changing_results():
    items=[leaf(i) for i in range(pg._MAP_READ_CACHE_LIMIT+1)]
    conn=Fake({digest:row(node) for digest,node in items});read=pg._map_reader(conn,'a')
    with pg._map_read_scope(conn,'a'):
        for digest,node in items:
            assert read(digest)==node
            assert len(pg._MAP_READ_SCOPE.get()[2])<=pg._MAP_READ_CACHE_LIMIT
        assert read(items[0][0])==items[0][1]
    assert len(conn.calls)==pg._MAP_READ_CACHE_LIMIT+2


def test_failure_discards_scope_and_later_append_revalidates_storage():
    digest,node=leaf();conn=Fake({digest:row(node)});read=pg._map_reader(conn,'a')
    with pytest.raises(RuntimeError):
        with pg._map_read_scope(conn,'a'):
            read(digest);raise RuntimeError('abort append')
    conn.rows[digest]=None
    with pg._map_read_scope(conn,'a'):
        with pytest.raises(EvidenceError):read(digest)
    assert len(conn.calls)==2 and pg._MAP_READ_SCOPE.get() is None


def test_real_append_shares_old_node_reads_but_retains_staged_readbacks(database,service,monkeypatch):
    store,recorder,record,kwargs=service
    class Probe:
        def __init__(self,conn):self.conn=conn;self.info=conn.info;self.in_pipeline=False;self.in_readback=False;self.reads=[];self.readbacks=[]
        def transaction(self):return self.conn.transaction()
        @contextmanager
        def cursor(self):
            # Observe both statement forms without replacing database replies.
            probe = self
            with self.conn.cursor() as cursor:
                class CursorProbe:
                    def execute(self, query, params=None):
                        if "WHERE tenant=%s AND hash=requested.hash LIMIT 1" in query:
                            assert probe.in_readback
                            probe.readbacks.extend((params[1], bytes(digest)) for digest in params[0])
                        return cursor.execute(query, params)
                    def executemany(self, query, params):return cursor.executemany(query, params)
                    def fetchall(self):return cursor.fetchall()
                yield CursorProbe()
        @contextmanager
        def pipeline(self):
            self.in_pipeline=True
            try:
                with self.conn.pipeline():yield
            finally:self.in_pipeline=False
        def execute(self,query,params=None):
            if query==pg.MAP_PROOF_SQL:
                (self.readbacks if self.in_readback else self.reads).append((params[0],bytes(params[1])))
            return self.conn.execute(query,params)
    original_insert=pg.insert_map_batch_on
    def observed_insert(conn,batch):
        conn.in_readback=True
        conn.expected_readbacks={(batch.tenant,digest) for digest,node in batch.nodes}
        try:return original_insert(conn,batch)
        finally:conn.in_readback=False
    monkeypatch.setattr(pg,'insert_map_batch_on',observed_insert)
    old_reads=0
    with transaction(database,store.tenant) as conn:
        probe=Probe(conn)
        for i in range(6):
            probe.reads=[];probe.readbacks=[]
            current=replace(record,record_id='cached-'+str(i))
            env,head=store.append_record_on(probe,recorder,current,digest_hex(current))
            counts=Counter(probe.reads)
            assert all(count==1 for count in counts.values())
            assert probe.readbacks and len(probe.readbacks)==len(set(probe.readbacks))
            assert set(probe.readbacks)==probe.expected_readbacks
            assert head.tree_size==i+1 and env.seq==i
            assert pg._MAP_READ_SCOPE.get() is None
            old_reads+=len(probe.reads)
    assert old_reads>0
