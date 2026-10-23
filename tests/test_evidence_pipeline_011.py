"""Immutable readback checks on the actual batched path; isolated defensive replies only."""
from uuid import uuid4
from contextlib import contextmanager
import psycopg
import pytest
from regulated_core import evidence_service_pg as pg
from regulated_core.evidence_map import EMPTY,key_digest
from regulated_core.evidence_service import KeySummary,EvidenceError
from test_evidence_service_pg_core import database,transaction


@pytest.mark.parametrize('fault',[None,'missing','digest','shape','network','content_digest','duplicate','unexpected'])
def test_pipelined_map_readback_checks_every_reply_and_rolls_back(database,fault):
    tenant='pipeline-'+uuid4().hex
    class Probe:
        def __init__(self,conn):self.conn=conn;self.info=conn.info;self.reads=0;self.batches=0
        @contextmanager
        def cursor(self):
            probe=self
            with self.conn.cursor() as cursor:
                class CursorProbe:
                    readback=False
                    def execute(inner,query,params=None):
                        inner.readback="WHERE tenant=%s AND hash=requested.hash LIMIT 1" in query
                        if inner.readback:
                            probe.batches+=1
                            probe.reads+=len(params[0])
                            assert params[1]==tenant
                        return cursor.execute(query,params)
                    def executemany(inner,query,params):return cursor.executemany(query,params)
                    def fetchall(inner):
                        rows=cursor.fetchall()
                        assert inner.readback and rows
                        # Isolated replies from the real query, without changing
                        # stored rows or production validation code.
                        if fault=='network':raise psycopg.OperationalError('synthetic readback disconnect')
                        if fault=='missing':return rows[:-1]
                        if fault=='duplicate':return rows+[rows[0]]
                        if fault=='unexpected':return rows+[(b'x'*32,*rows[0][1:])]
                        if fault=='digest':
                            return [(b'x'*32,*rows[0][1:]),*rows[1:]]
                        if fault=='shape':return [(rows[0][0],'invalid',*rows[0][2:]),*rows[1:]]
                        if fault=='content_digest':
                            row=list(rows[0])
                            row[5 if row[1]=='leaf' else 2]=b'changed' if row[1]=='leaf' else b'x'*32
                            return [tuple(row),*rows[1:]]
                        return rows
                yield CursorProbe()
        @contextmanager
        def pipeline(self):
            self.batches+=1
            with self.conn.pipeline():yield
        def execute(self,query,params=None):
            result=self.conn.execute(query,params)
            if query!=pg.MAP_PROOF_SQL:return result
            self.reads+=1
            class Reply:
                def fetchone(inner):
                    row=result.fetchone()
                    if fault=='missing':return None
                    if fault=='network':raise psycopg.OperationalError('synthetic readback disconnect')
                    if fault=='digest':return (*row[:4],b'changed')
                    if fault=='shape':return ('invalid',*row[1:])
                    return row
            return Reply()
    probe=None;batch=None
    def write():
        nonlocal probe,batch
        with transaction(database,tenant) as conn:
            batch=pg.stage_map_update_on(conn,tenant=tenant,tree_size=1,previous_root=EMPTY[0],
                updates={key_digest(tenant,'record_id','one'):('record_id',KeySummary(1,0,0,'a'*64))})
            probe=Probe(conn);pg.insert_map_batch_on(probe,batch)
    if fault is None:write()
    else:
        with pytest.raises((EvidenceError,psycopg.OperationalError)):write()
    assert probe.batches==1 and probe.reads==len(batch.nodes)>0
    with transaction(database,tenant) as conn:
        actual=conn.execute('SELECT count(*) FROM regulated_evidence_map_v2 WHERE tenant=%s',(tenant,)).fetchone()[0]
        assert actual==(len(batch.nodes) if fault is None else 0)
        assert conn.execute('SELECT count(*) FROM regulated_evidence_keys_v1 WHERE tenant=%s',(tenant,)).fetchone()[0]==(1 if fault is None else 0)
