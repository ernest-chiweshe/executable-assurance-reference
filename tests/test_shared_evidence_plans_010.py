"""Exact new SQL under non-owner RLS; synthetic plan data is not authority evidence."""
import ast
import json
import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
import psycopg
import pytest
from regulated_core.persistence_pg import SCHEMA
from regulated_core.evidence_service_pg import MAP_SCHEMA
from regulated_core.evidence_namespace_pg import NAMESPACE_SCHEMA

ROOT=Path(__file__).resolve().parents[1]

def queries(relative):
    raw=(ROOT/relative).read_bytes();tree=ast.parse(raw);out=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='execute' and n.args:
            q=n.args[0]
            if isinstance(q,ast.Constant) and isinstance(q.value,str) and q.value.startswith('SELECT ') and ('regulated_ns_' in q.value or 'FROM regulated_decision_evidence' in q.value):
                out.append((n.lineno,q.value,sha256(raw).hexdigest()))
    return out

def nodes(p):
    yield p
    for child in p.get('Plans',[]):yield from nodes(child)

@pytest.mark.parametrize('statistics',['fresh_load','analyzed'])
def test_namespace_and_provider_exact_plans(statistics):
    assert os.environ.get('REFERENCE_ISOLATED_PG_DATA')
    evidence=[];tenant='plan-'+uuid4().hex;role='plan_'+uuid4().hex
    with psycopg.connect(os.environ['FACTORY_TEST_DB_URL']) as c:
        c.execute(SCHEMA);c.execute(MAP_SCHEMA);c.execute(NAMESPACE_SCHEMA)
        c.execute('CREATE ROLE '+role+' NOLOGIN NOSUPERUSER NOBYPASSRLS')
        for table in ('regulated_ns_transition_v2','regulated_ns_tree_v2','regulated_decision_evidence_v1'):
            c.execute('GRANT SELECT ON '+table+' TO '+role)
        last=0
        for size in (1000,10000):
            # Deliberately detached rows qualify only access work, never signature or authorization semantics.
            c.execute("INSERT INTO regulated_ns_transition_v2 SELECT %s,'tenant','budget',i,'op-'||i,convert_to('transition','UTF8'),convert_to('source','UTF8'),'{}'::jsonb,decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),repeat('c',64) FROM generate_series(%s::bigint,%s::bigint) i",(tenant,last+1,size))
            c.execute("INSERT INTO regulated_ns_tree_v2 SELECT %s,'tenant','budget',0,i,decode(repeat('a',64),'hex') FROM generate_series(%s::bigint,%s::bigint) i",(tenant,last+1,size))
            c.execute("INSERT INTO regulated_decision_evidence_v1 SELECT %s,i,md5(i::text)||md5(i::text),'{}'::jsonb FROM generate_series(%s::bigint,%s::bigint) i",(tenant,last,size-1))
            if statistics=='analyzed':
                for table in ('regulated_ns_transition_v2','regulated_ns_tree_v2','regulated_decision_evidence_v1'):c.execute('ANALYZE '+table)
            c.execute('SET LOCAL ROLE '+role);c.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
            for relative in ('src/regulated_core/evidence_namespace_pg.py','src/regulated_core/evidence_runtime_pg.py'):
                for line,sql,digest in queries(relative):
                    for point in (1,size//2,size):
                        if 'regulated_ns_' in sql:
                            args=(tenant,'tenant','budget')
                            if 'level=%s' in sql:args+=(0,point);cap=1
                            elif 'operation_id=%s' in sql:args+=('op-'+str(point),);cap=1
                            elif 'version>%s' in sql:args+=(point-1,min(size,point+15),17);cap=17
                            elif 'version=%s' in sql:args+=(point,);cap=1
                            else:cap=1
                        else:
                            start=point-1
                            args=(tenant,start,min(size,start+16)-1)
                            cap=16
                        document=c.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,args).fetchone()[0][0]
                        scanned=[n for n in nodes(document['Plan']) if 'Scan' in n['Node Type'] and n.get('Relation Name')]
                        assert scanned
                        for n in scanned:
                            assert n.get('Actual Rows',0)*n.get('Actual Loops',0)<=cap,(sql,size,point,n)
                            assert n.get('Rows Removed by Filter',0)==0,(sql,size,point,n)
                            assert n.get('Rows Removed by Index Recheck',0)==0
                            assert n['Node Type']!='Seq Scan'
                            # A generous measured buffer ceiling catches history scans without pinning one planner shape.
                            assert n.get('Shared Hit Blocks',0)+n.get('Shared Read Blocks',0)<=80
                        evidence.append(dict(source=relative,line=line,source_sha256=digest,sql=sql,size=size,point=point,statistics=statistics,plan=document))
            c.execute('RESET ROLE');last=size
    destination=os.environ.get('CORE010_NEW_PLAN_OUTPUT')
    if destination:Path(destination+'.'+statistics).write_text(json.dumps(evidence,indent=2)+'\n')
