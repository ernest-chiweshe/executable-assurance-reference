from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
import os
from uuid import uuid4
import psycopg
import pytest
from regulated_core.persistence_pg import SCHEMA
from regulated_core.evidence_service_pg import MAP_SCHEMA
from regulated_core.evidence_namespace_pg import NAMESPACE_SCHEMA,PostgresNamespaceWriter
from regulated_core.evidence_namespace import Transition,advance_chain
from regulated_core.evidence_map import MemorySparseMap
from regulated_core.evidence_witness import WitnessScope
from regulated_core.evidence import GENESIS
from regulated_core.evidence_service import EvidenceError
from regulated_core.merkle import MemoryMerkleLog

@pytest.fixture
def database():
    assert os.environ.get('REFERENCE_ISOLATED_PG_DATA')
    dsn=os.environ['FACTORY_TEST_DB_URL'];role='ns_'+uuid4().hex
    with psycopg.connect(dsn) as c:
        c.execute(SCHEMA);c.execute(MAP_SCHEMA);c.execute(NAMESPACE_SCHEMA)
        c.execute('CREATE ROLE '+role+' NOLOGIN NOSUPERUSER NOBYPASSRLS')
        for table in ('regulated_ns_transition_v2','regulated_ns_tree_v2','regulated_ns_seal_v2','regulated_evidence_map_v2'):c.execute('GRANT SELECT,INSERT ON '+table+' TO '+role)
    @contextmanager
    def connection(tenant):
        with psycopg.connect(dsn) as c,c.transaction():
            c.execute('SET LOCAL ROLE '+role);c.execute("SELECT set_config('app.tenant',%s,true)",(tenant,));yield c
    return connection

def test_concurrent_namespace_writes_and_identical_retries_preserve_one_ordered_history(database):
    tenant='ns-'+uuid4().hex;scope=WitnessScope('tenant',tenant,'budget');writer=PostgresNamespaceWriter(scope)
    def append(i):
        source=f'body-{i}'.encode();transition=Transition('tenant',tenant,'budget',sha256(str(i).encode()).hexdigest(),0,'a'*64,sha256(source).hexdigest())
        with database(tenant) as c:return writer.append_on(c,operation_id=f'op-{i}',transition=transition,source=source)
    with ThreadPoolExecutor(max_workers=8) as pool:out=list(pool.map(append,[0,0,1,2,3,4,5,6]))
    assert out[0]==out[1]
    with database(tenant) as c:
        rows=c.execute('SELECT version,transition,tree_root,map_root,chain FROM regulated_ns_transition_v2 WHERE tenant=%s ORDER BY version',(tenant,)).fetchall()
        assert [r[0] for r in rows]==list(range(1,8))
        tree=MemoryMerkleLog();mapping=MemorySparseMap();chain=GENESIS
        for version,raw,tr,mr,cr in rows:
            transition=Transition.from_bytes(bytes(raw));tree.append(bytes(raw));mapping.update(bytes.fromhex(transition.key),transition.state_value().bytes());chain=advance_chain(chain,transition)
            assert (tree.root(),mapping.root,chain)==(bytes(tr),bytes(mr),cr)
    with database('other-tenant') as c:
        assert c.execute('SELECT version FROM regulated_ns_transition_v2 WHERE tenant=%s',(tenant,)).fetchall()==[]
        with pytest.raises(EvidenceError):writer.snapshot_on(c,1)
