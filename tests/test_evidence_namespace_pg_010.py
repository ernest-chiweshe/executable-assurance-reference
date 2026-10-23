from hashlib import sha256
from uuid import uuid4
import os
import psycopg
import pytest
from regulated_core.evidence_namespace_pg import NAMESPACE_SCHEMA,PostgresNamespaceWriter,PostgresNamespaceSealer,NamespaceRetention
from regulated_core.evidence_namespace import Transition,verify_namespace_head
from regulated_core.evidence_witness import WitnessScope
from regulated_core.evidence_service import EvidenceError
from regulated_core.evidence_map import MemorySparseMap
from regulated_core.evidence_service_pg import MAP_SCHEMA
from regulated_core.persistence_pg import SCHEMA
from test_evidence_service_formats import case

def test_idempotent_atomic_namespace_and_retention_gated_seal(case,tmp_path):
    assert os.environ.get('REFERENCE_ISOLATED_PG_DATA')
    clock,signer,_,trust,keys,*_=case;tenant='namespace-'+uuid4().hex
    scope=WitnessScope('tenant',tenant,'budget');writer=PostgresNamespaceWriter(scope)
    from regulated_core.evidence_publication import PublicationJournal
    from assurance_reference.local_retention import LocalRetentionStore
    retention=NamespaceRetention(scope=scope,worm=LocalRetentionStore(tmp_path/'retained'),journal=PublicationJournal(tmp_path/'journal.db'),clock=clock,retain_us=1000000)
    sealer=PostgresNamespaceSealer(scope,signer=signer,trust=trust,clock=clock,keys=keys,historical_keys={},verify_source=lambda t,s:True,retention=retention)
    with psycopg.connect(os.environ['FACTORY_TEST_DB_URL']) as c:
        c.execute(SCHEMA);c.execute(MAP_SCHEMA);c.execute(NAMESPACE_SCHEMA)
        c.execute("SELECT set_config('app.tenant',%s,true)",(tenant,))
        model=MemorySparseMap();snapshots=[]
        for i in range(3):
            raw=f'source-{i}'.encode();t=Transition('tenant',tenant,'budget',sha256(str(i).encode()).hexdigest(),i,'a'*64,sha256(raw).hexdigest())
            snapshot=writer.append_on(c,operation_id=f'op-{i}',transition=t,source=raw)
            assert writer.append_on(c,operation_id=f'op-{i}',transition=t,source=raw)==snapshot
            model.update(bytes.fromhex(t.key),t.state_value().bytes());assert snapshot.state_root==model.root;snapshots.append(snapshot)
        head=sealer.seal_on(c,previous=None,through=3)
        assert retention.journal.watermark()[0]==3 and head.map_root==snapshots[-1].state_root.hex()
        assert verify_namespace_head(head,**scope.fields(),clock_domain=clock.domain,trust=trust,allowed_keys=keys)
        with pytest.raises(EvidenceError):writer.append_on(c,operation_id='op-0',transition=t,source=raw)
        raw=b'next';t=Transition('tenant',tenant,'budget',t.key,3,'b'*64,sha256(raw).hexdigest())
        writer.append_on(c,operation_id='op-3',transition=t,source=raw)
        clock.value+=1000001
        with pytest.raises(EvidenceError):sealer.seal_on(c,previous=head,through=4)
        assert c.execute('SELECT count(*) FROM regulated_ns_seal_v2 WHERE tenant=%s',(tenant,)).fetchone()[0]==1
