"""Remaining source-query plans with explicit schema-fixture limitations."""
from dataclasses import fields
from hashlib import sha256
import json,os,sys
from pathlib import Path
from assurance_reference.local_roles import provision_local_roles,LocalPool
from assurance_reference.lifecycle_migration import private_digest
from assurance_reference.lifecycle_partition import partition_snapshot
from factory.packs.lifecycle import ActivationLedger
from factory.packs.lifecycle_pg import _snapshot,_canonical,_digest
from factory.governed_http_pg import migrate_http_attempts
from regulated_core.persistence_pg import _tenant
from regulated_core.canonical import digest_hex
from measure_history_plans_additional import relations

def settings(conn,tenant):
    _tenant(conn,tenant)
    for key,value in [("app.pack_tenant",tenant),("app.project_namespace","health"),("app.clinician","clinician")]:
        conn.execute("SELECT set_config(%s,%s,true)",(key,value))

def main():
    root=Path(__file__).resolve().parents[1]
    cat=json.loads((root/"docs/provenance/history-read-classifications.json").read_bytes())
    loci={"RetainedClinicalLineage.retain","RetainedClinicalStore.get","DurableClock._read","GuardedPostgresRevocationLedger.receipt","BudgetedHttpAttempts.record","_load","PartitionedActivationLedger.pack_ids","PartitionedActivationLedger._invoke","PostgresHttpAttempts.get","PostgresProjectStateStore.load","PostgresRosterStore._verified_history","PostgresRosterStore.apply"}
    sites=[s for s in cat["sites"] if s["kind"]=="history_sql" and s["locus"] in loci]
    assert len(sites)==15
    for site in sites:assert sha256((root/site["path"]).read_bytes()).hexdigest()==site["source_sha256"]
    out={"scope":"Exact-source SELECT plans, synthetic schema-valid fixture rows, no governed effect or authority acceptance.","script_sha256":sha256(Path(__file__).read_bytes()).hexdigest(),"helper_sha256":sha256((root/"scripts/measure_history_plans_additional.py").read_bytes()).hexdigest(),"limits":["Roster/epoch/clinical/HTTP fixture bodies are schema-valid diagnostic material, NOT valid signed authorizations or complete application documents. No source authority verifier is invoked.","Body width and distribution are synthetic; plans do not qualify real-world timing, decoding or proof costs.","Global pack enumeration grows with live pack count; clock domains are bootstrap entities, not historical actions.","Lifecycle retry-index count grows while selected payloads are empty; separate retained payload probes cover JSON growth.","Installed guards and RLS remain active; bootstrap role only provisions new diagnostic clock-domain rows and HTTP schema."],"results":[]}
    for n in (1000,10000):
        roles=provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
        owner=LocalPool(os.environ["FACTORY_TEST_DB_URL"],roles.schema,"diagnostic-bootstrap")
        tenant="fixture-tenant";pack="pack-0";scope={"pin":None,"requests":{},"governance_receipts":[]};body={"fixture":True,"authority":False};encoded=_canonical(body);digest=digest_hex(body)
        try:
            migrate_http_attempts(owner,receivers=(roles.receiver.role,))
            with owner.connection() as conn,conn.transaction():
                with conn.cursor() as cur:cur.executemany("INSERT INTO reference_clock_floor_v1(domain,highwater_us) VALUES(%s,0)",((f"fixture-domain-{i}",) for i in range(n-1)))
            with roles.governor.connection() as conn,conn.transaction():
                settings(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO regulated_revocation_events_v1(tenant,epoch,actor,reason,revoked_at_us) VALUES(%s,%s,'synthetic-fixture','diagnostic',0)",((tenant,i+1) for i in range(n)))
                    cur.executemany("INSERT INTO reference_epoch_withdrawal_receipts_v1(tenant,epoch,operation,nonce,change_digest,proof_digest,proof) VALUES(%s,%s,'governance:withdraw-tenant-epoch',%s,%s,%s,%s)",((tenant,i+1,f"nonce-{i}",digest,digest,encoded) for i in range(n)))
                    cur.executemany("INSERT INTO regulated_governance_rosters_v1(installation,version,roster_digest,body,tenant,operation,nonce,change_digest) VALUES('fixture-installation',%s,%s,%s,%s,'fixture',%s,%s)",((i+1,digest,encoded,tenant,f"roster-{i}",digest) for i in range(n)))
                    shared=partition_snapshot(pack,_snapshot(ActivationLedger(),pack,{}))["shared"]
                    cur.executemany("INSERT INTO reference_pack_shared_v1(pack_id,revision,payload,state_digest) VALUES(%s,1,%s::jsonb,%s)",((f"pack-{i}",_canonical(shared),_digest(f"pack-{i}",1,shared)) for i in range(n)))
                    cur.executemany("INSERT INTO reference_pack_tenants_v1(pack_id,tenant_id,revision,payload,state_digest) VALUES(%s,%s,1,%s::jsonb,%s)",((f"pack-{i}",tenant,_canonical(scope),private_digest(f"pack-{i}",tenant,1,scope)) for i in range(n)))
                    cur.executemany("INSERT INTO reference_pack_installation_retries_v1(pack_id,revision,requests,state_digest) VALUES(%s,1,'{}',%s)",((f"pack-{i}",private_digest(f"pack-{i}",None,1,{})) for i in range(n)))
                    cur.executemany("INSERT INTO reference_pack_retry_index_v1(pack_id,key_digest,request_digest) VALUES(%s,%s,%s)",((pack,sha256(str(i).encode()).hexdigest(),digest) for i in range(n)))
            with roles.receiver.connection() as conn,conn.transaction():
                settings(conn,tenant)
                with conn.cursor() as cur:cur.executemany("INSERT INTO regulated_http_attempts_v1(tenant,delivery_key,endpoint_id,endpoint_digest,request_digest,payload_digest,nonce) VALUES(%s,%s,'synthetic-endpoint',%s,%s,%s,%s)",((tenant,sha256(str(i).encode()).hexdigest(),digest,digest,digest,f"http-{i}") for i in range(n)))
            with roles.project_state.connection() as conn,conn.transaction():
                settings(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO projectos_states(tenant_id,namespace,project_id,revision,state) VALUES(%s,'health',%s,1,%s::jsonb)",((tenant,f"project-{i}",encoded) for i in range(n)))
                    cur.executemany("INSERT INTO reference_clinical_state_v1(workspace_id,owner_id,session_id,revision,record_digest,payload) VALUES(%s,%s,%s,1,%s,%s::jsonb)",((tenant,tenant+":clinician",f"session-{i}",digest,encoded) for i in range(n)))
            for site in sites:
                q=site["expression"];l=site["locus"]
                if l.startswith("PostgresRosterStore"):duty,params="governor",("fixture-installation",)
                elif l=="GuardedPostgresRevocationLedger.receipt":duty,params="governor",(tenant,"governance:withdraw-tenant-epoch","nonce-0",digest)
                elif l in ("BudgetedHttpAttempts.record","PostgresHttpAttempts.get"):duty,params="receiver",(tenant,sha256(b"0").hexdigest())
                elif l=="DurableClock._read":duty,params="clock",(roles.domain,)
                elif l=="RetainedClinicalStore.get":duty,params="project_state",(tenant,tenant+":clinician","session-0")
                elif l in ("RetainedClinicalLineage.retain","PostgresProjectStateStore.load"):duty,params="project_state",(tenant,"health","project-0")
                elif l=="PartitionedActivationLedger.pack_ids":duty,params="governor",()
                elif "reference_pack_tenants_v1" in q:duty,params="governor",(pack,tenant)
                else:duty,params="governor",(pack,)
                assert q.count("%s")==len(params)
                with getattr(roles,duty).connection() as conn,conn.transaction():
                    settings(conn,tenant)
                    plan=conn.execute("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+q,params).fetchone()[0]
                out["results"].append({"source_site":site,"fixture_rows":n,"prior_history":n,"role":duty,"relation_work":relations(plan[0]["Plan"]),"plan":plan})
            Path(sys.argv[1]).write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
            print(f"Retained {len(sites)} source plans at {n}",flush=True)
        finally:
            owner.close()
            for field in fields(roles):
                pool=getattr(roles,field.name)
                if callable(getattr(pool,"close",None)):pool.close()
if __name__=="__main__":main()
