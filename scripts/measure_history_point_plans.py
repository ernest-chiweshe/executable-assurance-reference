"""Exact-source point-query plans in an owned, guarded diagnostic cluster."""
from dataclasses import fields
from hashlib import sha256,pbkdf2_hmac
import json,os,sys
from pathlib import Path
from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import _tenant
from regulated_core.canonical import canonical_bytes,digest_hex
from measure_history_plans_additional import relations

def main():
    root=Path(__file__).resolve().parents[1]
    catalog=json.loads((root/"docs/provenance/history-read-classifications.json").read_bytes())
    loci={"LocalSessions.login","LocalSessions.authenticate","LocalSessions.resolve","LocalSessions.admit","LocalSessions.admit_many","PostgresPermitUseStore.used_on","PostgresReviewStore._latest"}
    sites=[s for s in catalog["sites"] if s["kind"]=="history_sql" and s["locus"] in loci]
    for site in sites:
        assert sha256((root/site["path"]).read_bytes()).hexdigest()==site["source_sha256"]
    roles=provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    out={"scope":"Exact-source SELECT plans only; no login, approval, permit authorization or external effect.","script_sha256":sha256(Path(__file__).read_bytes()).hexdigest(),"helper_sha256":sha256((root/"scripts/measure_history_plans_additional.py").read_bytes()).hexdigest(),"limits":["Synthetic identities and sessions; half sessions revoked; no authentication timing claim.","Synthetic review payloads are not approvals; no signing or authority validation invoked.","Measures present/absent indexed lookup plans, not lock contention, PBKDF, caller end-to-end latency or all distributions."],"results":[]}
    try:
        salt=b"synthetic-only-fixture-salt-000000"; password_hash=pbkdf2_hmac("sha256",b"synthetic-fixture-password",salt,600000)
        payload={"fixture":True,"authority":False}
        for n in (1000,10000):
            tenant=f"point-plan-{n}"
            with roles.session_issuer.connection() as conn,conn.transaction():
                _tenant(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO reference_identities_v1 (tenant,principal,username,salt,password_hash,active) VALUES(%s,%s,%s,%s,%s,true)",((tenant,f"principal-{i}",f"username-{i}",salt,password_hash) for i in range(n)))
                    cur.executemany("INSERT INTO reference_sessions_v1 (tenant,reference,principal,expires_at_us,revoked) VALUES(%s,%s,%s,%s,%s)",((tenant,f"session-{i}",f"principal-{i}",1000000000,bool(i%2)) for i in range(n)))
            with roles.receiver.connection() as conn,conn.transaction():
                _tenant(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO regulated_permit_uses_v1 (tenant,nonce) VALUES(%s,%s)",((tenant,f"nonce-{i}") for i in range(n)))
                    cur.executemany("INSERT INTO regulated_reviews_v1 (tenant,review_id,version,payload_digest,payload) VALUES(%s,'review-0',%s,%s,%s::jsonb)",((tenant,i,digest_hex(payload),canonical_bytes(payload).decode()) for i in range(n)))
            for site in sites:
                query=site["expression"];locus=site["locus"]
                for present in (True,False):
                    suffix="0" if present else "absent"
                    if locus=="PostgresPermitUseStore.used_on":duty,value="receiver",f"nonce-{suffix}"
                    elif locus=="PostgresReviewStore._latest":duty,value="receiver",f"review-{suffix}"
                    elif locus=="LocalSessions.login":duty,value="session_issuer",f"username-{suffix}"
                    elif "reference_sessions_v1" in query:duty,value="session_reader",f"session-{suffix}"
                    else:duty,value="session_reader",f"principal-{suffix}"
                    assert query.count("%s")==2
                    with getattr(roles,duty).connection() as conn,conn.transaction():
                        _tenant(conn,tenant)
                        plan=conn.execute("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query,(tenant,value)).fetchone()[0]
                    out["results"].append({"source_site":site,"prior_history":n,"present":present,"role":duty,"relation_work":relations(plan[0]["Plan"]),"plan":plan})
            Path(sys.argv[1]).write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
            print(f"Retained present/absent plans for {len(sites)} sites at {n}",flush=True)
    finally:
        for field in fields(roles):
            pool=getattr(roles,field.name)
            if callable(getattr(pool,"close",None)):pool.close()
if __name__=="__main__":main()
