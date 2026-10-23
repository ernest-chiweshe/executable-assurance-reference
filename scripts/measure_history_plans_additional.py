"""Additional exact-source SELECT plans; isolated synthetic data, guards active."""
from dataclasses import fields
from hashlib import sha256
import json, os, sys
from pathlib import Path
from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import _tenant

def relations(node):
    rows=[]
    if "Relation Name" in node:
        rows.append({k:node.get(k) for k in ("Node Type","Relation Name","Index Name","Actual Rows","Actual Loops","Rows Removed by Filter","Shared Hit Blocks","Shared Read Blocks")})
    for child in node.get("Plans",[]): rows.extend(relations(child))
    return rows

def main():
    root=Path(__file__).resolve().parents[1]
    catalog=json.loads((root/"docs/provenance/history-read-classifications.json").read_bytes())
    loci={"GuardedPostgresRevocationLedger.governance_epoch","GuardedPostgresRevocationLedger.apply","PostgresRevocationLedger.epoch","TargetAuthority.current","PostgresGovernanceLog.unresolved","PostgresEgressScopeStore._append"}
    sites=[s for s in catalog["sites"] if s["kind"]=="history_sql" and s["locus"] in loci]
    for site in sites:
        assert sha256((root/site["path"]).read_bytes()).hexdigest()==site["source_sha256"]
        assert site["expression"].startswith("SELECT ")
    roles=provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    out={"scope":"Isolated exact-source query-work diagnostic; not latency qualification or authorization.","script_sha256":sha256(Path(__file__).read_bytes()).hexdigest(),"limits":["Synthetic revocation histories, closed fences, inventoried egress scopes and absent enrolled pack.","Enclosing function reach does not prove every query branch executed in action traces.","Timing under concurrent tests is unqualified; guards and role boundaries remain active."],"results":[]}
    try:
        for n in (1000,10000):
            tenant=f"additional-plan-{n}"; scope=f"scope-{n}"
            with roles.governor.connection() as conn,conn.transaction():
                _tenant(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO regulated_revocation_events_v1 (tenant,epoch,actor,reason,revoked_at_us) VALUES (%s,%s,'synthetic-fixture','plan diagnostic',%s)",((tenant,i,i) for i in range(1,n+1)))
                    cur.executemany("INSERT INTO regulated_governance_fences_v1 (scope,attempt,phase) VALUES (%s,%s,%s)",((scope,sha256(f"{n}:{i}".encode()).hexdigest(),phase) for i in range(n) for phase in ("open","closed")))
            with roles.egress_scope.connection() as conn,conn.transaction():
                _tenant(conn,tenant)
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO regulated_egress_scope_v1 (tenant,revision,kind,pack_ref,packs,source) VALUES (%s,%s,'inventoried','','[]','synthetic-fixture')",((tenant,i) for i in range(1,n+1)))
            for site in sites:
                query=site["expression"]
                if site["locus"]=="PostgresGovernanceLog.unresolved": duty,params="governor",(scope,)
                elif site["locus"]=="PostgresEgressScopeStore._append": duty,params="egress_scope",((tenant,"absent-pack#1") if query.count("%s")==2 else (tenant,))
                else: duty,params=("receiver" if site["locus"]=="TargetAuthority.current" else "governor"),(tenant,)
                assert query.count("%s")==len(params)
                with getattr(roles,duty).connection() as conn,conn.transaction():
                    _tenant(conn,tenant)
                    plan=conn.execute("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query,params).fetchone()[0]
                out["results"].append({"source_site":site,"prior_history":n,"role":duty,"query_sha256":sha256(query.encode()).hexdigest(),"relation_work":relations(plan[0]["Plan"]),"plan":plan})
            Path(sys.argv[1]).write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
            print(f"Retained {len(sites)} additional source-site plans at {n}",flush=True)
    finally:
        for field in fields(roles):
            pool=getattr(roles,field.name)
            if callable(getattr(pool,"close",None)):pool.close()
if __name__=="__main__":main()
