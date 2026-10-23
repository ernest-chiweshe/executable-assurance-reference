"""Retain actual query plans for growing synthetic histories in an isolated DB.

All installed constraints/triggers remain active. Seeding is outside the measured
queries. These are query-work diagnostics, not end-to-end performance claims.
"""
from dataclasses import fields
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import _tenant
from measure_governance_history import seed as seed_governance
from regulated_core.canonical import canonical_bytes, digest_hex
from regulated_core.evidence import DecisionRecorder
from regulated_core.models import Action, ActionEffect, Decision, DecisionRecord, PolicyRef
from regulated_core.signing import Ed25519Signer, TrustDirectory


def source_queries(tenant, mission, scope):
    """Use catalogued AST strings and verify their source hashes before EXPLAIN.

    The older manually selected plans remain separate evidence. These exact
    query families add coverage; they do not cover every action query.
    """
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "docs/provenance/history-read-classifications.json").read_bytes())
    selectors = {
        "PostgresDecisionRecorder.entries": ("recorder", (tenant,)),
        "PostgresDecisionRecorder._append_on": ("recorder", (tenant,)),
        "ReferenceDecisionRecorder._sign_entry": ("recorder", (tenant,)),
        "PostgresGovernanceLog.events": ("governor", (tenant,)),
        "PostgresGovernanceLog.append": ("governor", (tenant,)),
        "TenantFencedGovernanceLog.append": ("governor", (tenant,)),
        "TenantFencedGovernanceLog.unresolved": ("governor", (tenant, scope)),
        "PostgresEgressScopeStore._read": ("egress_reader", (tenant,)),
        "PostgresMissionBudget._rows": ("allocator", (tenant, mission, "reservation-0")),
        "PostgresMissionBudget.reserve": ("allocator", (tenant, mission)),
        "PostgresMissionBudget._request_attempt_on": ("allocator", (tenant, mission, "reservation-0")),
        "PostgresMissionBudget.consume_permit_on": ("allocator", (tenant, mission, "reservation-0")),
        "PostgresMissionBudget.consume": ("allocator", (tenant, mission, "reservation-0")),
        "PostgresMissionBudget.committed": ("allocator", (tenant, mission)),
    }
    for site in catalog["sites"]:
        if site["kind"] != "history_sql" or site["locus"] not in selectors:
            continue
        assert sha256((root / site["path"]).read_bytes()).hexdigest() == site["source_sha256"]
        query = site["expression"]
        assert query.startswith("SELECT ")
        duty, params = selectors[site["locus"]]
        assert query.count("%s") == len(params)
        yield site, duty, query, params


def seed_decisions(pool, tenant, size):
    """Valid synthetic signed denial history; never used to authorize an effect."""
    signer, trust = Ed25519Signer("fixture:query-plan"), TrustDirectory()
    trust.register_signer(signer)
    recorder = DecisionRecorder(signer, trust)
    for i in range(size):
        record = DecisionRecord(f"record-{i}", tenant, f"assertion-{i}", "a" * 64,
            Action("fixture:query", ActionEffect.REVERSIBLE), "fixture", "query-plan", str(i),
            PolicyRef("fixture", "query-plan", "1"), Decision.deny("FIXTURE", "Synthetic diagnostic denial"), i)
        recorder.append(record, digest_hex(record))
    assert recorder.verify_chain(tenant)
    with pool.connection() as connection, connection.transaction():
        _tenant(connection, tenant)
        with connection.cursor() as cursor:
            cursor.executemany("INSERT INTO regulated_decision_evidence_v1 (tenant,seq,entry_hash,envelope) VALUES (%s,%s,%s,%s::jsonb)",
                ((tenant, env.seq, env.chain_hash(), canonical_bytes(env).decode()) for env in recorder.entries(tenant)))


def relation_work(node):
    result = []
    if "Relation Name" in node:
        result.append({key: node.get(key) for key in (
            "Node Type", "Relation Name", "Index Name", "Actual Rows", "Actual Loops",
            "Rows Removed by Filter", "Rows Removed by Index Recheck", "Shared Hit Blocks", "Shared Read Blocks")})
    for child in node.get("Plans", []):
        result.extend(relation_work(child))
    return result


def main():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    out = {"scope": "Isolated query-work diagnostic; installed guards active; timing not qualified under concurrent test load.",
           "results": [], "limits": ["Exact normalized AST SELECT strings from hash-checked source; no INSERT or authorization is explained.",
                                      "Synthetic signed denials, reserve-only budget events, closed fences and inventory events; other distributions remain pending.",
                                      "Other action queries remain pending; this is not complete phase0 coverage."],
           "script_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        with roles.receiver.connection() as connection:
            out["version"] = connection.execute("SELECT version()").fetchone()[0]
        for size in (1000, 10000):
            tenant, mission, scope = f"plan-fixture-{size}", "same-mission", "same-scope"
            seed_governance(roles.governor, tenant, size)
            seed_decisions(roles.recorder, tenant, size)
            with roles.egress_scope.connection() as connection, connection.transaction():
                _tenant(connection, tenant)
                with connection.cursor() as cursor:
                    cursor.executemany("INSERT INTO regulated_egress_scope_v1 (tenant,revision,kind,pack_ref,packs,source) VALUES (%s,%s,'inventoried','','[]','synthetic-plan-fixture')",
                                       ((tenant, i + 1) for i in range(size)))
            with roles.governor.connection() as connection, connection.transaction():
                _tenant(connection, tenant)
                with connection.cursor() as cursor:
                    cursor.executemany("INSERT INTO reference_tenant_fences_v1 (tenant,scope,attempt,phase) VALUES (%s,%s,%s,%s)",
                                       ((tenant, scope, sha256(str(i).encode()).hexdigest(), phase)
                                        for i in range(size) for phase in ("open", "closed")))
            with roles.allocator.connection() as connection, connection.transaction():
                _tenant(connection, tenant)
                with connection.cursor() as cursor:
                    # Each reserve passes the actual budget writer and limit trigger.
                    cursor.executemany("INSERT INTO regulated_mission_budget_events_v1 (tenant,mission,reservation_id,kind,units,limit_units) VALUES (%s,%s,%s,'reserve',1,20000)",
                                       ((tenant, mission, f"reservation-{i}") for i in range(size)))
            for site, duty, query, params in source_queries(tenant, mission, scope):
                with getattr(roles, duty).connection() as connection, connection.transaction():
                    _tenant(connection, tenant)
                    plan = connection.execute("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, params).fetchone()[0]
                out["results"].append({"query": site["locus"], "source_site": site,
                                       "prior_history": size, "role": duty,
                                       "query_sha256": sha256(query.encode()).hexdigest(),
                                       "relation_work": relation_work(plan[0]["Plan"]), "plan": plan})
            Path(sys.argv[1]).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
            print(f"Retained plans for {size} prior records", flush=True)
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if callable(getattr(pool, "close", None)):
                pool.close()


if __name__ == "__main__":
    main()
