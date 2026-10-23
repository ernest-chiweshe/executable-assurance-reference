"""Measure synthetic governance-log work in a fresh isolated reference database.

Fixture seeding is outside measurements; no external effects or production state.
This component diagnostic is not an end-to-end speedup benchmark.
"""
from dataclasses import fields
import json
import os
from pathlib import Path
import sys
import time

from history_work import PoolObservation, WorkCounts
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.tenant_fences import TenantFencedGovernanceLog
from regulated_core.canonical import canonical_bytes
from regulated_core.governance_targets import GovernanceEvent, event_body
from regulated_core.persistence_pg import PostgresGovernanceLog, _tenant


def event(tenant, serial):
    return GovernanceEvent(tenant, "synthetic-kind", "synthetic-subject", "a" * 64,
                           "absent", f"nonce-{serial}", f"record-{serial}", serial,
                           operation="synthetic-operation", scope="synthetic:" + tenant)


def seed(pool, tenant, size):
    with pool.connection() as connection, connection.transaction():
        _tenant(connection, tenant)
        with connection.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO regulated_governance_events_v1"
                " (tenant,seq,nonce,phase,scope,event_digest,body) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                ((tenant, i, e.nonce, e.phase, e.scope, e.digest(), canonical_bytes(event_body(e)).decode())
                 for i in range(size) for e in [event(tenant, i)]),
            )


def main():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    counts = WorkCounts()
    pool = PoolObservation(roles.governor, counts)
    results = []
    try:
        for log_type in (PostgresGovernanceLog, TenantFencedGovernanceLog):
            for size in (0, 1000, 10000):
                tenant = f"history-{log_type.__name__}-{size}"
                seed(roles.governor, tenant, size)
                log = log_type(pool=pool, **({"tenant": tenant} if log_type is TenantFencedGovernanceLog else {}))
                actions = {
                    "root": lambda: log.root(tenant),
                    "committed_missing": lambda: log.committed(tenant, "absent-nonce"),
                    "attempt_missing": lambda: log.attempt(tenant, "absent-nonce"),
                    "changes": lambda: log.changes(tenant),
                    "append_including_root": lambda: log.append(event(tenant, size)),
                }
                for name, action in actions.items():
                    with counts.observe(GovernanceEvent, "digest", "governance_digest_calls"):
                        with counts.measuring():
                            started = time.perf_counter()
                            result = action()
                            elapsed = (time.perf_counter() - started) * 1000
                    results.append({"implementation": log_type.__name__, "prior_events": size,
                                    "operation": name, "elapsed_ms": elapsed, "work": counts.snapshot(),
                                    "result_count": len(result) if name == "changes" else None})
                    print(json.dumps(results[-1]), flush=True)
        output = {"scope": "Synthetic isolated component diagnostic; not end-to-end qualification.",
                  "fixture": "Fresh unique tenants; valid synthetic committed log events seeded before measurement.",
                  "row_counter_limit": "Rows returned, not internal rows scanned. SQL plans require separate review.",
                  "results": results}
        Path(sys.argv[1]).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    finally:
        for field in fields(roles):
            value = getattr(roles, field.name)
            if callable(getattr(value, "close", None)):
                value.close()


if __name__ == "__main__":
    main()
