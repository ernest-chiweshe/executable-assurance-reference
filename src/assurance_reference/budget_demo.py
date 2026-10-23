"""Bounded PostgreSQL budget-store checks; no permit or external effect is issued."""

from __future__ import annotations

import argparse
import hashlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.demo import SchemaConnections
from regulated_core import canonical_bytes
from regulated_core.budget import BudgetError
from regulated_core.persistence_pg import PostgresMissionBudget, migrate


def run(output: Path, dsn: str) -> dict:
    """Retain one small schema and its observations in the standing test database."""
    if conninfo_to_dict(dsn).get("dbname") != "factory_test":
        raise ValueError("budget checks require the standing factory_test database")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    schema = "test_reference_" + uuid.uuid4().hex
    (output / "run.json").write_bytes(
        canonical_bytes({"schema": schema, "schema_retained": True, "status": "STARTED"})
        + b"\n"
    )
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    with pool.connection() as connection, connection.transaction():
        # Explicit fixture provisioning in this new schema. All insertion guards stay active.
        connection.execute(
            "INSERT INTO regulated_budget_writer_roles_v1 (role_name, kind) "
            "SELECT session_user::text, kind FROM "
            "(VALUES ('reserve'), ('consume'), ('release')) AS kinds(kind)"
        )
        connection.execute(
            "CREATE TABLE reference_budget_effect_v1 "
            "(tenant text, receipt text, body bytea, PRIMARY KEY (tenant,receipt))"
        )
    tenant, mission = "budget-fixture-a", "one-local-receipt"
    body = b"Synthetic database receipt; not an authorized application release."
    subject = hashlib.sha256(body).hexdigest()
    start = threading.Barrier(2, timeout=10)

    def reserve(worker):
        ledger = PostgresMissionBudget(pool=SchemaConnections(dsn, schema))
        start.wait()
        try:
            reservation = ledger.reserve(
                tenant, mission, reservation_id=worker, units=1, limit=1,
                subject_digest=subject,
            )
            return reservation.reservation_id, "reserved"
        except BudgetError:
            return worker, "refused"

    with ThreadPoolExecutor(max_workers=2) as workers:
        admissions = list(workers.map(reserve, ("worker-a", "worker-b")))
    if sorted(result for _, result in admissions) != ["refused", "reserved"]:
        raise RuntimeError("the final unit was not allocated to exactly one worker")
    winner = next(worker for worker, result in admissions if result == "reserved")

    class RollbackFixture(Exception):
        pass

    def consume(connection):
        connection.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
        PostgresMissionBudget(pool=pool).consume_on(
            connection, tenant, mission, winner, subject_digest=subject, units=1, limit=1,
        )
        connection.execute(
            "INSERT INTO reference_budget_effect_v1 VALUES (%s,%s,%s)",
            (tenant, winner, body),
        )

    try:
        with pool.connection() as connection, connection.transaction():
            consume(connection)
            raise RollbackFixture()
    except RollbackFixture:
        pass
    rebuilt = PostgresMissionBudget(pool=SchemaConnections(dsn, schema))
    with pool.connection() as connection:
        rolled_back_rows = connection.execute(
            "SELECT count(*) FROM reference_budget_effect_v1"
        ).fetchone()[0]
    if rolled_back_rows != 0 or rebuilt.committed(tenant, mission) != 0:
        raise RuntimeError("rollback left consumption or a database receipt")
    with pool.connection() as connection, connection.transaction():
        consume(connection)
    with pool.connection() as connection:
        receipts = connection.execute(
            "SELECT tenant,receipt,body FROM reference_budget_effect_v1"
        ).fetchall()
    if receipts != [(tenant, winner, body)] or rebuilt.committed(tenant, mission) != 1:
        raise RuntimeError("receipt and consumption did not commit together")
    replay_refused = False
    try:
        with pool.connection() as connection, connection.transaction():
            consume(connection)
    except BudgetError:
        replay_refused = True
    if not replay_refused:
        raise RuntimeError("consumed reservation admitted a second consumption")
    rebuilt.release(tenant, mission, winner)
    exhausted = False
    try:
        rebuilt.reserve(tenant, mission, reservation_id="later", units=1, limit=1)
    except BudgetError:
        exhausted = True
    if not exhausted or rebuilt.committed(tenant, mission) != 1:
        raise RuntimeError("consumed capacity was returned")
    other = rebuilt.reserve(
        "budget-fixture-b", mission, reservation_id="other", units=1, limit=1,
    )
    # No permit was created in this fixture, so unused capacity can be returned.
    rebuilt.release(other.tenant_id, mission, other.reservation_id)
    rebuilt.reserve(other.tenant_id, mission, reservation_id="replacement", units=1, limit=1)
    with pool.connection() as connection:
        events = connection.execute(
            "SELECT tenant,mission,reservation_id,kind,units,limit_units,subject_digest "
            "FROM regulated_mission_budget_events_v1 "
            "ORDER BY tenant,mission,reservation_id,kind"
        ).fetchall()
    result = {
        "schema": schema,
        "status": "PASS",
        "admissions": admissions,
        "rollback": {"effect_rows": rolled_back_rows, "consumed_units": 0},
        "committed_units": rebuilt.committed(tenant, mission),
        "receipt_sha256": hashlib.sha256(receipts[0][2]).hexdigest(),
        "replay_refused": replay_refused,
        "consumed_capacity_retained": exhausted,
        "events": events,
        "limits": [
            "Budget-store component fixture; no engine permit, delegation or external effect.",
            "Two threads with separate connections; no process crash or network partition.",
            "One provisioned database login; tenant key separation is not RLS qualification.",
            "Limit and subject are fixture inputs; production must derive them from trusted policy.",
            "Database atomicity does not establish filesystem or physical G4 atomicity.",
            "Unsigned local observations; no deployed custody or independent attestation.",
        ],
    }
    (output / "budget.json").write_bytes(canonical_bytes(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    if not dsn:
        parser.error("FACTORY_TEST_DB_URL is required")
    result = run(args.output, dsn)
    print("PASS: one final unit, atomic database receipt, retained spent capacity")
    print("Retained schema:", result["schema"])


if __name__ == "__main__":
    main()
