"""Read the isolated reference schema's immutable-table coverage.

This inventories installed no-mutation triggers; it is not a universal proof
that every possible schema or dynamically composed table has been inspected.
"""
from dataclasses import fields
import json
import os
from pathlib import Path
import sys

from assurance_reference.local_roles import provision_local_roles


def immutable_tables(connection):
    rows = connection.execute(
        "SELECT DISTINCT c.relname FROM pg_trigger t "
        "JOIN pg_class c ON c.oid=t.tgrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_proc p ON p.oid=t.tgfoid "
        "WHERE n.nspname=current_schema() AND NOT t.tgisinternal "
        "AND (t.tgtype & 8)<>0 AND (t.tgtype & 16)<>0 "
        "AND (p.proname LIKE '%no_mutation%' OR p.proname LIKE '%immutable%') "
        "ORDER BY c.relname"
    ).fetchall()
    return [row[0] for row in rows]


def main():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        with roles.receiver.connection() as connection:
            report = {"profile": "provision_local_roles", "version": connection.execute("SELECT version()").fetchone()[0],
                      "immutable_tables": immutable_tables(connection),
                      "append_only_by_design": ["collaboration_events"],
                      "limit": "Installed trigger inventory plus explicitly named design-only store; not runtime reach or query-plan proof."}
        Path(sys.argv[1]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if callable(getattr(pool, "close", None)):
                pool.close()


if __name__ == "__main__":
    main()
