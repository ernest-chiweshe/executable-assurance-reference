"""Reject process-test execution unless the launcher names this owned cluster."""

import os
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict


def verify_isolated_worker_database():
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    settings = conninfo_to_dict(dsn)
    port = os.environ.get("REFERENCE_ISOLATED_PG_PORT", "")
    directory = os.environ.get("REFERENCE_ISOLATED_PG_DATA", "")
    if (not port.isdecimal() or not 1 <= int(port) <= 65535 or not directory
            or settings.get("dbname") != "factory_test"
            or settings.get("host") != "127.0.0.1"
            or settings.get("hostaddr", "127.0.0.1") != "127.0.0.1"
            or settings.get("port") != port or settings.get("service")):
        raise ValueError("process tests require the explicit isolated launcher endpoint")
    # A port alone is not proof of ownership. This read precedes every fixture
    # migration and worker action; a failed match never falls back elsewhere.
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        actual = conn.execute("SHOW data_directory").fetchone()[0]
        domain = conn.execute("SELECT 'pg:' || system_identifier::text FROM pg_control_system()").fetchone()[0]
    if Path(actual).resolve() != Path(directory).resolve():
        raise ValueError("process test connection is not the launcher's owned cluster")
    return dsn, domain
