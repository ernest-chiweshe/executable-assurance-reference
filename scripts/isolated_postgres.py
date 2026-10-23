"""Run explicit local validation in a fresh, loopback-only PostgreSQL cluster.

No existing server, database or role is changed. The cluster and logs are kept
for inspection, then the server is stopped. A random administrator password is
kept only in memory after initialization, never printed or saved in the report.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time


def run(pg_bin: Path, root: Path, command: list[str], *, port: int = 0) -> int:
    if not command:
        raise ValueError("an explicit validation command is required")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be zero (ephemeral) or an explicit local TCP port")
    pg_bin = pg_bin.resolve(strict=True)
    root = root.absolute()
    root.mkdir(parents=True, exist_ok=False)
    secret = secrets.token_urlsafe(40)
    password_file = root / "init-password.txt"
    data, log = root / "data", root / "postgres.log"
    with socket.socket() as sock:
        if os.name == "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind(("127.0.0.1", port))
        port = sock.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="reference_admin",
               PGPASSWORD=secret, PGDATABASE="postgres", PGCONNECT_TIMEOUT="5")
    suffix = ".exe" if os.name == "nt" else ""

    def pg(name: str, args: list[str]) -> None:
        with (root / (name + ".log")).open("ab") as stream:
            subprocess.run([str(pg_bin / (name + suffix)), *args], env=env,
                           stdout=stream, stderr=subprocess.STDOUT, check=True,
                           timeout=60)

    report = {"scope": "Fresh isolated local validation; no production state",
              "host": "127.0.0.1", "port": port, "database": "factory_test",
              "started": False, "stopped": False, "validation_exit_code": None}
    started = time.monotonic()
    try:
        password_file.write_text(secret, encoding="ascii")
        try:
            pg("initdb", ["-D", str(data), "-U", "reference_admin", "--encoding=UTF8",
                          "--auth=scram-sha-256", "--pwfile=" + str(password_file)])
        finally:
            password_file.unlink(missing_ok=True)
        server_options = f"-h 127.0.0.1 -p {port}"
        if os.name != "nt":
            # All clients already use loopback TCP. A regular Linux user must
            # not need the system service's Unix-socket directory or privileges.
            server_options += " -c unix_socket_directories=''"
        pg("pg_ctl", ["-D", str(data), "-l", str(log), "-o",
                      server_options, "-w", "start"])
        report["started"] = True
        pg("createdb", ["factory_test"])
        # This child is the sole consumer of the ephemeral login. No command
        # text or connection string is copied into the retained report.
        env["FACTORY_TEST_DB_URL"] = (
            f"host=127.0.0.1 port={port} user=reference_admin "
            f"password={secret} dbname=factory_test"
        )
        # Test workers must match both this explicit endpoint and its owned
        # cluster directory before touching any fixture state.
        env["REFERENCE_ISOLATED_PG_PORT"] = str(port)
        env["REFERENCE_ISOLATED_PG_DATA"] = str(data.resolve())
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        with (root / "validation.log").open("wb") as stream:
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        validation_log = root / "validation.log"
        validation_log.write_bytes(validation_log.read_bytes().replace(secret.encode(), b"[REDACTED]"))
        report["validation_exit_code"] = result.returncode
        return result.returncode
    finally:
        # pg_ctl status also detects a server whose startup confirmation was lost.
        try:
            status = subprocess.run([str(pg_bin / ("pg_ctl" + suffix)), "-D", str(data),
                                     "status"], env=env, capture_output=True, timeout=10)
            if status.returncode == 0:
                pg("pg_ctl", ["-D", str(data), "-m", "fast", "-w", "stop"])
                report["stopped"] = True
            elif report["started"] and status.returncode == 3:
                report["stopped"] = True
        finally:
            report["elapsed_seconds"] = round(time.monotonic() - started, 2)
            (root / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0,
                        help="Explicit unused loopback port; default chooses an ephemeral port")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    sys.exit(run(args.pg_bin, args.work_root, command, port=args.port))


if __name__ == "__main__":
    main()
