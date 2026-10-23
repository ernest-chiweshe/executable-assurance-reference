"""Owned local clusters and read-only inventories for the D1 restore drill.

Fixture passwords stay in memory. This helper never connects to an existing
cluster, removes retained evidence, or resets a restored authority clock.
"""

from contextlib import ExitStack
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def save(path, value):
    path.write_bytes(canonical(value) + b"\n")


class OwnedCluster:
    def __init__(self, root, name, bins):
        self.path = root / name
        self.path.mkdir()
        self.data = self.path / "data"
        self.bins = bins
        self.started = self.stopped = False
        self.secret = secrets.token_urlsafe(40)
        with socket.socket() as probe:
            if os.name == "nt":
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        self.env.update(PGHOST="127.0.0.1", PGPORT=str(self.port), PGUSER="reference_admin",
                        PGPASSWORD=self.secret, PGDATABASE="factory_test", PGCONNECT_TIMEOUT="5")

    def command(self, name, args, label):
        suffix = ".exe" if os.name == "nt" else ""
        log = self.path / (label + ".log")
        # A Windows server process can inherit pg_ctl's pipe handles. Logging to
        # a file prevents communicate() waiting for a healthy server to exit.
        with log.open("wb") as stream:
            result = subprocess.run([str(self.bins / (name + suffix)), *map(str, args)],
                                    env=self.env, stdout=stream, stderr=subprocess.STDOUT, timeout=90)
        log.write_bytes(log.read_bytes().replace(self.secret.encode(), b"[REDACTED]"))
        if result.returncode:
            raise RuntimeError(f"{name} failed: retained {self.path.name}/{label}.log")

    @property
    def dsn(self):
        return make_conninfo(host="127.0.0.1", port=self.port, user="reference_admin",
                             password=self.secret, dbname="factory_test")

    def start(self):
        password_file = self.path / "init-password.txt"
        password_file.write_text(self.secret, encoding="ascii")
        try:
            self.command("initdb", ["-D", self.data, "-U", "reference_admin", "--encoding=UTF8",
                                    "--auth=scram-sha-256", "--pwfile=" + str(password_file)], "initdb")
        finally:
            # Only this newly-created, ephemeral bootstrap secret is removed.
            password_file.unlink(missing_ok=True)
        options = f"-h 127.0.0.1 -p {self.port}"
        if os.name != "nt":
            options += " -c unix_socket_directories=''"
        self.command("pg_ctl", ["-D", self.data, "-l", self.path / "server.log", "-o", options,
                                 "-w", "start"], "start")
        self.started = True
        self.command("createdb", ["factory_test"], "createdb")
        with psycopg.connect(self.dsn) as conn:
            path, identity = conn.execute("SELECT current_setting('data_directory'), "
                                          "system_identifier::text FROM pg_control_system()").fetchone()
            if Path(path).resolve() != self.data.resolve():
                raise RuntimeError("Connected server is not this newly owned cluster")
        return "pg:" + identity

    def stop(self):
        # Also catch a startup whose successful confirmation was lost.
        suffix = ".exe" if os.name == "nt" else ""
        status = subprocess.run([str(self.bins / ("pg_ctl" + suffix)), "-D", str(self.data), "status"],
                                env=self.env, capture_output=True, timeout=10)
        if status.returncode == 0:
            self.command("pg_ctl", ["-D", self.data, "-m", "fast", "-w", "stop"], "stop")
            self.stopped = True
        elif self.started and status.returncode == 3:
            self.stopped = True
        elif self.started:
            raise RuntimeError("Cannot confirm owned cluster shutdown")


def runtime_pools(roles):
    return [getattr(roles, field.name) for field in fields(roles)
            if field.name not in {"schema", "domain"}]


def inventory(owner, roles, *, representations=None):
    """Exact data and named guard catalog, kept in memory; no credential export."""
    with owner.connection() as conn, conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        names = [p.role for p in runtime_pools(roles)]
        tables = [r[0] for r in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename")]
        data = {name: sorted((r[0] for r in conn.execute(sql.SQL("SELECT to_jsonb(t) FROM {} t")
                    .format(sql.Identifier(name)))), key=canonical) for name in tables}
        queries = {
            "schema": "SELECT nspname,pg_get_userbyid(nspowner),nspacl::text FROM pg_namespace WHERE nspname=current_schema()",
            # pg_dump omits an explicit owner-only ACL when it equals the
            # PostgreSQL default. Compare every effective grant and grant option
            # in stable order, including PUBLIC, instead of NULL versus the
            # equivalent serialized owner ACL. Ownership/RLS remain separate.
            "relations": """SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,
                pg_get_userbyid(c.relowner),
                CASE WHEN c.relkind IN ('r','p','v','m','S','f') THEN
                    COALESCE((SELECT jsonb_agg(jsonb_build_array(
                        pg_get_userbyid(a.grantor),
                        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                        a.privilege_type,a.is_grantable)
                        ORDER BY pg_get_userbyid(a.grantor),
                        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                        a.privilege_type,a.is_grantable)
                    FROM aclexplode(COALESCE(c.relacl,acldefault(
                        CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) a),
                    '[]'::jsonb) ELSE NULL END
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname=current_schema() ORDER BY c.relname""",
            "columns": "SELECT c.relname,a.attname,a.attacl::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
            "policies": "SELECT tablename,policyname,permissive,roles,cmd,qual,with_check FROM pg_policies WHERE schemaname=current_schema() ORDER BY tablename,policyname",
            "triggers": "SELECT c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
            "constraints": "SELECT c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() ORDER BY c.relname,k.conname",
            "functions": "SELECT p.proname,pg_get_function_identity_arguments(p.oid),pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig,p.proacl::text,pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)",
        }
        catalog = {key: [list(row) for row in conn.execute(query)] for key, query in queries.items()}
        if representations is not None:
            # Preserve the raw form from this same read-only snapshot as an
            # inspection artifact; semantic equality still compares every grant.
            representations["relation_acls"] = [list(row) for row in conn.execute(
                "SELECT c.relname,c.relacl::text FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() ORDER BY c.relname")]
        catalog["roles"] = [list(row) for row in conn.execute(
            "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil::text,rolconfig FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname", (names,))]
        catalog["memberships"] = [list(row) for row in conn.execute(
            "SELECT parent.rolname,child.rolname,m.admin_option FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON child.oid=m.member WHERE child.rolname=ANY(%s) OR parent.rolname=ANY(%s) ORDER BY parent.rolname,child.rolname", (names, names))]
        catalog["clock_function"] = [[name, conn.execute(
            "SELECT has_function_privilege(%s,'pg_catalog.pg_control_system()','EXECUTE')", (name,)).fetchone()[0]] for name in sorted(names)]
    return {"tables": data, "catalog": catalog}


def public_inventory(value):
    return {"sha256": digest(value), "catalog_sha256": digest(value["catalog"]),
            "tables": {name: {"rows": len(rows), "sha256": digest(rows)}
                       for name, rows in value["tables"].items()}}


def restore_runtime_logins(cluster, roles):
    """Re-create only the exact fixture logins, not a cluster-wide role dump.

    Passwords are reused from the surviving fixture process in memory. This is
    explicitly not cold-start credential recovery or production key custody.
    """
    with psycopg.connect(cluster.dsn) as conn:
        for pool in runtime_pools(roles):
            credentials = conninfo_to_dict(pool._dsn)
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                                 "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
                         .format(sql.Identifier(pool.role), sql.Literal(credentials["password"])))
            # System catalog function ACLs are not included by a schema dump.
            conn.execute(sql.SQL("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}")
                         .format(sql.Identifier(pool.role)))


def reconnect_runtime_pools(cluster, roles):
    """Move fixture connections only; never rewrite domains, keys or permits."""
    with psycopg.connect(cluster.dsn) as conn:
        directory, identity = conn.execute(
            "SELECT current_setting('data_directory'),system_identifier::text FROM pg_control_system()"
        ).fetchone()
    if Path(directory).resolve() != cluster.data.resolve():
        raise RuntimeError("Retarget destination is not the owned restored cluster")
    expected_domain = "pg:" + identity
    if expected_domain == roles.domain:
        raise RuntimeError("Restore transport must point to a distinct cluster")
    observations = []
    for pool in runtime_pools(roles):
        credentials = conninfo_to_dict(pool._dsn)
        pool.retarget(make_conninfo(**{**credentials, "host": "127.0.0.1", "port": str(cluster.port)}))
        # Fill all three slots after retiring the previous pool. Read identity
        # from each actual server connection, not from its configured DSN.
        with ExitStack() as stack:
            connections = [stack.enter_context(pool.connection()) for _ in range(3)]
            for conn in connections:
                system_id, port, login, schema, backend = conn.execute(
                    "SELECT system_identifier::text,inet_server_port(),session_user,"
                    "current_schema(),pg_backend_pid() FROM pg_control_system()"
                ).fetchone()
                observed = {"role": pool.role, "domain": "pg:" + system_id,
                            "port": port, "login": login, "schema": schema, "backend_pid": backend}
                observations.append(observed)
                if (observed["domain"] != expected_domain or port != cluster.port
                        or login != pool.role or schema != pool.schema):
                    raise RuntimeError("Runtime pool did not reconnect to its restored identity")
    save(cluster.path / "runtime-pool-retarget.json", {
        "scope": "Read-only transport identity check; authority remains HOLD",
        "original_authority_domain": roles.domain, "restored_transport_domain": expected_domain,
        "expected_port": cluster.port, "observations": observations})
