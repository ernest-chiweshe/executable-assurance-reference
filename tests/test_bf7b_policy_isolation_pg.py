"""B-F7b population-independent isolation proof on the provisioned restricted schema; isolated PostgreSQL.

For every row-level-secured authority table in the role contract, the live catalog of a freshly provisioned schema shows:
row-level security enabled and forced; at least one policy; no permissive policy whose read or write condition is
absent or unconditional; and every policy condition comparing a row value to a session setting (``app.*``) that the
host sets per request. No runtime login is a superuser, bypasses row-level security, or owns any table. With these, a
row belonging to another tenant is not visible to, or writable by, any runtime login whatever the table holds; the
populated two-tenant contracts (test_tenant_row_isolation_pg.py, test_bf7b_tenant_fences_pg.py) show the same
behaviour on real rows. The exact per-table policies, including the roles each applies to, are pinned in
docs/provenance/c060-bf7b-tenant-stores/POLICIES.json and must match the live catalog field for field; connected as
each runtime login, row security is active on every RLS table. Catalog evidence; no rows are inserted and no guard is
changed.
"""
import json
import os
from pathlib import Path
import re

from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.role_contract import RLS_TABLES as CONTRACT_RLS_TABLES, ROLES

# Every provisioned schema uses the tenant-partitioned pack lifecycle (candidate 060), which adds its own forced-RLS
# tenant table to the contract's RLS tables.
RLS_TABLES = CONTRACT_RLS_TABLES | {"reference_pack_tenants_v1"}
# A row value compared with a per-request session setting, as PostgreSQL deparses it.
SESSION_COMPARISON = re.compile(r"=\s*current_setting\('app\.[a-z_]+'::text,\s*true\)")
UNCONDITIONAL = {"true", "(true)"}
ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("policy", "permissive", "roles", "cmd", "using", "with_check")


def test_every_rls_table_is_forced_and_scoped_by_a_session_setting():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    owner = LocalPool(os.environ["FACTORY_TEST_DB_URL"], roles.schema, "migration-owner")
    try:
        with owner.connection() as conn:
            flags = dict((name, (enabled, forced)) for name, enabled, forced in conn.execute(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relkind IN ('r','p')",
                (roles.schema,)).fetchall())
            policies = conn.execute(
                "SELECT tablename, policyname, permissive, roles::text, cmd, qual, with_check FROM pg_policies "
                "WHERE schemaname = %s", (roles.schema,)).fetchall()
            logins = {getattr(roles, kind).role for kind in ROLES}
            attributes = conn.execute(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = ANY(%s)", (sorted(logins),)
            ).fetchall()
            owned = conn.execute(
                "SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relkind IN ('r','p') "
                "AND pg_get_userbyid(c.relowner) = ANY(%s)", (roles.schema, sorted(logins))).fetchall()
        # Effective applicability per login: connected as each runtime login, row security is active on every RLS table.
        inactive = []
        for kind in ROLES:
            with getattr(roles, kind).connection() as conn:
                for table in sorted(RLS_TABLES):
                    active, = conn.execute("SELECT row_security_active(%s::regclass)", (table,)).fetchone()
                    if active is not True:
                        inactive.append((kind, table))
    finally:
        owner.close()
        for kind in ROLES:
            getattr(roles, kind).close()
    by_table = {}
    for table, name, permissive, granted, cmd, qual, check in policies:
        by_table.setdefault(table, []).append((name, permissive, granted, cmd, qual, check))
    checked = 0
    for table in sorted(RLS_TABLES):
        assert flags.get(table) == (True, True), (table, flags.get(table))
        assert by_table.get(table), ("no policy", table)
        for name, permissive, granted, cmd, qual, check in by_table[table]:
            conditions = [condition for condition in (qual, check) if condition is not None]
            assert conditions, (table, name, "policy without any condition")
            for condition in conditions:
                assert condition.strip() not in UNCONDITIONAL, (table, name, condition)
                assert SESSION_COMPARISON.search(condition), (table, name, condition)
            if permissive == "PERMISSIVE" and cmd in ("ALL", "SELECT"):
                assert qual is not None, (table, name, "permissive read without a row condition")
        checked += 1
    assert checked == len(RLS_TABLES) == 35
    # Exact reviewed semantics: the live policies equal the pinned per-table policy set, field for field, roles included.
    pinned = json.loads((ROOT / "docs/provenance/c060-bf7b-tenant-stores/POLICIES.json").read_text(encoding="utf-8"))
    live = {table: [dict(zip(FIELDS, entry)) for entry in sorted(entries)]
            for table, entries in by_table.items() if table in RLS_TABLES}
    expected = {table: [{key: policy[key] for key in FIELDS} for policy in sorted(policies, key=lambda p: p["policy"])]
                for table, policies in pinned["tables"].items()}
    assert live == expected
    # One permissive policy per table, for every role and every command. USING (existing rows read, updated or deleted)
    # is the WITH CHECK condition (rows written), or stricter: clinical state also hides removed sessions.
    assert all(len(policies) == 1 and policies[0]["permissive"] == "PERMISSIVE" and policies[0]["roles"] == "{public}"
               and policies[0]["cmd"] == "ALL" and policies[0]["with_check"][1:-1] in policies[0]["using"]
               for policies in expected.values())
    assert inactive == [], inactive
    assert len(attributes) == len(logins) == 19
    assert all(not superuser and not bypass for _, superuser, bypass in attributes), attributes
    assert owned == [], owned
