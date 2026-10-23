"""Restricted prepared-path authority, independent ACLs, RLS and server guards.

Synthetic identity and business data; retained keys in one process. No claim of
root-admission, arbitrary-SQL tenant authentication or performance acceptance.
"""
from dataclasses import replace
import time
import psycopg
import pytest
from psycopg import sql

from assurance_reference.clock_floor import HOLD_ALLOWLIST, HOLD_GUARD
from assurance_reference.local_prepared_roles import provision_local_prepared_roles
from assurance_reference.role_contract import ROLES, collect_access_matrix
from regulated_core.target import Outcome
from restricted_prepared_pg_fixture import BODY, OLD, TENANTS, prepared_environment, restricted_prepared_cas_fixture
from versioned_cas_pg_fixture import snapshot
from test_receiver_commit_deadline_pg import _stall_last_check


def test_two_tenants_prepare_issue_commit_and_replay_on_restricted_roles(tmp_path):
    env = prepared_environment(tmp_path)
    fixtures = [restricted_prepared_cas_fixture(tmp_path, tenant=t, environment=env) for t in TENANTS]
    a, b = fixtures
    wrong_tenant = b["receiver"].commit(a["signed"], BODY)
    assert wrong_tenant.outcome is Outcome.FAILED
    for f in fixtures:
        before = {"state": (3, OLD), "uses": 0, "outcomes": [], "budget": 0}
        assert snapshot(f) == before
        bad = replace(f["signed"], signature=replace(f["signed"].signature, value="00" * 64))
        assert f["receiver"].commit(bad, BODY).outcome is Outcome.FAILED
        assert snapshot(f) == before
        result = f["receiver"].commit(f["signed"], BODY)
        assert result.outcome is Outcome.COMMITTED, result
        expected = {"state": (4, BODY), "uses": 1, "outcomes": ["committed"], "budget": 1}
        assert snapshot(f) == expected
        assert f["receiver"].commit(f["signed"], BODY).outcome is Outcome.COMMITTED
        assert snapshot(f) == expected
    tables = ("regulated_database_attempts_v1", "regulated_database_receipts_v1", "regulated_decision_uses_v1",
              "regulated_decision_inputs_v1", "regulated_preparations_v1")
    with env.roles.receiver.connection() as conn:
        for tenant in TENANTS:
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant,))
                for table in tables:
                    rows = conn.execute(sql.SQL("SELECT tenant FROM {}").format(sql.Identifier(table))).fetchall()
                    assert rows and set(rows) == {(tenant,)}, (table,tenant,rows)


@pytest.fixture(scope="module")
def profile_environment(tmp_path_factory):
    return prepared_environment(tmp_path_factory.mktemp("prepared-profile"))


def test_exact_acl_roles_membership_and_always_enabled_guards(profile_environment):
    env = profile_environment
    roles = env.roles
    names = [getattr(roles,k).role for k in (*ROLES,"issuer","reviewer")]
    with roles.issuer.connection() as conn:
        attrs = conn.execute("SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,"
                             "rolreplication,rolinherit FROM pg_roles WHERE rolname=ANY(%s)", (names,)).fetchall()
        assert len(attrs) == len(names)
        assert all(row[1] and not any(row[2:]) for row in attrs)
        assert conn.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
                            "JOIN pg_roles g ON g.oid=m.roleid WHERE r.rolname=ANY(%s) OR g.rolname=ANY(%s)",
                            (names,names)).fetchone()[0] == 0
        unguarded = [r[0] for r in conn.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND c.relkind IN ('r','p') AND NOT c.relispartition "
            "AND NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname=%s AND t.tgenabled='A')",
            (HOLD_GUARD,)).fetchall()]
        assert set(unguarded) == HOLD_ALLOWLIST
        trigger = conn.execute("SELECT t.tgdeferrable,t.tginitdeferred,t.tgenabled,p.prosecdef "
            "FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid "
            "WHERE t.tgrelid='regulated_database_receipts_v1'::regclass AND t.tgname='receiver_commit_deadline_v1'").fetchone()
        assert trigger == (True,True,'A',True)
    # Existing audit executed inside prepared_environment before business tables;
    # these additional business privileges have their own exact column check.
    with roles.receiver.connection() as conn:
        for table in ("reference_root_members","reference_root_requests"):
            assert not conn.execute("SELECT has_table_privilege(current_user,%s,'UPDATE')", (table,)).fetchone()[0]
            columns = conn.execute("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'UPDATE') "
                "FROM pg_attribute WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped", (table,)).fetchall()
            assert {name for name,allowed in columns if allowed} == {"lock_anchor"}


@pytest.mark.parametrize("role,table", [
    ("issuer","regulated_preparations_v1"), ("issuer","regulated_database_receipts_v1"),
    ("receiver","regulated_reviews_v1"), ("reviewer","regulated_preparations_v1"),
    ("allocator","regulated_database_attempts_v1"), ("recorder","regulated_database_receipts_v1"),
    ("receiver","regulated_budget_writer_roles_v1"), ("recorder","regulated_preparation_writers_v1"),
])
def test_cross_duty_writes_are_denied(profile_environment, role, table):
    env = profile_environment
    with getattr(env.roles,role).connection() as conn:
        assert conn.execute("SELECT has_table_privilege(current_user,%s,'INSERT')", (table,)).fetchone() == (False,)
        columns = conn.execute("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'INSERT') "
            "FROM pg_attribute WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped", (table,)).fetchall()
        assert columns and not any(allowed for name,allowed in columns), (role,table,columns)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant',%s,true)", (TENANTS[0],))
                # Requires INSERT only: a missing SELECT cannot mask a write grant.
                conn.execute(sql.SQL("INSERT INTO {} DEFAULT VALUES").format(sql.Identifier(table)))


def test_restricted_receiver_stall_is_refused_by_deferred_deadline(tmp_path, monkeypatch):
    f = restricted_prepared_cas_fixture(tmp_path, admission_window_us=3_000_000)
    def wait_past(permit, reading):
        time.sleep(3.3)
    calls = _stall_last_check(monkeypatch, wait_past)
    result = f["receiver"].commit(f["signed"], BODY)
    assert len(calls) == 2
    assert result.outcome is Outcome.FAILED and "authority expired at database commit" in result.detail, result
    assert snapshot(f) == {"state": (3, OLD), "uses": 0, "outcomes": ["not_committed"], "budget": 0}


def test_hold_refuses_new_profile_writes_with_rh001(tmp_path):
    f = restricted_prepared_cas_fixture(tmp_path)
    roles = f["roles"]
    with roles.clock.connection() as conn, conn.transaction():
        assert conn.execute("SELECT reference_clock_floor_hold_v1(%s,%s,%s)",
                            (roles.domain,"synthetic profile hold",0)).fetchone()[0] > 0
    for kind,table in (("receiver","regulated_database_attempts_v1"),
                       ("recorder","regulated_decision_inputs_v1"),
                       ("reviewer","regulated_reviews_v1")):
        with getattr(roles,kind).connection() as conn:
            with pytest.raises(psycopg.DatabaseError) as refused:
                with conn.transaction():
                    conn.execute("SELECT set_config('app.tenant',%s,true)", (f["tenant"],))
                    conn.execute(sql.SQL("INSERT INTO {} SELECT * FROM {} WHERE false").format(
                        sql.Identifier(table),sql.Identifier(table)))
            assert refused.value.sqlstate == "RH001"
    assert snapshot(f)["state"] == (3, OLD)


@pytest.mark.parametrize("replacement", ["BEGIN", "BEGIN; SELECT 1/0", "BEGIN; SAVEPOINT regulated_effect_v1",
                                          "BEGIN; SAVEPOINT regulated_effect_v1; SELECT 1/0"])
@pytest.mark.parametrize("error_kind", ["EmissionError", "BudgetError"])
def test_restricted_transaction_replacement_remains_unknown(tmp_path, monkeypatch, replacement, error_kind):
    import test_receiver_effect_transaction_replacement as original
    monkeypatch.setattr(original, "prepared_cas_fixture", restricted_prepared_cas_fixture)
    original.test_committed_effect_replaced_transaction_then_refusal_is_unknown(
        tmp_path, getattr(original,error_kind), replacement)


@pytest.mark.parametrize("abort_sql", [False, True])
@pytest.mark.parametrize("error_kind", ["EmissionError", "BudgetError"])
def test_restricted_original_transaction_refusal_is_tombstoned(tmp_path, monkeypatch, abort_sql, error_kind):
    import test_receiver_effect_transaction_replacement as original
    monkeypatch.setattr(original, "prepared_cas_fixture", restricted_prepared_cas_fixture)
    original.test_original_transaction_refusal_can_be_tombstoned(tmp_path, getattr(original,error_kind), abort_sql)
