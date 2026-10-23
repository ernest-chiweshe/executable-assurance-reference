"""B-F7b on lawful two-tenant population: two fictional schools release through the real API on one schema.

Both tenants' rows are written only by the restricted runtime logins along the ordinary Education release (no
administrator seeding). Then, for every runtime login and every row-level-secured table it may read, as each
tenant: every visible row belongs to that tenant (checked on the table's own tenant column), and the tables that
really hold rows for both tenants are recorded so the coverage is exact rather than vacuous. Population is shown
across the readers together; this does not show that each individual permitted reader sees its own rows.
"""
import os
from dataclasses import replace

import pytest
from psycopg import sql

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.role_contract import RLS_TABLES, ROLES, expected_privileges
from assurance_reference.retained_settlement import RetainedSettlements, SettledReleaseGate
import hashlib

from regulated_core import Ed25519Signer
from regulated_core.delegation import DelegationAuthority
from regulated_core.persistence_pg import PostgresClearanceStore, PostgresRevocationLedger
from regulated_core.tier4 import issue_clearance
from test_education_session_release import reviewed_context

TENANTS = ("school-a", "school-b")
SETTINGS = ("app.tenant", "app.alert_tenant", "app.release_tenant", "app.education_tenant", "app.pack_tenant")
TENANT_COLUMNS = ("tenant", "tenant_id", "workspace_id")
# Tables whose tenant lives inside a signed body; the expression is the one their row policy uses.
TENANT_EXPRESSIONS = {"reference_alerts_v1": "convert_from(envelope,'UTF8')::jsonb->'payload'->>'tenant_id'"}
# Tables the two lawful releases must populate for BOTH tenants (asserted, so the isolation is not vacuous).
BOTH_POPULATED = ("regulated_decision_evidence_v1", "regulated_permit_uses_v1", "regulated_reviews_v1",
                  "regulated_mission_budget_events_v1", "reference_alerts_v1", "reference_identities_v1",
                  "reference_sessions_v1", "reference_release_settlements_v1", "regulated_revocation_events_v1",
                  "regulated_monitor_clearances_v1", "regulated_delegation_grants_v1")


@pytest.fixture(scope="module")
def two_schools(tmp_path_factory):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    for tenant in TENANTS:
        app = build_education_fixture(roles, tmp_path_factory.mktemp(tenant), tenant=tenant,
                                      bootstrap_pack=tenant == TENANTS[0])
        # Settled release: the retained settlement row is written by the settlement writer login.
        gate = SettledReleaseGate(app.gates["requester"], RetainedSettlements(pool=roles.settlement_writer))
        context = replace(reviewed_context(app), now_us=app.clock.now_us())
        decision = gate.settle(spec=app.spec, contract=app.contract, artifact=app.body, out_path=str(app.path),
                               context=context)
        assert decision.allowed, (tenant, decision.reason)
        result = gate.commit_release(spec=app.spec, contract=app.contract, decision=decision, artifact=app.body,
                                     out_path=str(app.path), context=replace(context, now_us=app.clock.now_us()))
        assert result.state == "committed", (tenant, result)
        # A monitor clearance of this school's real decision, written by the restricted monitor_ingress login.
        monitor = Ed25519Signer("fixture:bf7b-clearance-monitor:" + tenant)
        app.stores.recorder._trust.register_signer(monitor)
        PostgresClearanceStore(pool=roles.monitor_ingress).put(
            issue_clearance(monitor, decision.permit.envelope, cleared_at_us=app.clock.now_us()))
        # A delegation root for this school, bound to its real decision, stored by the restricted delegation_issuer
        # login through the host's grant store. (The full root-admission journey fixture hard-codes one school; the
        # login, the store write path and the row policy exercised here are the real ones.)
        delegator = Ed25519Signer("fixture:bf7b-delegation:" + tenant)
        app.stores.recorder._trust.register_signer(delegator)
        permit = decision.permit.permit.permit
        DelegationAuthority(delegator, app.stores.recorder._trust, app.stores.grants).admit_root(
            tenant_id=tenant, approver="head", subject="requester", operations=(permit.operation,),
            targets=(permit.target_digest,), policy_refs=("fixture:bf7b@" + "0" * 64,), root_mission="bf7b",
            budget_limit=1, expires_at_us=app.clock.now_us() + 600_000_000,
            decision_record_id=permit.decision_record_id,
            approval_digest=hashlib.sha256(str(permit.approval_ref).encode()).hexdigest(), delegable=False,
            now_us=app.clock.now_us())
        # A tenant revocation by the governor login, after the release.
        PostgresRevocationLedger(pool=roles.governor).revoke(tenant, actor="admin", reason="b-f7b lawful",
                                                             now_us=app.clock.now_us())
        app.alerts.append_refusal(tenant_id=tenant, request_hash="0" * 64, decision_hash=None,
                                  code="ADMISSION_REFUSED")
    return roles


def _tenant_column(conn, table):
    columns = {row[0] for row in conn.execute(
        "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped",
        (table,)).fetchall()}
    found = [c for c in TENANT_COLUMNS if c in columns]
    if found:
        return sql.Identifier(found[0])
    return sql.SQL(TENANT_EXPRESSIONS[table]) if table in TENANT_EXPRESSIONS else None


def _rows(conn, table, column, tenant):
    with conn.transaction():
        for setting in SETTINGS:
            conn.execute("SELECT set_config(%s, %s, true)", (setting, tenant))
        return [row[0] for row in conn.execute(
            sql.SQL("SELECT {} FROM {}").format(column, sql.Identifier(table))).fetchall()]


def test_every_login_sees_only_its_tenants_rows_on_every_rls_table_with_both_tenants_lawfully_populated(two_schools):
    roles = two_schools
    populated = {tenant: set() for tenant in TENANTS}
    checked, untenanted = 0, set()
    for kind in ROLES:
        with getattr(roles, kind).connection() as conn:
            for table in sorted(RLS_TABLES):
                if "SELECT" not in expected_privileges(kind, table):
                    continue
                column = _tenant_column(conn, table)
                if column is None:
                    untenanted.add(table)  # isolated by its policy on another key; not counted as checked here
                    continue
                for tenant in TENANTS:
                    values = _rows(conn, table, column, tenant)
                    foreign = [v for v in values if v != tenant and not str(v).startswith(tenant + ":")]
                    assert not foreign, (kind, table, tenant, foreign[:3])
                    if values:
                        populated[tenant].add(table)
                checked += 1
    assert checked >= 20
    both = populated[TENANTS[0]] & populated[TENANTS[1]]
    missing = [table for table in BOTH_POPULATED if table not in both]
    assert not missing, missing
    print("\nB-F7b lawful two-tenant population:", sorted(both))
    print("B-F7b readable RLS tables without a tenant column (not counted):", sorted(untenanted))
