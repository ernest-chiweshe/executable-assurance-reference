"""Clearance writer composition contracts; not an application tier-four qualification."""
from dataclasses import fields
import os

import psycopg
import pytest
from psycopg import sql

from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.role_contract import ROLES, collect_access_matrix, expected_privileges
from regulated_core import Ed25519Signer
from regulated_core.persistence_pg import PostgresClearanceStore
from regulated_core.tier4 import Tier4Controls, issue_clearance
from test_education_session_release import approved_request

TABLE = "regulated_monitor_clearances_v1"


class SyntheticReportingLines:
    def reporting_line(self, tenant_id, subject_id):
        if tenant_id != "school-a":
            return None
        return {"teacher": "fixture-classroom", "head": "fixture-department"}.get(subject_id)


@pytest.mark.parametrize("partitioned", [False, True])
def test_exact_clearance_duties_in_each_profile(partitioned):
    for role in ROLES:
        duties = {"INSERT"} if role == "monitor_ingress" else {"SELECT"} if role == "receiver" else set()
        assert expected_privileges(role, TABLE, partitioned_lifecycle=partitioned) == duties
    for column in ("tenant", "decision_record_id"):
        assert expected_privileges("monitor_ingress", TABLE, column, partitioned_lifecycle=partitioned) == {"SELECT", "INSERT"}
    for column in ("body", "signature"):
        assert expected_privileges("monitor_ingress", TABLE, column, partitioned_lifecycle=partitioned) == {"INSERT"}


@pytest.mark.parametrize("partitioned", [False, True])
def test_clearance_duty_preserves_governor_only_roster_reads(partitioned):
    for role in ROLES:
        assert ("SELECT" in expected_privileges(role, "regulated_governance_rosters_v1",
                                                partitioned_lifecycle=partitioned)) == (role == "governor")


@pytest.mark.parametrize("partitioned", [True])  # legacy profile refused since candidate 060
def test_signed_clearance_round_trip_uses_separate_restricted_roles(partitioned, tmp_path):
    provision = provision_partitioned_local_roles if partitioned else provision_local_roles
    roles = provision(os.environ["FACTORY_TEST_DB_URL"])
    try:
        app = build_education_fixture(roles, tmp_path, partitioned_lifecycle=partitioned)
        _, decision = approved_request(app)
        envelope = decision.permit.envelope
        trust = app.stores.recorder._trust
        monitor = Ed25519Signer("fixture:a03:clearance-monitor")
        trust.register_signer(monitor)
        clearance = issue_clearance(monitor, envelope, cleared_at_us=app.clock.now_us())
        writer = PostgresClearanceStore(pool=roles.monitor_ingress)
        reader = PostgresClearanceStore(pool=roles.receiver)
        assert reader.get(clearance.tenant_id, clearance.decision_record_id) is None
        writer.put(clearance)
        writer.put(clearance)  # Original signed evidence remains first-write idempotent.
        assert reader.get(clearance.tenant_id, clearance.decision_record_id) == clearance
        # A second genuine observation of the same decision must not replace
        # the first signed record. Repeating identical bytes alone cannot show this.
        later_clearance = issue_clearance(monitor, envelope,
            cleared_at_us=clearance.cleared_at_us + 1)
        assert later_clearance != clearance
        assert trust.verify(later_clearance.signed_body(), later_clearance.signature)
        writer.put(later_clearance)
        assert reader.get(clearance.tenant_id, clearance.decision_record_id) == clearance
        assert reader.get("other-fictional-school", clearance.decision_record_id) is None
        assert trust.verify(clearance.signed_body(), clearance.signature)
        controls = Tier4Controls(directory=SyntheticReportingLines(), clearances=reader, trust=trust,
            monitor_key_ids=frozenset({monitor.key_id}), cooling_off_us=1)
        # Verify only this control's original exact-decision/signature checks.
        # No claim that the tier-three application was qualified as tier four.
        assert controls.clearance_problem(envelope, now_us=app.clock.now_us()) is None
        report = collect_access_matrix(roles, partitioned_lifecycle=partitioned)
        assert report["privilege_contract_matches"], report["errors"]
        entry = report["roles"]["monitor_ingress"]["tables"][TABLE]
        assert set(entry["table_privileges"]) == {"INSERT"}
        assert entry["rls_enabled"] and entry["rls_forced"]
        with roles.monitor_ingress.connection() as connection:
            for column in ("body", "signature"):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SELECT {} FROM {} LIMIT 0").format(
                        sql.Identifier(column), sql.Identifier(TABLE)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.put(clearance)
        assert reader.get(clearance.tenant_id, clearance.decision_record_id) == clearance
        assert app.stores.recorder.verify_chain(clearance.tenant_id)
        assert not app.path.exists()
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
