"""Normal released-before-issuance history followed by exact bound settlement."""
import os

from assurance_reference import prepared_budget_demo
from regulated_core.budget import BudgetError, reservation_attempt_id
from regulated_core.persistence_pg import PostgresMissionBudget
from regulated_core.target import Outcome
from test_budget_retry_attempts import exercise_released_attempts
from test_delegated_draft import delegated_draft_fixture
from test_root_admission import TENANTS
import pytest


def test_postgres_released_attempts_keep_terminal_history(tmp_path):
    _, assemble, _ = delegated_draft_fixture(tmp_path)
    pool, *_, budget, _ = assemble(TENANTS[0])
    exercise_released_attempts(budget)
    first = budget.reserve("subject-tenant", "subject-mission",
                           reservation_id="subject-request", units=1, limit=10,
                           subject_digest="a" * 64)
    budget.release(first.tenant_id, first.mission, first.reservation_id)
    with pytest.raises(BudgetError, match="released attempt subject differs"):
        budget.reserve(first.tenant_id, first.mission,
                       reservation_id="subject-request", units=1, limit=10,
                       subject_digest="b" * 64)
    retry = budget.reserve(first.tenant_id, first.mission,
                           reservation_id="subject-request", units=1, limit=10,
                           subject_digest="a" * 64)
    assert retry.reservation_id == reservation_attempt_id("subject-request", 1)
    with pool.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant',%s,true)", (first.tenant_id,))
        with pytest.raises(BudgetError, match="reservation differs from request attempt lineage"):
            budget.require_request_attempt_on(
                conn, first.tenant_id, first.mission, retry.reservation_id,
                request_id="unrelated-request", subject_digest="a" * 64, units=1, limit=10,
            )
        checked = budget.require_request_attempt_on(
            conn, first.tenant_id, first.mission, retry.reservation_id,
            request_id="subject-request", subject_digest="a" * 64, units=1, limit=10,
        )
        assert checked == retry
        with pytest.raises(BudgetError):
            budget.require_request_attempt_on(
                conn, first.tenant_id, first.mission,
                reservation_attempt_id("subject-request", 2),
                request_id="subject-request", subject_digest="a" * 64, units=1, limit=10,
            )


def test_delegated_draft_binds_released_attempt_retry(tmp_path, monkeypatch):
    import test_delegated_draft as fixture
    original = fixture.PostgresMissionBudget
    allocated = []

    class ReleasedBeforeIssuance(original):
        def reserve(self, tenant, mission, **terms):
            # Normal cancellation of a synthetic allocation before any draft,
            # preparation, signature or receiver authority exists for it.
            first = super().reserve(tenant, mission, **terms)
            super().release(tenant, mission, first.reservation_id)
            second = super().reserve(tenant, mission, **terms)
            allocated.append((first, second, terms["subject_digest"]))
            return second

    monkeypatch.setattr(fixture, "PostgresMissionBudget", ReleasedBeforeIssuance)
    _, assemble, authorize = fixture.delegated_draft_fixture(tmp_path)
    result, _ = authorize(TENANTS[0], "alpha")
    assert result.status == "authorized", result.detail
    first, second, subject = allocated[0]
    assert first.reservation_id == result.permit.permit.nonce
    assert second.reservation_id == reservation_attempt_id(first.reservation_id, 1)
    assert result.permit.permit.budget_reservation == second.reservation_id
    pool, _, _, _, _, receiver, _, _ = assemble(TENANTS[0])
    delivered = receiver.commit(result.permit, fixture.BODY)
    assert delivered.outcome is Outcome.COMMITTED, delivered.detail
    ledger = PostgresMissionBudget(pool=pool)
    assert ledger.committed(second.tenant_id, second.mission) == 1
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT reservation_id,kind FROM regulated_mission_budget_events_v1 "
            "WHERE tenant=%s AND mission=%s", (second.tenant_id, second.mission)
        ).fetchall()
    assert set(rows) == {(first.reservation_id, "reserve"), (first.reservation_id, "release"),
                         (second.reservation_id, "reserve"), (second.reservation_id, "consume")}
    with pytest.raises(BudgetError, match="reservation id already used"):
        ledger.reserve(second.tenant_id, second.mission,
                       reservation_id=first.reservation_id, units=1, limit=10, subject_digest=subject)


def test_prepared_demo_binds_released_attempt_retry(tmp_path):
    result = prepared_budget_demo.run(tmp_path / "prepared-retry",
                                     os.environ["FACTORY_TEST_DB_URL"],
                                     released_attempt=True)
    permit = result["proof"]["permit"]
    assert permit["nonce"] == "draft-first"
    assert permit["budget_reservation"] == reservation_attempt_id("draft-first", 1)
    assert result["status"] == "PASS"
    assert sorted(row[0] for row in result["events"]) == ["consume", "release", "reserve", "reserve"]
    assert all(row[3] == (None if row[0] == "release" else
                          result["proof"]["preparation"]["subject_digest"]) for row in result["events"])
    assert result["counts"]["regulated_database_receipts_v1"] == 1
    assert result["counts"]["regulated_permit_uses_v1"] == 1
