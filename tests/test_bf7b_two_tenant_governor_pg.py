"""B-F7b on lawful two-tenant population: epoch-withdrawal receipts written by the restricted governor login.

Two fictional offices on one schema each complete an authenticated supervisor epoch withdrawal through the real
governance path (approval, permit, engine commit), which writes their own receipt row. No administrator seeding.
As each office (app.tenant), the governor login sees only that office's receipt and fence rows, and an insert that
names the other office is refused by the row policy.
"""
import os

import psycopg
import psycopg.sql
import pytest

from a16_supervisor_fixture import SupervisorWithdrawalFixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.persistence_pg import PostgresRevocationLedger
from regulated_core.target import Outcome

OFFICES = ("synthetic-office-a", "synthetic-office-b")
TABLES = ("reference_epoch_withdrawal_receipts_v1", "reference_tenant_fences_v1")
FREE_EPOCH = {}


@pytest.fixture(scope="module")
def two_offices():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    for office in OFFICES:
        app = SupervisorWithdrawalFixture(roles, tenant=office)
        pending = app.begin()
        authorized = app.authorize(pending, app.approve(pending))
        assert app.engine.commit(authorized, pending.output, app.target).outcome is Outcome.COMMITTED
    # One more ordinary revocation epoch for the second office, with no receipt: the target of the refused
    # cross-office insert below, so that only the row policy (not a key) can refuse it.
    free = PostgresRevocationLedger(pool=roles.governor).revoke(OFFICES[1], actor="admin", reason="bf7b",
                                                                now_us=app.clock.now_us())
    FREE_EPOCH[OFFICES[1]] = free.epoch
    return roles


def _visible(roles, table, office):
    with roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", (office,))
        return [row[0] for row in conn.execute(f"SELECT tenant FROM {table}").fetchall()]


@pytest.mark.parametrize("table", TABLES)
def test_each_office_sees_only_its_own_rows(two_offices, table):
    for office in OFFICES:
        rows = _visible(two_offices, table, office)
        assert rows, (table, office)  # populated for this office by its own lawful withdrawal
        assert set(rows) == {office}, (table, office, rows)


def test_a_receipt_naming_the_other_office_is_refused(two_offices):
    with two_offices.governor.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SELECT set_config('app.tenant', %s, true)", (OFFICES[0],))
                columns = [r[0] for r in conn.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_name ="
                    " 'reference_epoch_withdrawal_receipts_v1' ORDER BY ordinal_position").fetchall()]
                row = conn.execute("SELECT * FROM reference_epoch_withdrawal_receipts_v1 LIMIT 1").fetchone()
                values = dict(zip(columns, row))
                values["tenant"] = OFFICES[1]
                values["epoch"] = FREE_EPOCH[OFFICES[1]]  # exists for that office and has no receipt yet
                values["nonce"] = "foreign-" + str(values.get("nonce", ""))
                conn.execute(psycopg.sql.SQL("INSERT INTO reference_epoch_withdrawal_receipts_v1 ({}) VALUES ({})").format(
                    psycopg.sql.SQL(", ").join(map(psycopg.sql.Identifier, values)),
                    psycopg.sql.SQL(", ").join(psycopg.sql.Placeholder() * len(values))), list(values.values()))


# Governed receipts: two governing offices each enact a real two-reviewer checker qualification (A15 path).
def _governed_two_offices():
    from assurance_reference.durable_registries import PostgresQualificationRegistry
    from assurance_reference.governance_targets import qualification_target
    from factory.pg_session import SessionBoundPool
    from partitioned_governance_fixture import GovernedFixture
    from regulated_core.governance_targets import change_bytes
    from regulated_core.qualification import LabeledCase, QualificationDataset, qualify
    from regulated_core.signing import Ed25519Signer
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = GovernedFixture(roles)
    authority = Ed25519Signer("fixture:bf7b-qualification-authority")
    app.trust.register_signer(authority)
    reports = PostgresQualificationRegistry(pool=SessionBoundPool(roles.governor), trust=app.trust,
                                            authority=authority.key_id)
    for office in OFFICES:
        klass = "fixture:bf7b-checker:" + office
        report = qualify(authority, verification_class=klass, verifier_version="fixture:1",
                         dataset=QualificationDataset("fixture:bf7b", "1", "Synthetic dataset",
                                                      (LabeledCase("yes", True), LabeledCase("no", False))),
                         predicate=lambda text: text == "yes", qualified_at_us=app.clock.now_us(),
                         valid_for_us=600_000_000, jurisdictions=("fixture",), languages=("en",),
                         document_types=("fixture",), limitations=("Synthetic fixture; no qualification claim",))
        target = qualification_target(reports, report, tenant_id=office, authority=app.engine.targets,
                                      uses=app.uses, log=app.log, budget=app.budget)
        output = change_bytes("checker-qualification", klass, {"add_report": report.digest()})
        result = app.enact_target(office, target, output, mission="fixture:bf7b:qualification")[0]
        assert result.outcome is Outcome.COMMITTED, (office, result.detail)
    return roles


def test_each_governing_office_sees_only_its_own_governed_receipts():
    roles = _governed_two_offices()
    for office in OFFICES:
        rows = _visible(roles, "reference_governed_receipts_v1", office)
        assert rows, office
        assert set(rows) == {office}, (office, rows)
