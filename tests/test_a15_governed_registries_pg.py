"""A15: checker qualification and approver-issuer recognition commit through a supported durable path (candidate 062).

Each governed change runs the real two-reviewer tier-4 path (tests/partitioned_governance_fixture.py) into a PostgreSQL
registry whose transaction compares the approved prior state, consumes the mission budget, and appends the change and
its exact receipt together. The change commits exactly once; replaying the permit applies nothing again; a failure
after the final check rolls back the effect, the receipt and the consumption together and stays UNKNOWN; a lost
acknowledgement after a durable commit is UNKNOWN and is resolved by the receipt, never by applying again. The receipt
row is the governing tenant's alone. The in-memory registries remain refused by reference composition.
"""
import hashlib
import os

import pytest

from assurance_reference.durable_registries import PostgresIssuerRegistry, PostgresQualificationRegistry
from assurance_reference.governance_targets import issuer_target, qualification_target
from assurance_reference.local_roles import provision_local_roles
from factory.pg_session import SessionBoundPool
from partitioned_governance_fixture import GovernedFixture
from regulated_core.governance_targets import change_bytes
from regulated_core.qualification import LabeledCase, QualificationDataset, QualificationRegistry, qualify
from regulated_core.signing import Ed25519Signer
from regulated_core.target import Outcome

TENANT = "governance-office"
CLASS = "fixture:a15-checker"


@pytest.fixture
def app():
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    fixture = GovernedFixture(roles)
    fixture.authority = Ed25519Signer("fixture:a15-qualification-authority")
    fixture.issuer = Ed25519Signer("fixture:a15-credential-issuer")
    for signer in (fixture.authority, fixture.issuer):
        fixture.trust.register_signer(signer)
    fixture.reports = PostgresQualificationRegistry(pool=SessionBoundPool(roles.governor), trust=fixture.trust,
                                                    authority=fixture.authority.key_id)
    fixture.issuers = PostgresIssuerRegistry(pool=SessionBoundPool(roles.governor), trust=fixture.trust)
    return fixture


def _report(app):
    dataset = QualificationDataset("fixture:a15", "1", "Synthetic protocol dataset",
                                   (LabeledCase("yes", True), LabeledCase("no", False)))
    return qualify(app.authority, verification_class=CLASS, verifier_version="fixture:1", dataset=dataset,
                   predicate=lambda text: text == "yes", qualified_at_us=app.clock.now_us(), valid_for_us=600_000_000,
                   jurisdictions=("fixture",), languages=("en",), document_types=("fixture",),
                   limitations=("Synthetic protocol fixture; no scientific qualification",))


def _common(app):
    return dict(tenant_id=TENANT, authority=app.engine.targets, uses=app.uses, log=app.log, budget=app.budget)


def _qualify(app, report):
    target = qualification_target(app.reports, report, **_common(app))
    output = change_bytes("checker-qualification", CLASS, {"add_report": report.digest()})
    return app.enact_target(TENANT, target, output, mission="fixture:a15:qualification")


def _recognise(app):
    target = issuer_target(app.issuers, app.issuer.key_id, **_common(app))
    output = change_bytes("approver-issuer", app.issuer.key_id, {"kind": "role:governance-approver"})
    return app.enact_target(TENANT, target, output, mission="fixture:a15:issuer")


def _receipt_rows(app):
    with app.roles.governor.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", ("another-tenant",))
        foreign = conn.execute("SELECT count(*) FROM reference_governed_receipts_v1").fetchone()[0]
        conn.execute("SELECT set_config('app.tenant', %s, true)", (TENANT,))
        own = conn.execute("SELECT count(*) FROM reference_governed_receipts_v1").fetchone()[0]
    return own, foreign


def test_qualification_commits_once_with_budget_and_receipt_and_replay_applies_nothing(app):
    report = _report(app)
    result, target, authorized, output = _qualify(app, report)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert [r.digest() for r in app.reports.history(CLASS)] == [report.digest()]
    assert app.reports.current(CLASS, app.clock.now_us()) == report
    permit = authorized.permit.permit
    assert app.budget.committed(TENANT, permit.mission) == 1
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED  # Replay: stored outcome only.
    assert len(app.reports.history(CLASS)) == 1 and app.budget.committed(TENANT, permit.mission) == 1
    assert app.reports.governance_receipt(TENANT, target.operation, permit.nonce,
                                          hashlib.sha256(output).hexdigest()) is Outcome.COMMITTED
    assert _receipt_rows(app) == (1, 0)


def test_issuer_recognition_commits_once_and_the_receipt_is_the_governing_tenants(app):
    result, target, authorized, output = _recognise(app)
    assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.issuers.issuer_kind(app.issuer.key_id) == "role:governance-approver"
    mission = authorized.permit.permit.mission
    assert app.budget.committed(TENANT, mission) == 1  # Consumed in the recognition's own transaction (Q3).
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
    assert app.budget.committed(TENANT, mission) == 1  # Replay consumes nothing again.
    with app.roles.governor.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_issuer_recognitions_v1").fetchone() == (1,)
    assert _receipt_rows(app) == (1, 0)


@pytest.mark.parametrize("registry", ["qualification", "issuer"])
def test_failure_after_the_final_check_rolls_back_effect_receipt_and_consumption(app, monkeypatch, registry):
    import assurance_reference.durable_registries as durable
    real = durable._receipt_on

    def failing(conn, governed):
        real(conn, governed)
        raise RuntimeError("synthetic storage failure after the effect and receipt rows, before COMMIT")
    monkeypatch.setattr(durable, "_receipt_on", failing)
    if registry == "qualification":
        result, target, authorized, output = _qualify(app, _report(app))
        assert app.reports.history(CLASS) == ()
    else:
        result, target, authorized, output = _recognise(app)
        assert app.issuers.issuer_kind(app.issuer.key_id) is None
    assert result.outcome is Outcome.UNKNOWN, result.detail
    assert app.budget.committed(TENANT, authorized.permit.permit.mission) == 0
    assert target.reconcile(authorized.permit).outcome is Outcome.UNKNOWN  # No receipt: never treated as failed.
    assert _receipt_rows(app) == (0, 0)


def test_lost_acknowledgement_after_commit_is_resolved_by_the_receipt_without_applying_again(app, monkeypatch):
    real = PostgresIssuerRegistry.recognise_governed

    def lost(self, issuer_key_id, kind, governed):
        real(self, issuer_key_id, kind, governed)
        raise ConnectionError("synthetic lost acknowledgement after a durable commit")
    monkeypatch.setattr(PostgresIssuerRegistry, "recognise_governed", lost)
    result, target, authorized, output = _recognise(app)
    assert result.outcome is Outcome.UNKNOWN, result.detail
    monkeypatch.setattr(PostgresIssuerRegistry, "recognise_governed", real)
    assert target.reconcile(authorized.permit).outcome is Outcome.COMMITTED
    assert app.engine.reconcile(authorized, target).outcome is Outcome.COMMITTED
    assert target.commit(authorized.permit, output).outcome is Outcome.COMMITTED
    with app.roles.governor.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_issuer_recognitions_v1").fetchone() == (1,)


def test_in_memory_registries_stay_refused_by_reference_composition(app):
    with pytest.raises(TypeError, match="PostgreSQL qualification transaction"):
        qualification_target(QualificationRegistry(app.trust, authority=app.authority.key_id), _report(app),
                             **_common(app))
