"""Actual application permits and lawful withdrawal before a cold receiver.

Original keys, policy, session admission, qualification, recording and retention
services remain configured. New engine, target authority, epoch ledger, role
pools, budget/use stores and receiver are built; no guard method is replaced.
This is same-process reconstruction, not crash recovery or deployed IAM.
"""
from dataclasses import fields, replace
from hashlib import sha256
import os

import pytest

from a16_supervisor_fixture import SupervisorWithdrawalFixture
from assurance_reference.epoch_withdrawal_store import GuardedPostgresRevocationLedger
from assurance_reference.floor_bound_engine import FloorBoundReferenceEngine
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from factory.health_ui.documents import CLINICIAN, OBSERVATION, Paragraph, Session, build_document
from factory.health_ui.templates import CONSULTATION
from regulated_core.governance_guard import GovernanceGuard
from regulated_core.persistence_pg import PostgresMissionBudget, PostgresPermitUseStore
from regulated_core.target import TargetAuthority, Outcome
from test_education_session_release import approved_request
from three_application_fixture import prepare, ScriptedFactory


class ObservationComplete(Exception):
    """End the fixture after its actual reconstructed receiver outcome."""


def rebuild_engine(original, roles):
    assert type(original) is FloorBoundReferenceEngine
    pools = {kind: LocalPool(getattr(roles, kind)._dsn, roles.schema, getattr(roles, kind).role)
             for kind in ("governor", "receiver", "allocator")}
    clock = original.targets.clock
    ledger = GuardedPostgresRevocationLedger(pool=pools["governor"], clock=clock, guard=GovernanceGuard())
    prior = original.targets
    authority = TargetAuthority(prior._signer, prior._trust, revocation_epoch=ledger.epoch,
        clock=clock, chain_status=prior._chain_status, preparation_verifier=prior._preparation_verifier,
        require_preparation=prior._require_preparation, effect_margin_us=prior.effect_margin_us)
    # Match the existing host contract: receiver consumes; allocator reserves/releases.
    budget = PostgresMissionBudget(pool=pools["receiver"], allocator_pool=pools["allocator"])
    engine = type(original)(
        generation_floor=original._generation_floor, qualifications=original._qualifications,
        alerts=original._alerts, retention=original._retention, retention_us=original._retention_us,
        registry=original._registry, recorder=original._recorder, verification_trust=original._vtrust,
        approvals=original._approvals, emission=original._emission, preflight=original._preflight,
        targets=authority, budget=budget, default_mission_budget=original._default_mission_budget,
        revocation=ledger, delegation=original._delegation, tier4=original._tier4,
        restrictions=original._restrictions, delegation_source_status=original._source_status,
        heartbeat=original._heartbeat, clock=clock)
    return engine, ledger, budget, PostgresPermitUseStore(pool=pools["receiver"]), pools


def observe_receiving(app, gate, roles, withdrawn, monkeypatch):
    original = gate._engine
    observed = {}

    def receive(authorization, body, target):
        assert not observed and authorization.authorized and authorization.permit
        signed = authorization.permit
        tenant, nonce = signed.permit.tenant_id, signed.permit.nonce
        original.targets.verify(signed, body, tenant_id=tenant, target=target.target,
            operation=target.operation, current_target_state=target.current_state())
        assert not target.path.exists()
        if withdrawn:
            governance = SupervisorWithdrawalFixture(roles, tenant,
                shared_ledger=app.stores.revocation, shared_recorder=app.stores.recorder,
                principal_prefix="epoch-")
            pending = governance.begin()
            approved = governance.approve(pending)
            issued = governance.authorize(pending, approved)
            result = governance.engine.commit(issued, pending.output, governance.target)
            assert result.outcome is Outcome.COMMITTED, result.detail
        rebuilt, ledger, budget, uses, pools = rebuild_engine(original, roles)
        try:
            receiver = replace(target, authority=rebuilt.targets, uses=uses, budget=budget)
            assert rebuilt is not original and receiver is not target
            assert rebuilt.targets is not original.targets
            assert ledger is not app.stores.revocation
            assert rebuilt.targets._epoch == ledger.epoch
            # The target's existing session/domain effect_check is retained.
            assert receiver.effect_check is target.effect_check
            result = rebuilt.commit(authorization, body, receiver)
            assert result.outcome is (Outcome.FAILED if withdrawn else Outcome.COMMITTED), result.detail
            if withdrawn:
                assert "permit revoked" in result.detail
                assert not receiver.path.exists() and not uses.used(tenant, nonce)
            else:
                assert receiver.path.read_bytes() == body and uses.used(tenant, nonce)
            observed.update(tenant=tenant, nonce=nonce, outcome=result.outcome.value,
                            detail=result.detail, body_sha256=sha256(body).hexdigest())
        finally:
            for pool in pools.values():
                pool.close()
        raise ObservationComplete()

    monkeypatch.setattr(original, "commit", receive)
    return observed


@pytest.mark.parametrize("application", ["education", "health", "product_spec"])
@pytest.mark.parametrize("withdrawn", [False, True], ids=["current", "withdrawn"])
def test_integrated_application_cold_receiver_reads_supervised_epoch(application, withdrawn, tmp_path, monkeypatch):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        if application == "education":
            app = build_education_fixture(roles, tmp_path)
            context, decision = approved_request(app)
            gate = app.gates["requester"]
            observed = observe_receiving(app, gate, roles, withdrawn, monkeypatch)
            with pytest.raises(ObservationComplete):
                gate.commit_release(spec=app.spec, contract=app.contract, decision=decision,
                                    artifact=app.body, out_path=str(app.path), context=context)
        elif application == "health":
            app = build_clinical_fixture(roles, tmp_path)
            document = build_document(CONSULTATION, "Fictional epoch record", "case-fixture", "Invented subject", [])
            for section in document.sections:
                section.paragraphs.append(Paragraph("Invented local text; no patient or clinical advice.",
                                                    OBSERVATION, origin=CLINICIAN))
            session = Session("case-fixture", "Fictional clinician", "Fixture", "Invented subject",
                "2026-10-14T00:00:00+00:00", owner_id=app.clinician.owner_id,
                workspace_id=app.clinician.workspace_id, documents=[document])
            app.store.save(session)
            observed = observe_receiving(app, app.gate, roles, withdrawn, monkeypatch)
            with pytest.raises(ObservationComplete):
                app.finaliser.finalise(session, document, app.clinician)
        else:
            app = build_product_spec_fixture(roles, tmp_path, factory=ScriptedFactory())
            context, _, _ = prepare(app, "epoch-project", app.path)
            observed = observe_receiving(app, app.gates["requester"], roles, withdrawn, monkeypatch)
            with pytest.raises(ObservationComplete):
                app.engine.release("epoch-project", str(app.path), context=context)
        assert observed
        assert app.stores.recorder.verify_chain(observed["tenant"])
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
