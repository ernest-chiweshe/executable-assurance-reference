"""Normal guarded lifecycle through tier-4 approvals, plus supervised withdrawal."""

import hashlib
import json
import os
import time
import uuid

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from assurance_reference.alerts import AlertJournal, provision_alerts
from assurance_reference.clock_floor import DurableClock, provision_floor
from assurance_reference.demo import SchemaConnections
from assurance_reference.engine import ReferenceEngine
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.durable_governance import DurableGovernedEducationPacks
from assurance_reference.packs import verify_bundles
from assurance_reference.recorder import ReferenceDecisionRecorder
from regulated_core import (
    Action, ActionEffect, Actor, ApprovalWorkflow, Assertion, Ed25519Signer, EmissionAuthority,
    IdentityVerifier, IntendedUse, IntendedUseRegistry, PolicyContext, PolicyRegistry,
    PreflightAuthority, TrustDirectory, VerificationTrustStore, canonical_bytes, issue_credential,
)
from regulated_core.clock_pg import DbClock
from regulated_core.persistence_pg import PostgresMissionBudget
from assurance_reference.governance_targets import (
    pack_activation_target, pack_pin_target, pack_revocation_target, pack_rollback_target,
)
from regulated_core.governance_guard import GovernanceRefused
from regulated_core.governance_targets import (
    GOVERNANCE_CONTENT_TYPE, WITHDRAWAL_CONTENT_TYPE, GovernancePolicy, GovernanceWithdrawalPolicy,
    change_bytes,
)
from regulated_core.persistence_pg import (
    PostgresClearanceStore, PostgresGovernanceLog, PostgresPermitUseStore, PostgresRevocationLedger, migrate,
)
from regulated_core.target import BoundEffect, Outcome, effect_destination
from regulated_core.tier4 import Tier4Controls, issue_clearance


class RetainedFixtureLines:
    def __init__(self, pool):
        self.pool = pool

    def reporting_line(self, tenant_id, subject_id):
        with self.pool.connection() as connection:
            row = connection.execute(
                "SELECT reporting_line FROM fixture_reporting_lines WHERE tenant=%s AND subject=%s",
                (tenant_id, subject_id),
            ).fetchone()
        return None if row is None else row[0]


def test_durable_signed_pack_lifecycle(tmp_path):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn and conninfo_to_dict(dsn).get("dbname") == "factory_test"
    schema = "test_reference_" + uuid.uuid4().hex
    (tmp_path / "retained-schema.json").write_text(json.dumps({"schema": schema}), encoding="utf-8")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        domain = connection.execute(
            "SELECT 'pg:' || system_identifier::text FROM pg_catalog.pg_control_system()"
        ).fetchone()[0]
    pool = SchemaConnections(dsn, schema)
    migrate(pool)
    # One isolated synthetic login owns this fixture schema, not production duties.
    with pool.connection() as connection:
        connection.execute("INSERT INTO regulated_budget_writer_roles_v1 "
                           "SELECT session_user::text,kind FROM "
                           "(VALUES ('reserve'),('consume'),('release')) AS kinds(kind)")
    provision_alerts(pool)
    primary = DbClock(pool, domain)
    provision_floor(pool, primary)
    clock = DurableClock(primary, floor_pool=pool)
    trust = TrustDirectory()
    signers = {role: Ed25519Signer("governance-fixture:" + role) for role in (
        "evidence", "approval", "identity", "emission", "preflight", "alert", "monitor",
    )}
    for signer in signers.values():
        trust.register_signer(signer)
    with pool.connection() as connection, connection.transaction():
        connection.execute("CREATE TABLE fixture_reporting_lines (tenant text, subject text, reporting_line text NOT NULL, PRIMARY KEY (tenant,subject))")
        for subject, line in (("reviewer-a", "line-a"), ("reviewer-b", "line-b"), ("reviewer-c", "line-a")):
            connection.execute("INSERT INTO fixture_reporting_lines VALUES (%s,%s,%s)",
                               ("synthetic-governance", subject, line))

    def assemble():
        pool = SchemaConnections(dsn, schema)
        clock = DurableClock(DbClock(pool, domain), floor_pool=pool)
        recorder = ReferenceDecisionRecorder(signers["evidence"], trust, pool=pool, clock=clock)
        uses = PostgresPermitUseStore(pool=pool)
        approvals = ApprovalWorkflow(trust, signers["approval"], IdentityVerifier(trust, signers["identity"].key_id))
        policies = PolicyRegistry()
        policies.register(GovernancePolicy())
        policies.register(GovernanceWithdrawalPolicy())
        intended = IntendedUseRegistry()
        for operation in ("activate", "pin", "rollback"):
            intended.declare(IntendedUse("governance", f"governance:{operation}-pack", 4))
        intended.declare(IntendedUse("governance", "governance:revoke-pack", 3))
        preflight = PreflightAuthority(signers["preflight"], intended, trust)
        clearances = PostgresClearanceStore(pool=pool)
        cooling = 1_000_000  # A real, positive one-second fixture interval, never a deployed policy claim.
        tier4 = Tier4Controls(
            directory=RetainedFixtureLines(pool), clearances=clearances, trust=trust,
            monitor_key_ids=frozenset({signers["monitor"].key_id}), cooling_off_us=cooling,
        )
        engine = ReferenceEngine(
            budget=PostgresMissionBudget(pool=pool), default_mission_budget={"limit": 32, "units": 1},
            retention=LocalRetentionStore(tmp_path / "retention"),
            alerts=AlertJournal(pool, signers["alert"], trust), registry=policies, recorder=recorder,
            verification_trust=VerificationTrustStore(trust), approvals=approvals,
            emission=EmissionAuthority(signers["emission"], trust, uses), preflight=preflight,
            clock=clock, tier4=tier4, revocation=PostgresRevocationLedger(pool=pool),
        )
        packs = DurableGovernedEducationPacks(
            pool=pool, clock=clock, alerts=AlertJournal(pool, signers["alert"], trust),
        )
        # Single-login durability fixture, not a qualified multi-tenant composition: since candidate 060 the
        # component itself refuses the shared pack_lifecycle store, so this test binds the recovered ledger directly.
        from factory.packs.lifecycle_pg import PostgresActivationLedger
        packs.ledger = PostgresActivationLedger("", pool=pool, guard=packs.governance_guard)
        log = PostgresGovernanceLog(pool=pool)
        return engine, preflight, clock, uses, recorder, approvals, clearances, packs, log

    engine, preflight, clock, uses, recorder, approvals, clearances, packs, log = assemble()
    packs.ledger.migrate()  # Explicit bootstrap only; subsequent receivers just read retained state.
    tenant = "synthetic-governance"
    cooling = 1_000_000
    bundles = verify_bundles()["bundles"]
    first, second = (item["reference"] for item in bundles)
    pack_id = first.partition("#")[0]
    with pytest.raises(GovernanceRefused):
        packs.activate(first, at="fixture-before-permit")
    assert packs.active(pack_id) is None
    steps = []

    rebuilds = []

    def rebuild():
        nonlocal engine, preflight, clock, uses, recorder, approvals, clearances, packs, log
        packs.ledger.close()
        engine, preflight, clock, uses, recorder, approvals, clearances, packs, log = assemble()
        rebuilds.append(clock.now_us())

    def target_for(change):
        common = dict(tenant_id=tenant, authority=engine.targets, uses=uses, log=log, budget=engine._budget)
        if "activate" in change:
            return pack_activation_target(packs, change["activate"], **common)
        if "pin" in change:
            return pack_pin_target(packs, change["pin"], change["tenant"], **common)
        if "rollback" in change:
            return pack_rollback_target(packs, pack_id, change["rollback_to"], **common)
        return pack_revocation_target(packs, change["revoke"], **common)

    def enact(change, *, withdrawal=False, check_extra_refusals=False):
        target = target_for(change)
        index = len(steps)
        output = change_bytes("pack-activation", pack_id, change)
        context = PolicyContext(tenant, Actor("requester", tenant, frozenset()), "governance:fixture", f"step-{index}", clock.now_us())
        assertion = Assertion(
            f"change-{index}", tenant,
            WITHDRAWAL_CONTENT_TYPE if withdrawal else GOVERNANCE_CONTENT_TYPE,
            hashlib.sha256(output).hexdigest(),
        )
        action = Action(target.operation, ActionEffect.EXTERNAL, destination=effect_destination(
            {}, BoundEffect(hashlib.sha256(output).hexdigest(), target.target, target.current_state(), mission="fixture:governance:" + pack_id),
        ))
        capability = preflight.authorize(
            tenant_id=tenant, vertical="governance", action_id=target.operation,
            risk_tier=3 if withdrawal else 4, correlation_id=context.correlation_id,
            now_us=clock.now_us(), ttl_us=120_000_000, nonce=f"capability-{index}",
        )
        parameters = dict(vertical="governance", capability=capability, assertion=assertion,
                          action=action, ctx=context, output=output, target=target,
                          permit_ttl_us=60_000_000, nonce=f"effect-{index}")
        prior = target.current_state()
        refused = packs.authorize(engine, **parameters)
        assert not refused.authorized and target.current_state() == prior
        assert not uses.used(tenant, f"effect-{index}")
        assert len(PostgresGovernanceLog(pool=pool).events(tenant)) == 2 * index
        decision = next(item for item in reversed(recorder.entries(tenant))
                        if item.record.decision.kind.value == "require-approval")
        request = approvals.open(
            request_id=f"request-{index}", requester_id=context.actor.actor_id, tenant_id=tenant,
            assertion_id=assertion.assertion_id, decision_record_id=decision.record.record_id,
            decision_record_hash=decision.record_hash, requirement=decision.record.decision.approval,
            now_us=clock.now_us(),
        )

        def certificate(names):
            grants = []
            for name in names:
                credential = issue_credential(
                    signers["identity"], actor_id=name, tenant_id=tenant,
                    kind="role:governance-supervisor" if withdrawal else "role:governance-approver",
                    expires_at_us=clock.now_us() + 120_000_000,
                )
                grants.append(approvals.grant(request, Actor(name, tenant, frozenset(), (credential,)), clock.now_us()))
            return approvals.finalize(request, grants, clock.now_us())

        cert = certificate(("supervisor",) if withdrawal else ("reviewer-a", "reviewer-b"))
        if check_extra_refusals:
            same_line = packs.authorize(engine,
                **parameters, approval_cert=certificate(("reviewer-a", "reviewer-c")), approval_evidence=decision,
            )
            assert not same_line.authorized and same_line.envelope.record.decision.reason_codes == ("TIER4_SAME_REPORTING_LINE",)
            assert target.current_state() == prior and not uses.used(tenant, f"effect-{index}")
        if not withdrawal:
            remaining = decision.record.decided_at_us + cooling - clock.now_us()
            if remaining > 0:
                time.sleep(remaining / 1_000_000)
            if check_extra_refusals:
                uncleared = packs.authorize(engine, **parameters, approval_cert=cert, approval_evidence=decision)
                assert not uncleared.authorized and uncleared.envelope.record.decision.reason_codes == ("TIER4_MONITOR_NOT_CLEARED",)
                assert target.current_state() == prior and not uses.used(tenant, f"effect-{index}")
            clearance = issue_clearance(signers["monitor"], decision, cleared_at_us=clock.now_us())
            clearances.put(clearance)
        else:
            clearance = None
        authorized = packs.authorize(engine, **parameters, approval_cert=cert, approval_evidence=decision)
        assert authorized.authorized, authorized.reason
        assert authorized.permit is not None
        if not withdrawal:
            assert authorized.permit.permit.issued_at_us >= decision.record.decided_at_us + cooling
        permit = authorized.permit
        Ed25519PublicKey.from_public_bytes(signers["emission"].public_key_bytes).verify(
            bytes.fromhex(permit.signature.value),
            json.dumps(permit.permit.signed_body(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
        )
        del parameters
        # Drop the issuing composition before delivery; retain only signed authorization.
        rebuild()
        target = target_for(change)
        assert target.current_state() == prior
        result = engine.commit(authorized, output, target)
        assert result.outcome is Outcome.COMMITTED, result.detail
        receipt = (tenant, target.operation, permit.permit.nonce, hashlib.sha256(output).hexdigest())
        assert packs.governance_receipt(*receipt) is Outcome.COMMITTED
        history_count = len(packs.ledger.history(pack_id))
        after = target.current_state()
        rebuild()
        target = target_for(change)
        assert target.current_state() == after
        assert packs.governance_receipt(*receipt) is Outcome.COMMITTED
        assert uses.used(tenant, f"effect-{index}")
        assert target.commit(permit, output).outcome is Outcome.COMMITTED
        assert len(packs.ledger.history(pack_id)) == history_count
        assert target.reconcile(permit).outcome is Outcome.COMMITTED
        steps.append(dict(change=change, approval=cert, approved_decision=decision,
                          clearance=clearance, permit=permit, result=result,
                          receipt=receipt, prior=prior, after=target.current_state()))

    enact({"activate": first, "at": "fixture-step-0"}, check_extra_refusals=True)
    enact({"activate": second, "at": "fixture-step-1"})
    assert packs.active(pack_id).reference == second
    enact({"pin": first, "tenant": "sample-school"})
    assert packs.activation_for("sample-school", pack_id).reference == first
    assert packs.activation_for("other-school", pack_id).reference == second
    assert packs.ledger.pinned("other-school", pack_id) is None
    enact({"rollback": pack_id, "rollback_to": first, "at": "fixture-step-3", "reason": "fixture rollback"})
    assert packs.active(pack_id).reference == first
    enact({"revoke": first, "at": "fixture-step-4", "reason": "fixture withdrawal"}, withdrawal=True)
    assert packs.active(pack_id).reference == second
    assert packs.activation_for("sample-school", pack_id) is None
    assert packs.activation_for("other-school", pack_id).reference == second
    assert packs.ledger.pinned("sample-school", pack_id) == first.partition("#")[2]
    assert packs.ledger.is_revoked(pack_id, first.partition("#")[2])
    assert recorder.verify_chain(tenant)
    events = PostgresGovernanceLog(pool=pool).events(tenant)
    assert len(events) == 10
    assert [event.phase for event in events] == ["prepared", "committed"] * 5
    assert all(uses.used(tenant, f"effect-{index}") for index in range(5))
    assert len(rebuilds) == 10 and rebuilds == sorted(rebuilds)
    history = packs.ledger.history(pack_id)
    assert all(int(record.activated_at) > 0 for record in history)
    assert [int(record.activated_at) for record in history] == sorted(int(record.activated_at) for record in history)
    with pool.connection() as connection:
        alert_ids = [row[0] for row in connection.execute("SELECT alert_id FROM reference_alerts_v1 ORDER BY alert_id").fetchall()]
        durable_state = connection.execute("SELECT revision, state_digest, payload FROM pack_lifecycle WHERE pack_id=%s", (pack_id,)).fetchone()
    assert len(alert_ids) == 7  # Five missing approvals, same-line pair, absent monitor clearance.
    alerts = [packs.alerts.read(ident, tenant_id=tenant) for ident in alert_ids]
    for alert in alerts:
        Ed25519PublicKey.from_public_bytes(signers["alert"].public_key_bytes).verify(
            bytes.fromhex(alert["signature"]["value"]),
            json.dumps(alert["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
        )
        assert alert["payload"]["code"] == "AUTHORIZATION_REFUSED"
    assert len(durable_state[2]["governance_receipts"]) == 5
    assert durable_state[0] == 5
    assert durable_state[1] == hashlib.sha256(json.dumps(
        [pack_id, durable_state[0], durable_state[2]], sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()
    previous = "0" * 64
    for seq, entry in enumerate(recorder.entries(tenant)):
        assert entry.seq == seq and entry.prev_hash == previous
        record = json.loads(canonical_bytes(entry.record))
        assert entry.record_hash == hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        body = {"schema": "regulated/evidence/v2", "seq": seq, "prev_hash": previous,
                "record_hash": entry.record_hash, "clock_domain": domain}
        Ed25519PublicKey.from_public_bytes(signers["evidence"].public_key_bytes).verify(
            bytes.fromhex(entry.signature.value), json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
        )
        body["schema"] = "regulated/evidence-chain/v2"
        previous = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    (tmp_path / "governance-evidence.json").write_bytes(canonical_bytes({
        "schema": schema, "bundles": bundles, "rebuilds": rebuilds, "alerts": alerts, "durable_state": durable_state, "steps": steps, "events": events,
        "entries": recorder.entries(tenant), "lifecycle": packs.ledger.history(pack_id),
        "public_keys": {key.key_id: key.public_key_bytes.hex() for key in signers.values()},
        "limits": ["Synthetic credentials and PostgreSQL reporting-line fixture; positive one-second cooling interval.",
                   "Lifecycle, pins, revocations and receipts persist through ten object/connection rebuilds with retained keys.",
                   "PostgreSQL evidence/log/nonce retention; no HSM/WORM or operator delivery claim.",
                   "No pack code installed or executed; no revoked-pack application release test.",
                   "Same-process reconstruction and retry; no killed-process, concurrency, deployed identity or RLS qualification."],
    }) + b"\n")
