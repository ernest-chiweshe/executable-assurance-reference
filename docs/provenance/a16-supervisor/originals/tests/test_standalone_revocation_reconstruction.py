"""Normal application authorization, withdrawal, and receiver reconstruction.

This observes intact constructors and commit methods. Keys, policies, approval
services and recorder remain in process: this is not crash recovery or supervisor
identity qualification.
"""
import json
import os
from dataclasses import asdict, replace

import pytest

from assurance_reference import demo, health
from assurance_reference.demo import SchemaConnections
from regulated_core.persistence_pg import PostgresMissionBudget, PostgresPermitUseStore
from regulated_core.target import Outcome


class ObservationComplete(Exception):
    """Stop the sample app after its first real target outcome was observed."""


@pytest.mark.parametrize("application", [demo, health], ids=["demo", "health"])
@pytest.mark.parametrize("withdraw", [False, True], ids=["current", "withdrawn"])
def test_standalone_receiver_reconstruction(application, withdraw, tmp_path, monkeypatch):
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "").strip()
    assert dsn, "FACTORY_TEST_DB_URL is required; no skipped qualification"
    real_engine = application.ReferenceEngine
    observed = {}

    def observe_constructor(**parameters):
        first = real_engine(**parameters)

        def observe_commit(authorization, body, target):
            assert not observed, "only the first authorized application effect is observed"
            assert authorization.authorized and authorization.permit is not None
            signed = authorization.permit
            permit = signed.permit
            assert not target.path.exists()
            # The actual application signed this permit through its ordinary
            # policy/approval path; authenticate all current target conditions.
            first.targets.verify(
                signed, body, tenant_id=target.tenant_id, target=target.target,
                operation=target.operation, current_target_state=target.current_state(),
            )
            ledger = parameters.get("revocation")
            assert ledger is not None, "standalone app must supply its durable ledger"
            original_pool = ledger._pool
            pool = SchemaConnections(original_pool.dsn, original_pool.schema)
            assert pool is not original_pool
            event = None
            if withdraw:
                event = first.revoke(
                    target.tenant_id, actor="synthetic-fixture-host",
                    reason="Withdraw pending synthetic application delivery",
                    now_us=first.targets.now_us(),
                )
            rebuilt_parameters = dict(parameters)
            rebuilt_parameters["revocation"] = type(ledger)(pool=pool)
            rebuilt_parameters["budget"] = PostgresMissionBudget(pool=pool)
            rebuilt = real_engine(**rebuilt_parameters)
            uses = PostgresPermitUseStore(pool=pool)
            receiver = replace(
                target, authority=rebuilt.targets, uses=uses,
                budget=rebuilt_parameters["budget"],
            )
            # Full, unmodified engine/adapter commit path; no verification,
            # policy, signature, nonce or effect guard is replaced.
            result = rebuilt.commit(authorization, body, receiver)
            expected = Outcome.FAILED if withdraw else Outcome.COMMITTED
            assert result.outcome is expected, result.detail
            if withdraw:
                assert "permit revoked" in result.detail
                assert not receiver.path.exists()
                assert not uses.used(permit.tenant_id, permit.nonce)
            else:
                assert receiver.path.read_bytes() == body
                assert uses.used(permit.tenant_id, permit.nonce)
            with pool.connection() as connection:
                events = connection.execute(
                    "SELECT tenant,epoch,actor,reason,revoked_at_us "
                    "FROM regulated_revocation_events_v1 ORDER BY tenant,epoch"
                ).fetchall()
            if withdraw:
                assert events == [(target.tenant_id, event.epoch, event.actor,
                                   event.reason, event.at_us)]
                assert rebuilt_parameters["revocation"].epoch(target.tenant_id) == event.epoch
            else:
                assert events == []
            observed.update({
                "application": application.__name__, "withdrawn": withdraw,
                "outcome": result.outcome.value, "detail": result.detail,
                "event": asdict(event) if event else None,
                "schema": pool.schema, "nonce_spent": uses.used(permit.tenant_id, permit.nonce),
                "target_exists": receiver.path.exists(),
                "limits": [
                    "Synthetic host withdrawal; supervisor identity/authorization not qualified.",
                    "New engine, revocation ledger, connection factory, use store and target.",
                    "Keys, policy/approval services, clock and recorder remain in process.",
                    "No process crash, concurrent withdrawal/effect ordering or deployment claim.",
                ],
            })
            raise ObservationComplete()

        first.commit = observe_commit
        return first

    monkeypatch.setattr(application, "ReferenceEngine", observe_constructor)
    with pytest.raises(ObservationComplete):
        application.run(tmp_path / "application", dsn)
    assert observed
    (tmp_path / "receiver-reconstruction.json").write_text(
        json.dumps(observed, indent=2) + "\n", encoding="utf-8",
    )
