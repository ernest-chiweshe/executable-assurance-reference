"""Host-condition routing through the restricted synthetic Education release.

Readiness is a synthetic host port here; signed proof semantics are separately
checked in test_host_conditions.py. No production custody or provider is used.
"""

import os
from dataclasses import replace

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import provision_local_roles
from regulated_core.production_gate import ProductionReadinessError, ReadinessWindow
from regulated_core.signing import Signature
from regulated_core.target import Outcome
from test_education_session_release import reviewed_context


def request(app, context):
    return dict(spec=app.spec, contract=app.contract, out_path=str(app.path),
                context=context, artifact=app.body)


def test_configured_monitor_blocks_release_until_verified_observation(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    app = build_education_fixture(roles, tmp_path, monitor_heartbeat=True)
    context = reviewed_context(app)
    gate = app.gates["requester"]
    refused = gate.authorize_release(**request(app, context))
    assert not refused.allowed and "heartbeat" in refused.reason
    assert not app.path.exists()
    app.publish_monitor_heartbeat()
    decision = gate.authorize_release(**request(app, context))
    assert decision.allowed, decision.reason
    result = gate.commit_release(decision=decision, **request(app, context))
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")


class SyntheticReadinessPort:
    """An explicit fixture observation port, not deployed assurance evidence."""

    def __init__(self):
        self.clock = None
        self.refuse = False
        self.bindings = []
        self.calls = 0

    def bind(self, pack_id, verification_classes, credential_verifier):
        assert pack_id and verification_classes
        assert callable(credential_verifier.verify)
        self.bindings.append((pack_id, verification_classes))
        return self.check

    def check(self):
        self.calls += 1
        if self.refuse:
            raise ProductionReadinessError("synthetic readiness unavailable")
        now = self.clock.now_us()
        return ReadinessWindow(self.clock, now, now + 60_000_000)


@pytest.mark.parametrize("refusal_phase", [None, "authorization", "commit"])
def test_readiness_hook_controls_authorization_and_commit(tmp_path, refusal_phase):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    readiness = SyntheticReadinessPort()
    app = build_education_fixture(roles, tmp_path, production_assurance=readiness)
    readiness.clock = app.clock
    assert len(readiness.bindings) == 3
    assert readiness.calls == 0  # construction binds the port without evaluating it
    context = reviewed_context(app)
    gate = app.gates["requester"]
    readiness.refuse = refusal_phase == "authorization"
    decision = gate.authorize_release(**request(app, context))
    if refusal_phase == "authorization":
        assert not decision.allowed and "readiness unavailable" in decision.reason
        assert not app.path.exists()
    else:
        assert decision.allowed, decision.reason
        before = readiness.calls
        readiness.refuse = refusal_phase == "commit"
        result = gate.commit_release(decision=decision, **request(app, context))
        assert readiness.calls > before
        if refusal_phase == "commit":
            assert result.state == "failed" and "readiness unavailable" in result.detail
            assert not app.path.exists()
        else:
            assert result.state == "committed", result
            assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")


@pytest.mark.parametrize("condition", ["other-tenant", "other-correlation", "invalid-signature", "expired"])
def test_signed_preflight_refuses_at_engine_before_permit_or_effect(tmp_path, condition):
    from assurance_reference.host_runtime import compose_reference_host
    from assurance_reference.local_fixture_host import configuration
    from test_reference_host import render_request

    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, keys = configuration(roles, tmp_path)
    host = compose_reference_host(
        stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified",
    )
    engine, lawful, target, body = render_request(host, tmp_path)
    assert lawful.authorized, lawful.reason
    ctx = lawful.ctx
    capability = engine._preflight.authorize(
        tenant_id="other-synthetic-tenant" if condition == "other-tenant" else ctx.tenant_id,
        vertical="course", action_id=target.operation, risk_tier=1,
        correlation_id="other-request" if condition == "other-correlation" else ctx.correlation_id,
        now_us=engine.targets.now_us(), ttl_us=60_000_000, nonce="preflight-contract",
    )
    if condition == "invalid-signature":
        capability = replace(capability, signature=Signature(keys["preflight"].key_id, "00" * 64))
    elif condition == "expired":
        now = engine.targets.now_us()
        capability = replace(capability, issued_at_us=now - 2, expires_at_us=now - 1)
        # Signed historical fixture data; the live clock and verifier stay intact.
        capability = replace(capability, signature=keys["preflight"].sign(capability.signed_body()))
    refused = engine.authorize_for_target(
        vertical="course", capability=capability, assertion=lawful.assertion,
        action=lawful.action, ctx=ctx, output=body, target=target,
        nonce="refused-preflight", permit_ttl_us=60_000_000,
    )
    assert not refused.authorized and refused.permit is None
    assert refused.envelope.record.decision.reason_codes == ("PREFLIGHT_INVALID",)
    assert not target.path.exists()
    assert not (target.path.parent / ".commit-receipts").exists()
    assert not stores.permits.used(ctx.tenant_id, "refused-preflight")
    assert not stores.permits.used(ctx.tenant_id, lawful.permit.permit.nonce)
    assert engine.commit(lawful, body, target).outcome is Outcome.COMMITTED
    assert target.path.read_bytes() == body
    assert stores.recorder.verify_chain(ctx.tenant_id)
