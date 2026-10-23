"""Guarded host composition under restricted PostgreSQL runtime logins."""

from dataclasses import replace
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from assurance_reference.local_fixture_host import configuration

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_roles import provision_local_roles
from assurance_reference.packs import FIXTURES, PUBLISHER
from regulated_core import (
    Action, ActionEffect, Actor, Assertion, CoursePolicy, IntendedUse,
    IntendedUseRegistry, PolicyContext, PolicyRegistry,
)
from regulated_core.models import PolicyRef
from regulated_core.certificates import CertificateRegistry, DEMONSTRATION_CERTIFICATE
from regulated_core.document_gate import VerifierRegistry
from regulated_core.governance_guard import GovernanceRefused
from regulated_core.identity_provider import CredentialVerifier, LocalIdentityProvider
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination
from factory.packs.demonstration_checks import EvidenceSnapshot, SnapshotVerifier
from factory.packs.registry import PackRegistry
from factory.projectos.regulated import EmissionContext
from factory.projectos.spec import RegulatedBlock, VerticalSpec


@pytest.fixture
def roles():
    dsn = os.environ.get("FACTORY_TEST_DB_URL", "")
    assert dsn, "explicit isolated factory_test is required"
    return provision_local_roles(dsn)


class SyntheticBoundedCoursePolicy(CoursePolicy):
    """One-unit policy for the shared fictional render fixture only."""
    ref = PolicyRef("course", "synthetic-host-budget", "fixture-1")

    def mission_budget(self, action_id):
        return {"limit": 1, "units": 1} if action_id == "course:render-lesson" else None


def render_request(host, tmp_path, risk_tier=1):
    # An ordinary reversible course operation tests composition, not D1 release.
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(SyntheticBoundedCoursePolicy())
    operation = "course:render-lesson"
    intended.declare(IntendedUse("course", operation, risk_tier))
    base = host.factory.engine
    engine = base.for_policy(registry=registry, preflight=base._preflight.for_uses(intended))
    tenant, body = "synthetic-host", b"Local reversible draft.\n"
    target = FilesystemTargetAdapter(
        path=tmp_path / "draft.txt", tenant_id=tenant, authority=engine.targets,
        uses=host.stores.permits, operation_name=operation, budget=host.stores.budget,
    )
    digest = hashlib.sha256(body).hexdigest()
    context = PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft", "render", 0)
    capability = engine._preflight.authorize(
        tenant_id=tenant, vertical="course", action_id=operation, risk_tier=risk_tier,
        correlation_id="render", now_us=engine.targets.now_us(), ttl_us=60_000_000, nonce="cap",
    )
    authorization = engine.authorize_for_target(
        vertical="course", capability=capability,
        assertion=Assertion("draft", tenant, "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(),
                            mission="synthetic:host-render"))),
        ctx=context, output=body, target=target, nonce="render", permit_ttl_us=60_000_000,
    )
    return engine, authorization, target, body


def test_reference_host_preserves_qualification_and_restricted_recording(roles, tmp_path):
    stores, authorities, alerts, qualifications, report, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    with pytest.raises(GovernanceRefused):
        stores.activation.governance_guard.require("pack-activation", "education")
    engine, authorization, target, body = render_request(host, tmp_path)
    assert authorization.authorized, authorization.reason
    assert authorization.permit.permit.qualification_digests == (report.digest(),)
    assert engine.commit(authorization, body, target).outcome is Outcome.COMMITTED
    assert target.path.read_bytes() == body
    assert stores.budget.committed("synthetic-host", "synthetic:host-render") == 1
    assert stores.recorder.verify_chain("synthetic-host")
    assert not authorities.credential_verifier.provider_backed


def test_configured_monitor_silence_is_preserved_in_policy_sibling(roles, tmp_path):
    stores, authorities, alerts, qualifications, _, keys = configuration(roles, tmp_path)
    authorities = replace(authorities, heartbeat_monitor_key_ids=frozenset({keys["monitor"].key_id}),
                          heartbeat_installation="fixture-installation")
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    base = host.factory.engine
    sibling = base.for_policy(registry=PolicyRegistry(),
                              preflight=base._preflight.for_uses(IntendedUseRegistry()))
    problem = sibling._heartbeat.problem(3, now_us=authorities.clock.now_us())
    assert problem[0] == "MONITOR_HEARTBEAT_STALE"


def test_reference_host_cannot_silently_omit_session_admission(roles, tmp_path):
    stores, authorities, alerts, qualifications, _, keys = configuration(roles, tmp_path)
    unscoped = CredentialVerifier(authorities.trust, keys["credential"], LocalIdentityProvider(),
                                   CertificateRegistry(authorities.trust, {
                                       keys["issuer"].key_id: DEMONSTRATION_CERTIFICATE}))
    with pytest.raises(ValueError, match="session admission"):
        compose_reference_host(stores, replace(authorities, credential_verifier=unscoped),
                               alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")


def test_signed_education_pack_builds_with_reference_guards_and_refuses_inactive_release(roles, tmp_path):
    stores, authorities, alerts, qualifications, _, keys = configuration(roles, tmp_path)
    for key in json.loads((FIXTURES / "trust-anchors.json").read_bytes())["keys"]:
        authorities.trust.register(key["key_id"], bytes.fromhex(key["public_key_hex"]), key["alg"])
    registry = PackRegistry(trust=authorities.trust, activation=stores.activation)
    pack = registry.install(FIXTURES / "bundles" / "education-0.1.2",
                            publisher_key_id=PUBLISHER, today="2026-10-14")
    now = authorities.clock.now_us()
    snapshot = EvidenceSnapshot("school-a", "geometry", "1", "Fictional feedback",
        (("rubric", "1", "Label the equal sides."),), (("rubric", "Label the equal sides."),),
        ("Synthetic evidence only.",), now, now + 60_000_000)
    verifiers = VerifierRegistry()
    verifiers.register("source:fidelity", SnapshotVerifier((snapshot,)))
    authorities = replace(authorities, host_verifiers=verifiers,
                          verifier_signers={name: keys["verifier"]
                                            for name in pack.rulebook.effective_content["checks"]})
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications, floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    document = pack.rulebook.document
    spec = VerticalSpec("education", "course", "education", "project_id", (), regulated=RegulatedBlock(
        policy_ref=f"{document.vertical}/{document.policy_id}", intended_use="formative feedback",
        policy_digest=document.digest(), pack_version=pack.reference,
    ))
    gate = host(pack, registry, SimpleNamespace(spec=spec))
    context = EmissionContext(tenant="school-a", actor_id="teacher", project_id="geometry",
                              vertical_name="education", action_id="release", nonce="inactive")
    decision = gate.authorize_release(spec=spec, contract=snapshot.contract(),
                                      out_path=str(tmp_path / "feedback.txt"), context=context,
                                      artifact=snapshot.render().encode())
    assert not decision.allowed and "inactive" in decision.reason
    assert not (tmp_path / "feedback.txt").exists()
    assert stores.recorder.verify_chain("school-a")
