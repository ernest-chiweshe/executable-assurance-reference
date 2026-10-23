"""A19: the permit-expiry guard alone refuses an expired permit at the filesystem target (Paper A Table 2, guard 4).

Earlier A19-4 removals survived because the session-admission deadline (``effect_check``) and the database decision-age
bound also refuse expired permits. Here the receiving target is the bare filesystem adapter with no session admission
and no database receiver, and the permit's decision, signature, revocation epoch, preparation and exact bytes all stay
valid: the permit is simply past its absolute expiry on the authority's clock. Only ``require_permit_clock`` in
``TargetAuthority.current`` stands between it and the effect. The same permit verifies before it expires (control).
Ordinary elapsed time on the durable clock; no clock is altered. Isolated PostgreSQL.
"""
import hashlib
import os
import time

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core import Action, ActionEffect, Actor, Assertion, IntendedUse, IntendedUseRegistry, PolicyContext, PolicyRegistry
from regulated_core.persistence_pg import PostgresPermitUseStore
from regulated_core.target import ABSENT, BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination
from test_reference_host import SyntheticBoundedCoursePolicy

PERMIT_TTL_US = 4_000_000


def _short_lived_permit(host, tmp_path):
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(SyntheticBoundedCoursePolicy())
    operation = "course:render-lesson"
    intended.declare(IntendedUse("course", operation, 1))
    base = host.factory.engine
    engine = base.for_policy(registry=registry, preflight=base._preflight.for_uses(intended))
    tenant, body = "synthetic-host", b"Local reversible draft whose permit expires.\n"
    target = FilesystemTargetAdapter(path=tmp_path / "draft.txt", tenant_id=tenant, authority=engine.targets,
                                     uses=host.stores.permits, operation_name=operation, budget=host.stores.budget)
    digest = hashlib.sha256(body).hexdigest()
    capability = engine._preflight.authorize(
        tenant_id=tenant, vertical="course", action_id=operation, risk_tier=1, correlation_id="expiry",
        now_us=engine.targets.now_us(), ttl_us=60_000_000, nonce="cap-expiry")
    authorization = engine.authorize_for_target(
        vertical="course", capability=capability,
        assertion=Assertion("draft", tenant, "course:lesson", content_digest=digest),
        action=Action(operation, ActionEffect.REVERSIBLE, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(), mission="synthetic:expiry"))),
        ctx=PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft", "expiry", 0),
        output=body, target=target, nonce="expiry", permit_ttl_us=PERMIT_TTL_US)
    assert authorization.authorized, authorization.reason
    return authorization.permit, target, body


def test_an_expired_permit_is_refused_by_the_expiry_guard_alone(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Synthetic local fixture; generation retirement is not qualified")
    signed, target, body = _short_lived_permit(host, tmp_path)
    permit = signed.permit
    receiving = FilesystemTargetAdapter(target.path, target.tenant_id, target.authority,
                                        PostgresPermitUseStore(pool=roles.receiver), operation_name=target.operation,
                                        budget=target.budget)
    assert receiving.effect_check is None  # No session-admission deadline on this path.
    # Control: before expiry every check passes, including the clock window.
    receiving.authority.verify(signed, body, tenant_id=receiving.tenant_id, target=receiving.target,
                               operation=receiving.operation, current_target_state=ABSENT)
    remaining = permit.expires_at_us - receiving.authority.now_us()
    time.sleep(max(remaining, 0) / 1_000_000 + 0.25)
    assert receiving.authority.now_us() > permit.expires_at_us
    result = receiving.commit(signed, body)
    assert result.outcome is Outcome.FAILED, result
    assert "window" in result.detail or "expired" in result.detail, result.detail
    assert not receiving.path.exists() and not stores.permits.used(permit.tenant_id, permit.nonce)
