"""X-15 egress enforced / X-8 on the managed host: outbound delivery composes admission and the governed egress target.

The managed reference host builds the egress delivery target over its own engine, budget, permit-use store, target
authority and governance log, and ``deliver`` admits the exact send against the tenant's scope before committing the
permit while that scope lock is held. An inventoried unregulated tenant delivers exactly once; a tenant with unknown
scope, or a regulated tenant whose packs declare no egress action, is refused before any request. This composition
case uses the host egress policy with no human approver (a trusted machine endpoint: every send still needs a permit
and is recorded); approval is exercised in test_x8_governed_egress_pg.py. Synthetic destination; no network.
"""
from hashlib import sha256
import os
import uuid

import pytest

from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.governed_egress import DuplicateSendRefused
from assurance_reference.managed_egress import compose_reference_managed_host
from factory.egress_composition import EGRESS_SETTING
from factory.governed_http import HttpEndpoint
from factory.governed_http_pg import migrate_http_attempts
from regulated_core import Action, ActionEffect, Actor, Assertion, PolicyContext
from regulated_core.choke_points import EGRESS_CONTENT_TYPE, EGRESS_OPERATION, EgressPolicy, egress_bytes
from regulated_core.egress_admission import EgressRefused
from regulated_core.persistence_pg import PostgresEgressScopeStore
from regulated_core.target import BoundEffect, Outcome, effect_destination
from test_x8_governed_egress_pg import SyntheticDestination


class BudgetedEgressPolicy(EgressPolicy):
    """The host's explicit egress policy for this fixture, with its declared mission budget: the managed host has no
    default budget, so an undeclared one is refused fail-closed ("no policy budget or host default")."""

    def mission_budget(self, action_id):
        return {"limit": 4, "units": 1}


@pytest.fixture
def managed(tmp_path):
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    try:
        migrate_http_attempts(owner)
        with owner.connection() as conn, conn.transaction():
            conn.execute(f"GRANT SELECT, INSERT ON regulated_http_attempts_v1 TO {roles.receiver.role}")
    finally:
        owner.close()
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_managed_host(stores, authorities, roles=roles, env={EGRESS_SETTING: "enforce"},
        alerts=alerts, qualifications=qualifications, floor_not_used_reason="Local managed-delivery fixture")
    yield roles, host


def _send(roles, host, tenant, *, scope):
    writer = PostgresEgressScopeStore(pool=roles.egress_scope)
    if scope == "unregulated":
        writer.record_inventory(tenant, frozenset(), evidence="fixture:inventory")
    elif scope == "regulated":
        writer.record_inventory(tenant, frozenset({"pack:fictional"}), evidence="fixture:inventory")
    engine = host.egress_engine(BudgetedEgressPolicy(approvers=0))
    destination = SyntheticDestination("https://destination.example.org")
    endpoint = HttpEndpoint(tenant_id=tenant, endpoint_id="synthetic-publication",
                            delivery_url=destination.origin + "/deliver", receipt_url=destination.origin + "/receipts")
    target = host.delivery_target(endpoint, request=destination, engine=engine)
    output = egress_bytes("synthetic-publication", media_type="text/plain", payload="Fictional managed bulletin.")
    digest = sha256(output).hexdigest()
    now = engine.targets.now_us()
    capability = engine._preflight.authorize(tenant_id=tenant, vertical="egress", action_id=EGRESS_OPERATION,
        risk_tier=2, correlation_id="managed", now_us=now, ttl_us=120_000_000, nonce="cap-managed")
    authorized = engine.authorize_for_target(vertical="egress", capability=capability,
        assertion=Assertion("managed-outbound", tenant, EGRESS_CONTENT_TYPE, digest),
        action=Action(EGRESS_OPERATION, ActionEffect.EXTERNAL, destination=effect_destination(
            {}, BoundEffect(digest, target.target, target.current_state(), mission="fixture:managed-egress"))),
        ctx=PolicyContext(tenant, Actor("publisher", tenant, frozenset()), "fixture:egress", "managed", now),
        output=output, target=target, permit_ttl_us=60_000_000, nonce="send-managed")
    assert authorized.authorized, authorized.reason
    return engine, destination, target, authorized, output


def test_an_inventoried_tenant_delivers_exactly_once_through_the_managed_host(managed):
    roles, host = managed
    tenant = "synthetic-managed-" + uuid.uuid4().hex[:8]
    engine, destination, target, authorized, output = _send(roles, host, tenant, scope="unregulated")
    result = host.deliver(engine, authorized, output, target, subject="publisher", purpose="publish:bulletin")
    assert result.outcome is Outcome.COMMITTED, result
    assert len(destination.posts) == 1
    with pytest.raises(DuplicateSendRefused, match="refused at egress"):
        host.deliver(engine, authorized, output, target, subject="publisher", purpose="publish:bulletin")
    assert len(destination.posts) == 1


@pytest.mark.parametrize("scope,code", [("unknown", "EGRESS_SCOPE_UNKNOWN"), ("regulated", "EGRESS_NOT_DECLARED")])
def test_admission_refuses_before_any_request(managed, scope, code):
    roles, host = managed
    tenant = "synthetic-managed-" + uuid.uuid4().hex[:8]
    engine, destination, target, authorized, output = _send(roles, host, tenant, scope=scope)
    with pytest.raises(EgressRefused) as refused:
        host.deliver(engine, authorized, output, target, subject="publisher", purpose="publish:bulletin")
    assert refused.value.code == code
    assert destination.posts == [] and not engine._emission.uses.used(tenant, authorized.permit.permit.nonce)
