"""X-15 egress enforcement on actual restricted local logins; synthetic tenants, isolated PostgreSQL.

The managed host's send-time admission reads through the read-only egress_reader
login and inventory/enrolment append through the egress_scope login. Neither the
receiver nor any migration credential holds scope duties. Every refusal here is a
signed deny on the tenant's own evidence chain; nothing is sent while unknown,
regulated or changed.
"""
import hashlib
import os
import uuid

import psycopg
import pytest

from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.managed_egress import compose_reference_managed_host
from factory.egress_composition import EGRESS_SETTING
from regulated_core.egress_admission import (EGRESS_POLICY_ID, EgressRefused, EgressRequest, Passthrough, Regulated,
                                             Unregulated, inventory_tenant, scope_state)
from regulated_core.models import DecisionKind
from regulated_core.persistence_pg import PostgresEgressScopeStore

ENFORCE = {EGRESS_SETTING: "enforce"}
BODY = b"fictional outbound bytes"


@pytest.fixture
def managed(tmp_path):
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, tmp_path)
    host = compose_reference_managed_host(
        stores, authorities, roles=roles, env=ENFORCE, alerts=alerts, qualifications=qualifications,
        floor_not_used_reason="Local managed-egress fixture")
    try:
        yield roles, stores, host
    finally:
        for value in vars(roles).values():
            if isinstance(value, LocalPool):
                value.close()


def _tenant():
    return "synthetic-tenant-" + uuid.uuid4().hex[:12]


def _request(tenant):
    return EgressRequest(tenant, "fictional-teacher", "message:email", "endpoint-1",
                         hashlib.sha256(BODY).hexdigest(), len(BODY))


def _signed_deny(stores, tenant, refused, code):
    assert refused.code == code and refused.record
    assert "could not be recorded" not in refused.reason
    entries = [e for e in stores.recorder.entries(tenant) if e.record.record_id == refused.record]
    assert len(entries) == 1
    record = entries[0].record
    assert record.decision.kind is DecisionKind.DENY and record.decision.reason_codes == (code,)
    assert record.policy.policy_id == EGRESS_POLICY_ID and record.action.action_id == "egress:send"
    assert stores.recorder.verify_chain(tenant)


def _scope_lock_free(pool, tenant):
    with pool.connection() as conn, conn.transaction():
        return conn.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                            ("regulated-egress-scope:" + tenant,)).fetchone()[0]


def test_scope_duties_are_held_only_by_the_dedicated_egress_logins(managed):
    roles, _, _ = managed
    tenant = _tenant()
    reader = PostgresEgressScopeStore(pool=roles.egress_reader)
    assert reader.events(tenant) == ()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        reader.enroll(tenant, "pack:fictional", source="fixture")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        PostgresEgressScopeStore(pool=roles.receiver).events(tenant)
    writer = PostgresEgressScopeStore(pool=roles.egress_scope)
    assert writer.record_inventory(tenant, frozenset(), evidence="fixture:inventory") == 1
    with roles.egress_scope.connection() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant', %s, true)", (tenant,))
            conn.execute("UPDATE regulated_egress_scope_v1 SET source = 'changed' WHERE tenant = %s", (tenant,))


def test_readable_empty_history_refuses_with_a_signed_record(managed):
    _, stores, host = managed
    tenant = _tenant()
    assert host.egress.store.events(tenant) == ()
    with pytest.raises(EgressRefused) as refused:
        host.egress.for_tenant(tenant).admit(_request(tenant))
    assert refused.value.reason == "no inventory of this tenant's existing data has been recorded"
    _signed_deny(stores, tenant, refused.value, "EGRESS_SCOPE_UNKNOWN")


def test_inventoried_unregulated_tenant_sends_holding_the_scope_lock(managed):
    roles, _, host = managed
    tenant = _tenant()
    state = inventory_tenant(host.egress.store, tenant, (lambda t: frozenset(),), evidence="fixture:inventory")
    assert state == Unregulated(1)
    view = host.egress.for_tenant(tenant)
    admitted = view.admit(_request(tenant))
    assert isinstance(admitted, Passthrough) and admitted.revision == 1
    held = []

    def transport():
        # Observed from the scope writer: an enrolment cannot commit while the send starts.
        held.append(_scope_lock_free(roles.egress_scope, tenant))
        return "sent"

    assert view.send(admitted, _request(tenant), transport) == "sent"
    assert held == [False]
    assert _scope_lock_free(roles.egress_scope, tenant) is True


def test_enrolment_after_admission_refuses_the_send_with_a_signed_record(managed):
    _, stores, host = managed
    tenant = _tenant()
    inventory_tenant(host.egress.store, tenant, (lambda t: frozenset(),), evidence="fixture:inventory")
    view = host.egress.for_tenant(tenant)
    admitted = view.admit(_request(tenant))
    host.egress.project_enrollment(tenant)("pack:fictional-health", "project-1")
    sent = []
    with pytest.raises(EgressRefused) as refused:
        view.send(admitted, _request(tenant), lambda: sent.append(True))
    assert not sent
    _signed_deny(stores, tenant, refused.value, "EGRESS_SCOPE_CHANGED")


def test_enrolled_regulated_tenant_refuses_undeclared_egress_with_a_signed_record(managed):
    _, stores, host = managed
    tenant = _tenant()
    host.egress.project_enrollment(tenant)("pack:fictional-health", "project-1")
    host.egress.project_enrollment(tenant)("pack:fictional-health", "project-2")
    assert scope_state(host.egress.store, tenant) == Regulated(frozenset({"pack:fictional-health"}), 1)
    with pytest.raises(EgressRefused) as refused:
        host.egress.for_tenant(tenant).admit(_request(tenant))
    _signed_deny(stores, tenant, refused.value, "EGRESS_NOT_DECLARED")


def test_scope_history_is_tenant_isolated_on_the_restricted_logins(managed):
    roles, _, host = managed
    first, second = _tenant(), _tenant()
    inventory_tenant(host.egress.store, first, (lambda t: frozenset(),), evidence="fixture:inventory")
    assert PostgresEgressScopeStore(pool=roles.egress_reader).events(second) == ()
    with roles.egress_reader.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.tenant', %s, true)", (second,))
        assert conn.execute("SELECT count(*) FROM regulated_egress_scope_v1").fetchone() == (0,)
    with roles.egress_scope.connection() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant', %s, true)", (second,))
            conn.execute("INSERT INTO regulated_egress_scope_v1 (tenant, revision, kind, pack_ref, packs, source)"
                         " VALUES (%s, 1, 'inventoried', '', '[]'::jsonb, 'cross-tenant')", (first,))
