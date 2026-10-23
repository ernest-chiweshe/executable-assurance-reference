"""X-15 egress enforcement on the reference managed host; offline construction contracts.

Startup performs no database, signing or retention I/O (the fixture's ports assert
that). With every store unavailable, a covered send still refuses fail-closed and
says its refusal is unrecorded. Lawful scope reads, inventory, enrolment and signed
refusal recording on actual restricted logins are in test_managed_egress_pg.py.
"""
import hashlib
from types import SimpleNamespace

import pytest

from assurance_reference.managed_egress import ReferenceManagedHost, compose_reference_managed_host
from factory.egress_composition import EGRESS_SETTING
from regulated_core.egress_admission import EgressAdmission, EgressRefused, EgressRequest
from regulated_core.persistence_pg import PostgresEgressScopeStore
from test_host_contract import NoIOPool, contract  # noqa: F401

ENFORCE = {EGRESS_SETTING: "enforce"}


def _roles(**changes):
    names = ("receiver", "allocator", "recorder", "governor", "delegation_issuer", "egress_reader", "egress_scope")
    return SimpleNamespace(**{**{name: NoIOPool(name) for name in names}, **changes})


def _host(c, env, roles=None):
    return compose_reference_managed_host(
        c.stores, c.authorities, roles=_roles() if roles is None else roles, env=env, alerts=c.alerts,
        qualifications=c.qualifications, floor_not_used_reason="Offline managed-egress construction contract")


def test_enforced_egress_binds_dedicated_reader_and_scope_writer_without_io(contract):  # noqa: F811
    roles = _roles()
    host = _host(contract, ENFORCE, roles)
    assert isinstance(host, ReferenceManagedHost)
    assert isinstance(host.egress.admission, EgressAdmission)
    assert isinstance(host.egress.store, PostgresEgressScopeStore)
    assert host.egress.store._pool is roles.egress_scope
    assert isinstance(host.egress.admission._store, PostgresEgressScopeStore)
    assert host.egress.admission._store._pool is roles.egress_reader
    assert contract.stores.pool not in (host.egress.store._pool, host.egress.admission._store._pool)


@pytest.mark.parametrize("missing", ["egress_reader", "egress_scope"])
def test_managed_host_without_an_egress_login_refuses(contract, missing):  # noqa: F811
    with pytest.raises(ValueError, match="requires explicit egress_reader and egress_scope logins"):
        _host(contract, ENFORCE, _roles(**{missing: None}))


def test_egress_reader_and_writer_must_be_distinct(contract):  # noqa: F811
    with pytest.raises(ValueError, match="must be distinct"):
        _host(contract, ENFORCE, _roles(egress_scope=NoIOPool("egress_reader")))


@pytest.mark.parametrize("shared", ["receiver", "allocator", "recorder", "governor", "delegation_issuer"])
def test_egress_login_shared_with_another_duty_refuses(contract, shared):  # noqa: F811
    with pytest.raises(ValueError, match="must be separate from receiver"):
        _host(contract, ENFORCE, _roles(egress_reader=NoIOPool(shared)))


@pytest.mark.parametrize("env", [{}, {EGRESS_SETTING: ""}, {EGRESS_SETTING: "off"}])
def test_managed_host_without_enforced_egress_refuses_composition(contract, env):  # noqa: F811
    with pytest.raises(ValueError, match="requires FACTORY_EGRESS_ADMISSION=enforce"):
        _host(contract, env)


@pytest.mark.parametrize("value", ["on", "ENFORCE", "true", "enforce-later"])
def test_malformed_egress_setting_refuses_startup(contract, value):  # noqa: F811
    with pytest.raises(ValueError, match="must be unset, 'off' or 'enforce'"):
        _host(contract, {EGRESS_SETTING: value})


def test_unavailable_scope_store_refuses_and_reports_unrecorded_refusal(contract):  # noqa: F811
    # Explicitly unavailable storage (NoIOPool raises), not an empty readable history.
    host = _host(contract, ENFORCE)
    body = b"fictional outbound bytes"
    request = EgressRequest("tenant-a", "teacher", "message:email", "endpoint-1",
                            hashlib.sha256(body).hexdigest(), len(body))
    with pytest.raises(EgressRefused) as refused:
        host.egress.for_tenant("tenant-a").admit(request)
    assert refused.value.code == "EGRESS_SCOPE_UNKNOWN"
    assert "could not be read (AssertionError)" in refused.value.reason
    assert refused.value.reason.endswith("(the refusal could not be recorded)")
    assert refused.value.record == ""


def test_tenant_view_refuses_another_tenants_request(contract):  # noqa: F811
    host = _host(contract, ENFORCE)
    body = b"fictional outbound bytes"
    request = EgressRequest("tenant-b", "teacher", "message:email", "endpoint-1",
                            hashlib.sha256(body).hexdigest(), len(body))
    with pytest.raises(EgressRefused) as refused:
        host.egress.for_tenant("tenant-a").admit(request)
    assert refused.value.code == "EGRESS_TENANT_MISMATCH"
