"""X-20 on actual restricted local logins: server-bound release context at the Project OS entry.

Fictional tenants and members; isolated PostgreSQL. Keys are verified through the dedicated api_key_reader login
on every call, members through the session reader, and project ownership through the session-bound project state.
"""
from dataclasses import fields
import os
from types import SimpleNamespace

import pytest

from assurance_reference.clock_floor import DurableClock
from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.local_sessions import LocalSessions
from assurance_reference.project_entry import (CLIENT_AUTHORITY_FIELDS, ApiKeyVerifier, EntryRefused, ProjectEntry,
                                               issue_api_key, project_state_ownership, revoke_api_key)
from assurance_reference.project_state import compose_project_state
from regulated_core.clock_pg import DbClock

PASSWORD = "fictional-password-001"


@pytest.fixture
def entry():
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    try:
        clock = DurableClock(DbClock(roles.receiver, roles.domain), floor_pool=roles.clock)
        sessions = LocalSessions(reader=roles.session_reader, issuer=roles.session_issuer, clock=clock)

        def member(tenant, principal):
            sessions.provision_identity(tenant, principal, principal + "." + tenant, PASSWORD)
            return sessions.login(tenant, principal + "." + tenant, PASSWORD)

        tokens = {("school-a", "teacher"): member("school-a", "teacher"),
                  ("school-b", "teacher"): member("school-b", "teacher"),
                  ("school-a", "school-a"): member("school-a", "school-a")}
        for tenant in ("school-a", "school-b"):
            identity = sessions.authenticate(tenant, tokens[(tenant, "teacher")])
            compose_project_state(pool=roles.project_state, sessions=sessions, authenticated=identity,
                                  namespace="education").create("geometry-" + tenant, {"stage": "draft"})
        keys = {tenant: issue_api_key(owner, tenant=tenant, scopes=("education",), issued_at_us=clock.now_us())
                for tenant in ("school-a", "school-b")}
        service = ProjectEntry(keys=ApiKeyVerifier(pool=roles.api_key_reader), sessions=sessions,
                               project_exists=project_state_ownership(pool=roles.project_state, sessions=sessions))

        def context(tenant="school-a", member=("school-a", "teacher"), project="geometry-school-a", body=None,
                    vertical="education", key=None):
            return service.context(api_key=key or keys[tenant], session_token=member and tokens[member],
                                   vertical=vertical, project_id=project, body=body or {"nonce": "n-1"})

        yield SimpleNamespace(owner=owner, clock=clock, keys=keys, tokens=tokens, context=context, roles=roles)
    finally:
        owner.close()
        for f in fields(roles):
            value = getattr(roles, f.name)
            if isinstance(value, LocalPool):
                value.close()


def test_tenant_and_actor_come_only_from_authentication(entry):
    context = entry.context(body={"nonce": "n-1", "action_id": "education:release-feedback", "review_id": "r-1"})
    assert (context.tenant, context.actor_id, context.project_id, context.vertical_name) == (
        "school-a", "teacher", "geometry-school-a", "education")
    assert (context.nonce, context.action_id, context.approval) == ("n-1", "education:release-feedback", "r-1")


@pytest.mark.parametrize("field", sorted(CLIENT_AUTHORITY_FIELDS))
def test_client_chosen_tenant_or_actor_is_refused_at_entry(entry, field):
    with pytest.raises(EntryRefused, match="cannot choose the tenant or actor") as refused:
        entry.context(body={"nonce": "n-1", field: "school-b"})
    assert refused.value.status == 400


def test_revoked_api_key_is_refused_on_the_next_request(entry):
    assert entry.context().tenant == "school-a"
    assert revoke_api_key(entry.owner, entry.keys["school-a"], revoked_at_us=entry.clock.now_us())
    with pytest.raises(EntryRefused, match="valid API key") as refused:
        entry.context()
    assert refused.value.status == 401


@pytest.mark.parametrize("key", ["", "rk_" + "0" * 32 + ".forged", "not-a-key"])
def test_unknown_or_forged_api_key_is_refused(entry, key):
    with pytest.raises(EntryRefused, match="valid API key"):
        entry.context(key=key or "rk_")


def test_key_secret_must_match_its_stored_digest(entry):
    key_id = entry.keys["school-a"].split(".", 1)[0]
    with pytest.raises(EntryRefused, match="valid API key"):
        entry.context(key=key_id + ".wrong-secret")


def test_key_not_scoped_to_the_vertical_is_refused(entry):
    with pytest.raises(EntryRefused, match="not scoped") as refused:
        entry.context(vertical="health")
    assert refused.value.status == 403


@pytest.mark.parametrize("member", [None, ("school-a", "school-a"), ("school-b", "teacher")])
def test_workspace_or_foreign_member_is_never_the_approver(entry, member):
    with pytest.raises(EntryRefused, match="individual member account") as refused:
        entry.context(member=member)
    assert refused.value.status == 403


def test_another_tenants_project_is_not_found(entry):
    with pytest.raises(EntryRefused, match="no such project") as refused:
        entry.context(project="geometry-school-b")
    assert refused.value.status == 404
    with pytest.raises(EntryRefused, match="no such project"):
        entry.context(project="geometry-missing")


def test_runtime_key_reader_cannot_issue_or_revoke(entry):
    import psycopg
    with entry.roles.api_key_reader.connection() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("UPDATE reference_api_keys_v1 SET revoked_at_us = NULL")
