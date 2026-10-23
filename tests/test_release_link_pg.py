"""Pending real PostgreSQL contracts. No full signed-review/receiver claim."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import fields, replace
import os
from threading import Event

import psycopg
import pytest

from assurance_reference.local_roles import LocalPool, provision_local_roles
from regulated_core.canonical import digest_hex
from test_release_link_admission import scene  # noqa: F401
from assurance_reference.release_link import ReleaseLink, ReleaseLinkRefused
from assurance_reference.release_link_pg import (
    PostgresGoalReleaseStore, provision_release_goal,
)


@pytest.fixture
def stored(scene):  # noqa: F811
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    try:
        # Provisioned with the dedicated release_linker duty by provision_local_roles.
        provision_release_goal(owner, scene.goal)
        scene.service.goals = PostgresGoalReleaseStore(pool=roles.release_linker)
        scene.owner, scene.roles = owner, roles
        # This stage checks the real transaction/store using a synthetic review
        # projection. Full signed-review composition is explicitly outstanding.
        class Reviews:
            def verify(self, goal, request):
                return scene.review
            def current_on(self, conn, goal, request, verified):
                assert conn.execute("SELECT current_setting('app.release_tenant',true)").fetchone()[0] == goal.tenant
                scene.on_current()
                return scene.review
        scene.service.reviews = Reviews()
        yield scene
    finally:
        owner.close()
        for f in fields(roles):
            value = getattr(roles, f.name)
            if isinstance(value, LocalPool):
                value.close()


def test_atomic_link_survives_store_reconstruction_and_exact_retry(stored):
    s = stored
    link = s.service.admit(s.request)
    reopened = PostgresGoalReleaseStore(pool=s.roles.release_linker)
    assert reopened.retained("tenant", s.request) == link
    s.service.goals = reopened
    assert s.service.admit(s.request) == link
    with s.owner.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_release_links_v1").fetchone()[0] == 1


def test_refused_publication_rolls_back_and_retry_can_succeed(stored):
    s = stored
    def refuse():
        raise ReleaseLinkRefused("ordinary current authority refused")
    s.on_current = refuse
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert s.service.goals.retained("tenant", s.request) is None
    s.on_current = lambda: None
    assert s.service.admit(s.request) == s.service.goals.retained("tenant", s.request)


def test_owner_change_between_preflight_and_transaction_refuses(stored):
    s = stored
    store = s.service.goals
    original = store.transact
    def changed(tenant, request, mutation):
        provision_release_goal(s.owner, replace(s.goal, owner="replacement-owner"),
                               expected_digest=digest_hex(s.goal))
        return original(tenant, request, mutation)
    store.transact = changed
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)
    assert store.retained("tenant", s.request) is None


def test_normal_owner_change_waits_for_admission_transaction(stored):
    s = stored
    entered = Event()
    def update():
        entered.set()
        return provision_release_goal(s.owner, replace(s.goal, owner="replacement-owner"),
                                      expected_digest=digest_hex(s.goal))
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = []
        def current():
            future = executor.submit(update)
            pending.append(future)
            assert entered.wait(2)
            with pytest.raises(TimeoutError):
                future.result(timeout=0.2)
        s.on_current = current
        s.service.admit(s.request)
        pending[0].result(timeout=8)
    with pytest.raises(ReleaseLinkRefused):
        s.service.admit(s.request)


def test_different_task_semantics_are_not_overwritten(stored):
    s = stored
    original = s.service.admit(s.request)
    with pytest.raises(ReleaseLinkRefused):
        s.service.goals.transact("tenant", s.request,
            lambda goal, existing, conn: ReleaseLink(s.request, goal, replace(s.review, nonce="different")))
    assert s.service.goals.retained("tenant", s.request) == original


def test_restricted_runtime_duties_and_tenant_scope(stored):
    s = stored
    with s.roles.release_linker.connection() as conn, conn.transaction():
        conn.execute("SELECT set_config('app.release_tenant','other',true)")
        assert conn.execute("SELECT count(*) FROM reference_release_goal_versions_v1").fetchone()[0] == 0
        role = s.roles.release_linker.role
        assert conn.execute("SELECT has_table_privilege(%s,'reference_release_goal_versions_v1','INSERT')",
                            (role,)).fetchone() == (False,)
        assert conn.execute("SELECT has_table_privilege(%s,'reference_release_links_v1','UPDATE'),"
                            "has_table_privilege(%s,'reference_release_links_v1','DELETE')",
                            (role,role)).fetchone() == (False,False)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("CREATE TABLE cannot_create_release_authority(value text)")


def test_two_ordinary_link_calls_publish_one_exact_row(stored):
    s = stored
    def publish():
        return s.service.goals.transact("tenant", s.request,
            lambda goal, existing, conn: ReleaseLink(s.request, goal, s.review))
    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = executor.submit(publish), executor.submit(publish)
        assert first.result(timeout=8) == second.result(timeout=8)
    with s.owner.connection() as conn:
        assert conn.execute("SELECT count(*) FROM reference_release_links_v1").fetchone()[0] == 1
