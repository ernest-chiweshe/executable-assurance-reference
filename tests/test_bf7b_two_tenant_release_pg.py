"""B-F7b on two-tenant population: release goals, materials and links, and the tenant-owner roster.

Rows are written only through the product's own paths: the owner-provisioning functions (provision_release_goal,
provision_release_material, set_tenant_owner: owner duties by design, as no runtime login holds INSERT on those
tables) and the restricted release_linker store for the link itself (PostgresGoalReleaseStore.transact; the signed
review composition of the admission service is outstanding in this reference, so the link body uses the same
synthetic verified binding as tests/test_release_link_pg.py). Owner provisioning goes through those product APIs on
the migration-owner connection; there is no direct administrator SQL seeding. Then, for every runtime login that may
read these tables, as each tenant: every visible row belongs to that tenant, and every table holds rows for both
tenants (across the readers together; this does not show that each individual reader sees its own rows).
"""
import os

import pytest

from assurance_reference.local_roles import LocalPool, provision_local_roles
from assurance_reference.release_link import (GoalReleaseBinding, ReleaseLink, ReleaseLinkRequest,
                                              VerifiedReleaseBinding)
from assurance_reference.release_link_authority import provision_release_material
from assurance_reference.release_link_pg import PostgresGoalReleaseStore, provision_release_goal
from assurance_reference.role_contract import ROLES, expected_privileges
from assurance_reference.sole_owner_approval import set_tenant_owner
from factory.projectos.regulated import EmissionContext, ReleaseAuthorityBinding
from test_bf7b_two_tenant_lawful_pg import _rows, _tenant_column

TENANTS = ("release-tenant-a", "release-tenant-b")
TABLES = ("reference_release_goal_heads_v1", "reference_release_goal_versions_v1",
          "reference_release_materials_v1", "reference_release_links_v1", "reference_tenant_owners_v1")


@pytest.fixture(scope="module")
def two_tenants():
    dsn = os.environ["FACTORY_TEST_DB_URL"]
    roles = provision_local_roles(dsn)
    owner = LocalPool(dsn, roles.schema, "migration-owner")
    try:
        for tenant in TENANTS:
            request = ReleaseLinkRequest("goal", "task", "education", "project", "review", "target")
            goal = GoalReleaseBinding(tenant, "goal", "owner", "a" * 64, "b" * 64, 100,
                                      "education", "project", "instance", "executor")
            review = VerifiedReleaseBinding(tenant, "executor", "education", "project", "instance",
                "review", "target", "action", "nonce", "c" * 64, "d" * 64, 80,
                ReleaseAuthorityBinding("e" * 64, "f" * 64, "1" * 64, "root-mission"))
            provision_release_goal(owner, goal)
            store = PostgresGoalReleaseStore(pool=roles.release_linker)
            link = store.transact(tenant, request, lambda current, existing, conn: ReleaseLink(request, current, review))
            assert link.goal.tenant == tenant
            provision_release_material(owner, goal_id="goal", review_id="review",
                contract={"fixture": "bf7b"}, context=EmissionContext(
                    tenant=tenant, actor_id="executor", project_id="project", vertical_name="education",
                    action_id="release", nonce="nonce", now_us=1, not_after_us=2**62))
            set_tenant_owner(owner, tenant=tenant, principal="owner", active_from_us=1)
        yield roles
    finally:
        owner.close()


def test_every_reader_sees_only_its_tenants_release_and_owner_rows(two_tenants):
    roles = two_tenants
    populated = {tenant: set() for tenant in TENANTS}
    checked = 0
    for kind in ROLES:
        with getattr(roles, kind).connection() as conn:
            for table in TABLES:
                if "SELECT" not in expected_privileges(kind, table):
                    continue
                column = _tenant_column(conn, table)
                assert column is not None, table
                for tenant in TENANTS:
                    values = _rows(conn, table, column, tenant)
                    assert all(v == tenant for v in values), (kind, table, tenant, values[:3])
                    if values:
                        populated[tenant].add(table)
                checked += 1
    assert checked >= len(TABLES)
    both = populated[TENANTS[0]] & populated[TENANTS[1]]
    assert both == set(TABLES), sorted(set(TABLES) - both)
