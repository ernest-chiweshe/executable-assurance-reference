"""Preventive catalog contracts using synthetic observations only.

Calls the unchanged original catalog guard. No PostgreSQL connection, role-state
change, target, or effect exists. Full host enforcement is a separate test.
"""

from types import SimpleNamespace

import pytest

from factory.customer.generation_floor_pg import GenerationFloorVerifier
from regulated_core.identity_provider import CredentialError


class SyntheticCatalog:
    def __init__(self, *, roles, live_membership=None, active_session=None):
        self.roles = roles
        self.live_membership = live_membership
        self.active_session = active_session
        self.reads = []

    def execute(self, statement, parameters):
        assert parameters == (["fixture:retired"],)
        query = " ".join(statement.split())
        assert query.startswith(("SELECT ", "WITH RECURSIVE "))
        if query.startswith("SELECT rolname,rolcanlogin"):
            self.reads.append("role-flags")
            return SimpleNamespace(fetchall=lambda: self.roles)
        if query.startswith("WITH RECURSIVE grantees"):
            self.reads.append("membership-observation")
            return SimpleNamespace(fetchone=lambda: self.live_membership)
        assert "pg_catalog.pg_stat_activity" in query
        self.reads.append("session-observation")
        return SimpleNamespace(fetchone=lambda: self.active_session)


@pytest.mark.parametrize("catalog,reason,reads", [
    (SyntheticCatalog(roles=[]), "missing or still enabled", ["role-flags"]),
    (SyntheticCatalog(roles=[("fixture:retired", True)]), "missing or still enabled", ["role-flags"]),
    (SyntheticCatalog(roles=[("fixture:retired", False)], live_membership=(1,)),
     "granted to a live login", ["role-flags", "membership-observation"]),
    (SyntheticCatalog(roles=[("fixture:retired", False)], active_session=(1,)),
     "still has a database session", ["role-flags", "membership-observation", "session-observation"]),
], ids=["missing-role", "enabled-observation", "live-membership-observation", "session-observation"])
def test_original_catalog_guard_refuses_disqualifying_synthetic_observations(catalog, reason, reads):
    with pytest.raises(CredentialError, match=reason):
        GenerationFloorVerifier._retired_on(catalog, ("fixture:retired",))
    assert catalog.reads == reads


def test_original_catalog_guard_requires_all_three_clear_observations():
    catalog = SyntheticCatalog(roles=[("fixture:retired", False)])
    GenerationFloorVerifier._retired_on(catalog, ("fixture:retired",))
    assert catalog.reads == ["role-flags", "membership-observation", "session-observation"]
