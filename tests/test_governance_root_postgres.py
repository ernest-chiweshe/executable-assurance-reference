"""Signed governance and a retained local root under restricted runtime roles."""

import json
import os
import time

import pytest

from assurance_reference.governance_artifact import retain_governance_artifact, verify_governance_artifact
from assurance_reference.lifecycle_migration import provision_partitioned_local_roles
from assurance_reference.packs import verify_bundles
from partitioned_governance_fixture import GovernedFixture
from regulated_core.persistence_pg import PostgresGovernanceLog
from regulated_core.target import Outcome
from regulated_core.worm import LocalWormStore


@pytest.fixture
def app():
    roles = provision_partitioned_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        yield GovernedFixture(roles)
    finally:
        for value in vars(roles).values():
            if callable(getattr(value, "close", None)):
                value.close()


def test_two_signed_approvers_change_policy_and_export_verifiable_root(app, tmp_path):
    tenant = "synthetic-office"
    references = [item["reference"] for item in verify_bundles()["bundles"]]
    for reference in references:
        result, _, _, _ = app.enact(tenant, {"activate": reference, "at": "synthetic fixture"})
        assert result.outcome is Outcome.COMMITTED, result.detail
    assert app.packs.active(references[0].partition("#")[0]).reference == references[-1]
    reopened = PostgresGovernanceLog(pool=app.roles.governor)
    root = reopened.root(tenant)
    assert [event.phase for event in reopened.events(tenant)] == ["prepared", "committed"] * 2
    artifact = retain_governance_artifact(reopened, LocalWormStore(), tenant,
                                          retain_us=60_000_000, now_us=app.clock.now_us())
    path = tmp_path / "governance-root.json"
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    assert verify_governance_artifact(json.loads(path.read_bytes()),
                                      expected_tenant=tenant, expected_root=root)
    assert artifact["root_record"]["events"] == 4
    assert artifact["receipt"]["provider"] == "local-mock"


def test_expired_governance_permit_refuses_before_policy_write(app):
    tenant = "synthetic-office"
    reference = verify_bundles()["bundles"][0]["reference"]
    pack = reference.partition("#")[0]

    def let_signed_permit_expire(authorized):
        remaining = authorized.permit.permit.expires_at_us - app.clock.now_us()
        if remaining >= 0:
            time.sleep((remaining + 20_000) / 1_000_000)

    result, _, _, _ = app.enact(tenant, {"activate": reference, "at": "synthetic fixture"},
                                permit_ttl_us=100_000, before_commit=let_signed_permit_expire)
    assert result.outcome is Outcome.FAILED, result.detail
    assert app.packs.active(pack) is None
    assert not any(event.phase == "committed" for event in app.log.events(tenant))
