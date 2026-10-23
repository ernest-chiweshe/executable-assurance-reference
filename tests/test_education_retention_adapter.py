"""Guarded scoped Education refuses synthetic unverified retention responses."""

from dataclasses import fields
import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from regulated_core.providers_aws import S3ObjectLockWormStore
from retention_adapter_fixtures import RetentionResponses, no_provider_sdks  # noqa: F401
from test_education_scoped_release import source_decision
from test_education_session_release import reviewed_context


@pytest.mark.parametrize("fault", [None, "mode", "short", "bytes", "version", "missing-retention", "unavailable"])
def test_stored_retention_is_checked_before_release_permit(tmp_path, fault):
    client = RetentionResponses()
    retention = S3ObjectLockWormStore("fictional-bucket", compliance=True, client=client)
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        app = build_education_fixture(roles, tmp_path, retention=retention, scoped_authority=True)
        assert source_decision(app)["confirmed"]
        context = reviewed_context(app)
        client.fault = fault
        decision = app.gates["requester"].authorize_release(spec=app.spec, contract=app.contract,
            out_path=str(app.path), context=context, artifact=app.body)
        if fault is None:
            assert decision.allowed and decision.permit is not None
            result = app.gates["requester"].commit_release(spec=app.spec, contract=app.contract,
                decision=decision, artifact=app.body, out_path=str(app.path), context=context)
            assert result.state == "committed", result
            assert app.path.read_bytes() == app.body
        else:
            assert not decision.allowed and decision.permit is None
            assert decision.evidence["outage"] == "write-once-evidence"
            assert not app.path.exists()
        assert app.stores.recorder.verify_chain("school-a")
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()
