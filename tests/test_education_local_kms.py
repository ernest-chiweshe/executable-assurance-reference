"""Full scoped Education with the original LocalKms/KmsSigner seam.

All keys remain local mock keys. Reuse existing guarded outage contracts;
never change a guard, policy, authority clock or deadline to induce an effect.
"""

from dataclasses import fields
import hashlib
import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_roles import LocalPool, provision_local_roles
from local_kms_fixtures import LocalKmsFixtureSigner
from regulated_core.canonical import canonical_bytes
from regulated_core.outage import AlarmRoute, FanOutAlarm, RecordingOutageAlarm, Severity
from test_education_scoped_release import source_decision
from test_education_session_release import approved_request
from test_education_signer_outage import BrokenAlarm
from test_education_signer_outage import (  # noqa: F401
    test_signer_failure_before_permit_refuses_and_raises_independent_alarm,
    test_outcome_signer_failure_is_unknown_then_reconciles_from_existing_receipt,
    test_broken_alarm_sink_does_not_mask_signer_refusal,
)


@pytest.fixture
def signer_app(tmp_path, request):
    drivers = {}

    def signer_factory(key_id):
        signer = LocalKmsFixtureSigner(key_id)
        drivers[key_id.rsplit(":", 1)[1]] = signer
        return signer

    observed = RecordingOutageAlarm()
    routes = [AlarmRoute(observed, Severity.HIGH, "local-observer")]
    if getattr(request, "param", False):
        routes.insert(0, AlarmRoute(BrokenAlarm(), Severity.HIGH, "broken-fixture"))
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        app = build_education_fixture(roles, tmp_path, signer_factory=signer_factory,
            outage_alarm=FanOutAlarm(routes), scoped_authority=True)
        assert source_decision(app)["confirmed"]
        assert all(key.custody.provider == "local-mock" for key in drivers.values())
        yield app, drivers, observed
    finally:
        for field in fields(roles):
            pool = getattr(roles, field.name)
            if isinstance(pool, LocalPool):
                pool.close()


def test_scoped_local_kms_release_retains_exact_artifact_and_receipt(signer_app):
    app, drivers, observed = signer_app
    context, decision = approved_request(app)
    gate = app.gates["requester"]
    result = gate.commit_release(spec=app.spec, contract=app.contract,
        context=context, decision=decision, artifact=app.body, out_path=str(app.path))
    assert result.state == "committed", result
    assert app.path.read_bytes() == app.body
    assert app.stores.recorder.verify_chain("school-a")
    receipt = gate.release_receipt(spec=app.spec, out_path=str(app.path), tenant="school-a",
        nonce=context.nonce, artifact_sha256=hashlib.sha256(app.body).hexdigest(),
        decision_record_hash=decision.permit.envelope.record_hash)
    assert receipt is not None and not observed.events
    (app.path.parent / "local-kms-release-evidence.json").write_bytes(canonical_bytes({
        "fixture": True, "scope": "Scoped Education with original LocalKms/KmsSigner seam",
        "custody": {name: key.custody.as_dict() for name, key in drivers.items()},
        "public_keys": app.public_keys, "permit": decision.permit.permit,
        "receipt": receipt, "outcome": result,
        "chain": app.stores.recorder.entries("school-a"),
        "limits": "Local in-process mock keys; no external custody or full A11 closure.",
    }))
