"""Observe intact release ordering without retaining or using internal permits."""

import os

import pytest

from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_retention import LocalRetentionStore
from assurance_reference.local_roles import provision_local_roles
from regulated_core.worm import WormUnavailable
from test_education_record_outage import CountingSigner
from test_education_session_release import reviewed_context


@pytest.mark.parametrize("failure", [None, "anchor", "verification"])
def test_education_records_and_verifies_retention_before_signing(tmp_path, failure):
    events = []
    observation = {"armed": False, "recorder": None}

    class ObservedSigner(CountingSigner):
        def sign(self, body):
            if observation["armed"] and self.key_id.endswith(":emission"):
                events.append("permit-signing")
            return super().sign(body)

        def sign_bytes(self, body):
            if observation["armed"] and self.key_id.endswith(":emission"):
                events.append("permit-signing")
            return super().sign_bytes(body)

    class ObservedRetention:
        def __init__(self):
            self.delegate = LocalRetentionStore(tmp_path / "retention")

        def anchor(self, tenant, data, **kwargs):
            if observation["armed"]:
                assert "permit-signing" not in events
                recorder = observation["recorder"]
                assert len(recorder.entries(tenant)) > observation["prior_entries"]
                assert recorder.verify_chain(tenant)
                events.append("record-present-at-anchor")
                if failure == "anchor":
                    raise WormUnavailable("synthetic retention unavailable")
            return self.delegate.anchor(tenant, data, **kwargs)

        def verify(self, receipt):
            if observation["armed"]:
                assert "permit-signing" not in events
                events.append("retention-verification")
                if failure == "verification":
                    return False
            return self.delegate.verify(receipt)

        def fetch(self, tenant, object_ref):
            return self.delegate.fetch(tenant, object_ref)

    app = build_education_fixture(provision_local_roles(os.environ["FACTORY_TEST_DB_URL"]),
        tmp_path, retention=ObservedRetention(), signer_factory=ObservedSigner)
    context = reviewed_context(app)
    observation.update(armed=True, recorder=app.stores.recorder,
                       prior_entries=len(app.stores.recorder.entries("school-a")))
    gate = app.gates["requester"]
    decision = gate.authorize_release(spec=app.spec, contract=app.contract,
        out_path=str(app.path), context=context, artifact=app.body)
    assert not app.path.exists()
    assert app.stores.recorder.verify_chain("school-a")
    if failure:
        assert not decision.allowed and decision.permit is None
        assert "permit-signing" not in events
        assert events[0] == "record-present-at-anchor"
        assert decision.evidence["outage"] == "write-once-evidence"
        assert not app.stores.permits.used("school-a", context.nonce)
    else:
        assert decision.allowed and decision.permit is not None, decision.reason
        assert events[:3] == ["record-present-at-anchor", "retention-verification", "permit-signing"]
        assert "worm_retention" in decision.evidence
        observation["armed"] = False
        result = gate.commit_release(spec=app.spec, contract=app.contract, decision=decision,
            out_path=str(app.path), context=context, artifact=app.body)
        assert result.state == "committed", result
        assert app.path.read_bytes() == app.body
