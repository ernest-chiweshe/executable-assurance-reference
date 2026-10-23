"""Preflight admission precedes a budget that cannot admit any spend."""
from dataclasses import replace

import pytest

from test_reference_host_budget_contract import composition


@pytest.mark.parametrize("engine_type", ["core", "reference"])
def test_mismatched_request_refuses_preflight_before_zero_budget(tmp_path, engine_type):
    engine, request, signer, budget, events, uses = composition(
        tmp_path, {"limit": 0, "units": 1}, engine_type=engine_type)
    # A genuine capability for the original request cannot admit another request.
    request["ctx"] = replace(request["ctx"], correlation_id="different-request")
    refused = engine.authorize_for_target(**request, nonce="preflight-order")
    assert not refused.authorized and refused.permit is None
    assert refused.envelope.record.decision.reason_codes == ("PREFLIGHT_INVALID",)
    assert events == [] and signer.calls == 0
    assert budget.committed(request["ctx"].tenant_id, "synthetic:mission") == 0
    assert not uses.used(request["ctx"].tenant_id, "preflight-order")
    assert not request["target"].path.exists()
    assert engine._recorder.verify_chain(request["ctx"].tenant_id)
