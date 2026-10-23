"""Synthetic alarm observation only; no release, provider or database operation."""

import json
from types import SimpleNamespace

import pytest

from regulated_core.outage import (
    EventBridgeAlarm, OpenTelemetryAlarm, OutageEvent, RecordingOutageAlarm,
    Severity, SnsAlarm, alarm_envelope,
)
from regulated_core.projectos_gate import _RegulatedGateBase
from regulated_core.kms import KmsUnavailable


@pytest.mark.parametrize("unavailable", [False, True])
@pytest.mark.parametrize("effect_possible", [False, True])
def test_alarm_survives_unavailable_authority_time(unavailable, effect_possible, caplog):
    calls = []

    def now_us():
        calls.append("clock")
        if unavailable:
            raise RuntimeError("synthetic authority clock unavailable")
        return 123

    observed = RecordingOutageAlarm()
    host = SimpleNamespace(
        _engine=SimpleNamespace(targets=SimpleNamespace(now_us=now_us)),
        _outage=observed,
    )
    reason = _RegulatedGateBase._raise_outage(
        host, KmsUnavailable("synthetic signer unavailable"), "fixture-observation",
        SimpleNamespace(tenant="synthetic-tenant"), effect_possible=effect_possible,
    )
    event, = observed.events
    assert calls == ["clock"]
    assert event.at_us == (None if unavailable else 123)
    assert alarm_envelope(event)["at_us"] == (None if unavailable else 123)
    assert event.component == "signer"
    assert event.severity is (Severity.CRITICAL if effect_possible else Severity.HIGH)
    assert event.phase == ("outcome-unknown" if effect_possible else "contained")
    assert "independent alarm was raised" in reason
    clock_errors = [r.clock_error_type for r in caplog.records if hasattr(r, "clock_error_type")]
    assert clock_errors == (["RuntimeError"] if unavailable else [])

@pytest.mark.parametrize("at_us", [None, 123])
@pytest.mark.parametrize("adapter", ["eventbridge", "sns", "otel"])
def test_local_adapter_callbacks_preserve_optional_authority_time(at_us, adapter):
    event = OutageEvent("synthetic-tenant", "signer", "fixture-observation",
                        "SyntheticUnavailable", at_us, Severity.HIGH, "contained")
    calls = []
    if adapter == "eventbridge":
        def put_events(**payload):
            calls.append(payload)
            return {"FailedEntryCount": 0}
        EventBridgeAlarm(put_events).raise_alarm(event)
        payload, = calls
        body = json.loads(payload["Entries"][0]["Detail"])
    elif adapter == "sns":
        def publish(**payload):
            calls.append(payload)
        SnsAlarm(publish, topic_arn="synthetic-local-topic").raise_alarm(event)
        payload, = calls
        body = json.loads(payload["Message"])
        assert payload["MessageAttributes"]["severity"]["StringValue"] == "HIGH"
    else:
        def emit(body, severity_number, severity_text, attributes):
            assert all(value is not None for value in attributes.values())
            calls.append((body, severity_number, severity_text, attributes))
        OpenTelemetryAlarm(emit).raise_alarm(event)
        (serialized, number, name, attributes), = calls
        body = json.loads(serialized)
        assert (number, name) == (17, "HIGH")
        if at_us is None:
            assert "regulated.alarm.at_us" not in attributes
        else:
            assert attributes["regulated.alarm.at_us"] == at_us
    assert body == alarm_envelope(event)
    assert body["at_us"] == at_us
