"""Local configured-alarm compatibility with an explicitly unavailable authority time."""
import json
import logging

import pytest

from regulated_core.outage import (
    AlarmRoute, FanOutAlarm, OutageEvent, RecordingOutageAlarm, Severity,
    alarm_envelope, alarm_from_config,
)


@pytest.mark.parametrize("at_us", [None, 123456])
@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
def test_configured_routes_preserve_envelope_and_filter_severity(at_us, severity, caplog):
    calls = {"eventbridge": [], "sns": [], "otel": []}

    def put_events(**kwargs):
        calls["eventbridge"].append(kwargs)
        return {"FailedEntryCount": 0}

    def publish(**kwargs):
        calls["sns"].append(kwargs)
        return {"MessageId": "synthetic-local-only"}

    def emit(body, number, text, attributes):
        calls["otel"].append((body, number, text, attributes))

    alarm = alarm_from_config(
        {"FACTORY_ALARM_ROUTES": "eventbridge:HIGH,sns:CRITICAL,otel:HIGH",
         "FACTORY_ALARM_EVENT_BUS": "synthetic-local",
         "FACTORY_ALARM_SNS_TOPIC_ARN": "synthetic-local-topic"},
        clients={"put_events": put_events, "publish": publish, "otel_emit": emit},
    )
    event = OutageEvent("synthetic-tenant", "signer", "authorize_release",
                        "SyntheticUnavailable", at_us, severity,
                        "contained" if severity == Severity.HIGH else "outcome-unknown")
    expected = alarm_envelope(event)
    with caplog.at_level(logging.CRITICAL, logger="regulated_core.outage"):
        alarm.raise_alarm(event)
    logs = [r for r in caplog.records if r.name == "regulated_core.outage"]
    assert len(logs) == 1 and json.loads(logs[0].getMessage()) == expected
    assert len(calls["eventbridge"]) == 1
    entries = calls["eventbridge"][0]["Entries"]
    assert len(entries) == 1 and entries[0]["EventBusName"] == "synthetic-local"
    assert json.loads(entries[0]["Detail"]) == expected
    assert len(calls["sns"]) == (1 if severity == Severity.CRITICAL else 0)
    if calls["sns"]:
        assert json.loads(calls["sns"][0]["Message"]) == expected
    assert len(calls["otel"]) == 1
    body, number, text, attributes = calls["otel"][0]
    assert json.loads(body) == expected
    assert (number, text) == (int(severity), severity.name)
    assert attributes == {"regulated.alarm." + k: v for k, v in expected.items() if v is not None}


@pytest.mark.parametrize("at_us", [None, 123456])
def test_recording_routes_keep_exact_event_identity(at_us):
    log, sink = RecordingOutageAlarm(), RecordingOutageAlarm()
    event = OutageEvent("synthetic-tenant", "signer", "authorize_release",
                        "SyntheticUnavailable", at_us, Severity.HIGH, "contained")
    FanOutAlarm([AlarmRoute(sink, Severity.HIGH)], log=log).raise_alarm(event)
    assert len(log.events) == len(sink.events) == 1
    assert log.events[0] is event and sink.events[0] is event
