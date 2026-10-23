"""A17: authority outage alarms carry levels and reach the organisation's own infrastructure, never one fixed target.

Paper A section 5.3; docs/ARCHITECTURE-OF-RECORD/08 row A17; owner direction 27 September 2026. The real patient
education gate raises the outage; the sinks receive the host's own client calls, recorded here instead of a network,
so each proves exactly what an EventBridge bus, an SNS topic or an OpenTelemetry logger would be handed.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from regulated_core.outage import (
    ALARM_DETAIL_TYPE, ALARM_SOURCE, OUTAGE_MARKER, SINK_FAILURE_MARKER, AlarmRoute, EventBridgeAlarm, FanOutAlarm,
    OpenTelemetryAlarm, OutageEvent, RecordingOutageAlarm, Severity, SnsAlarm, alarm_envelope, alarm_from_config,
)
from tests.test_authority_outage_alarm import _released
from tests.test_patient_education_e2e import TID, _ctx, _setup

CRITICAL = OutageEvent("t", "signer", "commit_release", "KmsUnavailable", 1, Severity.CRITICAL, "outcome-unknown")
HIGH = OutageEvent("t", "write-once-evidence", "authorize_release", "WormUnavailable", 2, Severity.HIGH)


def test_a_contained_outage_is_high_and_an_outcome_unknown_outage_is_critical(tmp_path: Path) -> None:
    _, alarm, out = _released(tmp_path, fail="evidence-store")
    assert not out.exists()
    assert [(e.severity, e.phase) for e in alarm.events] == [(Severity.HIGH, "contained")]
    _, gate, _ = _setup(tmp_path / "commit")
    recorded = RecordingOutageAlarm()
    gate._outage = recorded
    text = gate._raise_outage(OSError("store"), "commit_release", _ctx(), effect_possible=True)
    assert "unknown" in text
    assert [(e.severity, e.phase, e.tenant_id) for e in recorded.events] == [(Severity.CRITICAL, "outcome-unknown", TID)]


def test_severity_uses_the_opentelemetry_numbers_so_any_backend_can_filter() -> None:
    assert [int(s) for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)] == [9, 13, 17, 21]
    envelope = alarm_envelope(CRITICAL)
    assert envelope["severity"] == "CRITICAL" and envelope["severity_number"] == 21
    assert envelope["marker"] == OUTAGE_MARKER and envelope["phase"] == "outcome-unknown"


def test_the_event_bus_receives_one_entry_its_rules_can_match_by_pattern() -> None:
    calls: list[dict[str, Any]] = []
    def put_events(**kw: Any) -> dict[str, int]:
        calls.append(kw)
        return {"FailedEntryCount": 0}

    EventBridgeAlarm(put_events, event_bus_name="security-alarms").raise_alarm(CRITICAL)
    (entry,) = calls[0]["Entries"]
    assert (entry["Source"], entry["DetailType"], entry["EventBusName"]) == (ALARM_SOURCE, ALARM_DETAIL_TYPE,
                                                                             "security-alarms")
    detail = json.loads(entry["Detail"])
    # an EventBridge rule pattern {"source": [ALARM_SOURCE], "detail": {"severity": ["CRITICAL"]}} matches it
    assert entry["Source"] == ALARM_SOURCE and detail["severity"] == "CRITICAL"


def test_sns_carries_the_levels_as_attributes_for_subscription_filter_policies() -> None:
    calls: list[dict[str, Any]] = []
    SnsAlarm(lambda **kw: calls.append(kw), topic_arn="arn:aws:sns:af-south-1:1:alarms").raise_alarm(HIGH)
    attributes = calls[0]["MessageAttributes"]
    assert attributes["severity"] == {"DataType": "String", "StringValue": "HIGH"}
    assert attributes["component"]["StringValue"] == "write-once-evidence"
    assert json.loads(calls[0]["Message"]) == alarm_envelope(HIGH) and calls[0]["Subject"].startswith("HIGH")


def test_opentelemetry_receives_the_severity_number_text_and_attributes() -> None:
    records: list[tuple[str, int, str, Any]] = []
    OpenTelemetryAlarm(lambda *record: records.append(record)).raise_alarm(CRITICAL)
    body, number, text, attributes = records[0]
    assert (number, text) == (21, "CRITICAL") and attributes["regulated.alarm.component"] == "signer"
    assert json.loads(body)["schema"] == "regulated/authority-alarm/v1"


def test_each_route_receives_only_its_levels_and_a_failed_route_never_stops_the_others(
        caplog: pytest.LogCaptureFixture) -> None:
    critical_only, everything = RecordingOutageAlarm(), RecordingOutageAlarm()

    class Broken:
        def raise_alarm(self, event: OutageEvent) -> None:
            raise ConnectionError("bus unreachable")

    fan = FanOutAlarm([AlarmRoute(Broken(), Severity.LOW, "eventbridge"),
                       AlarmRoute(critical_only, Severity.CRITICAL, "pager"), AlarmRoute(everything)])
    with caplog.at_level(logging.ERROR, logger="regulated_core.outage"):
        fan.raise_alarm(HIGH)
        fan.raise_alarm(CRITICAL)
    assert [e.severity for e in critical_only.events] == [Severity.CRITICAL]
    assert [e.severity for e in everything.events] == [Severity.HIGH, Severity.CRITICAL]
    markers = [json.loads(r.getMessage())["marker"] for r in caplog.records]
    assert markers.count(OUTAGE_MARKER) == 2, "the log channel the metric filter reads is always delivered"
    failures = [json.loads(r.getMessage()) for r in caplog.records if SINK_FAILURE_MARKER in r.getMessage()]
    assert [(f["route"], f["error"]) for f in failures] == [("eventbridge", "ConnectionError")] * 2


def test_a_bus_that_reports_a_failed_entry_is_a_failed_route(caplog: pytest.LogCaptureFixture) -> None:
    from regulated_core.outage import AlarmDeliveryError

    bus = EventBridgeAlarm(lambda **kw: {"FailedEntryCount": 1})
    with pytest.raises(AlarmDeliveryError):
        bus.raise_alarm(CRITICAL)
    log = RecordingOutageAlarm()
    with caplog.at_level(logging.ERROR, logger="regulated_core.outage"):
        FanOutAlarm([AlarmRoute(bus, name="bus")], log=log).raise_alarm(CRITICAL)      # contained, never raised
    assert log.events == (CRITICAL,)
    assert [json.loads(r.getMessage())["error"] for r in caplog.records] == ["AlarmDeliveryError"]


def test_routes_are_composed_from_configuration_and_a_route_without_its_client_is_refused_at_startup() -> None:
    sent: list[str] = []
    alarm = alarm_from_config(
        {"FACTORY_ALARM_ROUTES": "eventbridge:high, sns:critical, otel",
         "FACTORY_ALARM_EVENT_BUS": "org-bus", "FACTORY_ALARM_SNS_TOPIC_ARN": "arn:aws:sns:x:1:t"},
        clients={"put_events": lambda **kw: sent.append("bus:" + kw["Entries"][0]["EventBusName"]),
                 "publish": lambda **kw: sent.append("sns"), "otel_emit": lambda *a: sent.append("otel")})
    alarm.raise_alarm(HIGH)
    assert sent == ["bus:org-bus", "otel"]
    sent.clear()
    alarm.raise_alarm(CRITICAL)
    assert sent == ["bus:org-bus", "sns", "otel"]
    with pytest.raises(ValueError, match="client"):
        alarm_from_config({"FACTORY_ALARM_ROUTES": "sns"}, clients={})
    with pytest.raises(ValueError, match="severity"):
        alarm_from_config({"FACTORY_ALARM_ROUTES": "otel:urgent"}, clients={"otel_emit": lambda *a: None})
    assert isinstance(alarm_from_config({}), FanOutAlarm), "with no routes the log channel still stands"


def test_the_host_runtime_hands_its_composed_alarm_to_every_pack_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The factory the host runtime composes passes its alarm to the gate builder, which passes it to the gate."""
    import inspect
    from types import SimpleNamespace as NS

    from regulated_core import pack_gate
    from regulated_core.host_runtime import RuntimeAuthorities

    assert "outage_alarm" in RuntimeAuthorities.__dataclass_fields__
    assert "outage_alarm" in inspect.signature(pack_gate.RulebookGate.__init__).parameters
    built: dict[str, Any] = {}
    monkeypatch.setattr(pack_gate, "build_pack_gate", lambda pack, **kw: built.update(kw))
    alarm = RecordingOutageAlarm()
    document = NS(vertical="v", policy_id="pid", digest=lambda: "d")
    pack = NS(reference="p#1", rulebook=NS(document=document))
    surface = NS(spec=NS(regulated=NS(pack_version="p#1", policy_ref="v/pid", policy_digest="d")))
    factory = pack_gate.PackGateFactory(trust=None, engine=None, host_verifiers=None,  # type: ignore[arg-type]
                                        verifier_signers={}, credential_verifier=None,  # type: ignore[arg-type]
                                        intended_uses=None, worm=None, outage_alarm=alarm)  # type: ignore[arg-type]
    assert factory(pack, None, surface) is None  # type: ignore[arg-type]
    assert built["outage_alarm"] is alarm
