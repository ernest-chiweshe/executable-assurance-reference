"""Authority outages raise an independent alarm (Paper A 5.3; claims register row A17).

When the signer, the key store or the write-once evidence store fails, the governance runtime cannot produce a signed
refusal: the component that would sign or retain it is the one that failed. Nothing is released, and the failure must
still be seen. So the outage is reported through a channel that does not depend on any of those components, and the
refusal the caller receives says plainly that it is unsigned.

The default channel is the process's structured log, at CRITICAL, as one JSON line carrying a fixed marker. In the
managed deployment a CloudWatch metric filter on the container log group turns that marker into an alarm
(`deploy/terraform-managed/alarms.tf`), so the alarm is raised by CloudWatch, not by the failed component. Any other
independent channel can be composed through the `OutageAlarm` protocol. An alarm channel that itself fails must never
turn the refusal into anything else: its failure is swallowed after a last-resort write to standard error.

**Levels and delivery (owner direction, 2026-09-27).** Every alarm carries a severity, numbered on the OpenTelemetry
scale so any telemetry backend can filter it: CRITICAL when an effect may have happened and its outcome is unknown,
HIGH when the outage was contained and nothing was released. Every sink receives the same stable envelope
(`alarm_envelope`), so an organisation routes alarms with its own infrastructure: the log line and its CloudWatch (or
equivalent) metric filter, OpenTelemetry, an EventBridge bus (default or custom) whose rules match on
`source`, `detail-type` and `detail.severity`, SNS with a subscription filter policy on the `severity` attribute, or
any other sink behind `OutageAlarm`. `FanOutAlarm` routes one alarm to many sinks, each above its own minimum
severity; a failed sink is reported on the log channel and never stops the others or the refusal. The core imports no
cloud SDK: each adapter takes the host's own client call, so the choice of infrastructure stays the host's.
"""
from __future__ import annotations

import enum
import json
import logging
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

#: The fixed marker the managed metric filter matches. Changing it breaks the alarm, so a test pins it to alarms.tf.
OUTAGE_MARKER = "REGULATED_AUTHORITY_OUTAGE"
#: Written when an alarm sink itself fails, so a broken delivery route is visible without masking the alarm.
SINK_FAILURE_MARKER = "REGULATED_ALARM_SINK_FAILURE"
ALARM_SCHEMA = "regulated/authority-alarm/v1"
ALARM_SOURCE = "lumiwright.regulated-authority"
ALARM_DETAIL_TYPE = "Regulated Authority Outage"


class Severity(enum.IntEnum):
    """Alarm levels, valued on the OpenTelemetry severity-number scale (INFO 9, WARN 13, ERROR 17, FATAL 21)."""

    LOW = 9
    MEDIUM = 13
    HIGH = 17
    CRITICAL = 21

_LOG = logging.getLogger("regulated_core.outage")


@dataclass(frozen=True, slots=True)
class OutageEvent:
    tenant_id: str
    component: str          # "signer", "key-store" or "write-once-evidence"
    operation: str          # what was refused, such as "authorize_release" or "commit_release"
    detail: str             # the failure's class and fixed text, never payload content
    at_us: int | None       # None when the authority clock is unavailable; never invent a timestamp
    severity: Severity = Severity.CRITICAL
    phase: str = "contained"    # "contained": nothing released; "outcome-unknown": an effect may have happened


class OutageAlarm(Protocol):
    def raise_alarm(self, event: OutageEvent) -> None:
        """Report the outage through a channel independent of the failed component. Must not raise."""
        ...


def alarm_envelope(event: OutageEvent) -> dict[str, Any]:
    """The one stable form every sink delivers: identical fields whichever infrastructure carries it."""
    return {"schema": ALARM_SCHEMA, "marker": OUTAGE_MARKER, "source": ALARM_SOURCE, "detail_type": ALARM_DETAIL_TYPE,
            "severity": event.severity.name, "severity_number": int(event.severity), "phase": event.phase,
            "tenant_id": event.tenant_id, "component": event.component, "operation": event.operation,
            "detail": event.detail, "at_us": event.at_us}


class AlarmDeliveryError(RuntimeError):
    """A sink could not confirm delivery. FanOutAlarm reports it on the log channel and carries on."""


def _last_resort(line: str) -> None:
    try:
        sys.stderr.write(line + "\n")
    except Exception:
        pass


class LogOutageAlarm:
    """The default independent channel: one structured CRITICAL log line with the fixed marker and the severity."""

    def raise_alarm(self, event: OutageEvent) -> None:
        line = json.dumps(alarm_envelope(event), sort_keys=True)
        try:
            _LOG.critical(line)
        except Exception:                                   # the alarm path must never mask the refusal
            _last_resort(line)


@dataclass(frozen=True, slots=True)
class AlarmRoute:
    """One delivery route: a sink and the lowest severity it receives."""

    sink: OutageAlarm
    minimum: Severity = Severity.LOW
    name: str = ""


class FanOutAlarm:
    """Deliver one alarm to every route at or above its minimum severity. The log channel is always first, because
    the managed metric filter depends on it; a route that fails is reported on the log channel, never raised."""

    def __init__(self, routes: Sequence[AlarmRoute], *, log: OutageAlarm | None = None) -> None:
        self._log = log if log is not None else LogOutageAlarm()
        self._routes = tuple(routes)

    def raise_alarm(self, event: OutageEvent) -> None:
        try:
            self._log.raise_alarm(event)
        except Exception:           # a failed log channel never suppresses the independent routes (review 3146)
            _last_resort(json.dumps(alarm_envelope(event), sort_keys=True))
        for index, route in enumerate(self._routes):
            if event.severity < route.minimum:
                continue
            try:
                route.sink.raise_alarm(event)
            except Exception as failed:
                line = json.dumps({"marker": SINK_FAILURE_MARKER, "route": route.name or str(index),
                                   "error": type(failed).__name__, "alarm_severity": event.severity.name,
                                   "component": event.component, "operation": event.operation}, sort_keys=True)
                try:
                    _LOG.error(line)
                except Exception:
                    _last_resort(line)


class EventBridgeAlarm:
    """Put the envelope on an EventBridge bus, default or custom. Rules route it by pattern, for example
    {"source": ["lumiwright.regulated-authority"], "detail": {"severity": ["CRITICAL"]}}.

    `put_events` is the host's client call (boto3 `events.put_events`); a reported failed entry raises."""

    def __init__(self, put_events: Callable[..., Any], *, event_bus_name: str = "default",
                 source: str = ALARM_SOURCE) -> None:
        self._put, self._bus, self._source = put_events, event_bus_name, source

    def raise_alarm(self, event: OutageEvent) -> None:
        envelope = alarm_envelope(event)
        response = self._put(Entries=[{"Source": self._source, "DetailType": ALARM_DETAIL_TYPE,
                                       "Detail": json.dumps(envelope, sort_keys=True), "EventBusName": self._bus}])
        if isinstance(response, Mapping) and response.get("FailedEntryCount", 0):
            raise AlarmDeliveryError("the event bus refused the alarm entry")


class SnsAlarm:
    """Publish the envelope to an SNS topic; subscriptions filter on the `severity` and `component` attributes.

    `publish` is the host's client call (boto3 `sns.publish`)."""

    def __init__(self, publish: Callable[..., Any], *, topic_arn: str) -> None:
        if not topic_arn:
            raise ValueError("an SNS alarm sink needs a topic")
        self._publish, self._topic = publish, topic_arn

    def raise_alarm(self, event: OutageEvent) -> None:
        envelope = alarm_envelope(event)
        self._publish(TopicArn=self._topic, Subject=f"{event.severity.name}: regulated authority outage"[:100],
                      Message=json.dumps(envelope, sort_keys=True),
                      MessageAttributes={name: {"DataType": "String", "StringValue": str(envelope[name])}
                                         for name in ("severity", "component", "operation", "phase")})


class OpenTelemetryAlarm:
    """Emit the envelope as an OpenTelemetry log record with its severity number and text.

    `emit(body, severity_number, severity_text, attributes)` is the host's adapter onto its OpenTelemetry logger, so
    any backend that ingests OpenTelemetry (a CloudWatch equivalent or otherwise) receives the same levels."""

    def __init__(self, emit: Callable[[str, int, str, Mapping[str, Any]], None]) -> None:
        self._emit = emit

    def raise_alarm(self, event: OutageEvent) -> None:
        envelope = alarm_envelope(event)
        # Keep unavailable authority time explicit in JSON without forwarding
        # null as a typed telemetry attribute.
        attributes = {f"regulated.alarm.{key}": value for key, value in envelope.items()
                      if value is not None}
        self._emit(json.dumps(envelope, sort_keys=True), int(event.severity), event.severity.name, attributes)


def alarm_from_config(config: Mapping[str, str], *, clients: Mapping[str, Any] | None = None) -> OutageAlarm:
    """Compose the alarm from the host's configuration, never a hard-wired target.

    `FACTORY_ALARM_ROUTES` is a comma-separated list of `<sink>[:<minimum severity>]` with sinks `eventbridge`, `sns`
    and `otel`; `FACTORY_ALARM_EVENT_BUS` (default "default") and `FACTORY_ALARM_SNS_TOPIC_ARN` configure them.
    `clients` carries the host's own calls: `put_events`, `publish`, `otel_emit`. The log channel is always on. A
    route named without its client or topic is refused at composition, not discovered at the first outage."""
    clients = clients or {}
    unusable = sorted(name for name, client in clients.items() if not callable(client))
    if unusable:
        raise ValueError(f"alarm client(s) {unusable} are not callable")
    routes: list[AlarmRoute] = []
    for raw in filter(None, (part.strip() for part in config.get("FACTORY_ALARM_ROUTES", "").split(","))):
        name, _, level = raw.partition(":")
        try:
            minimum = Severity[level.strip().upper()] if level else Severity.LOW
        except KeyError:
            raise ValueError(f"unknown alarm severity {level!r}") from None
        if name == "eventbridge" and "put_events" in clients:
            sink: OutageAlarm = EventBridgeAlarm(clients["put_events"],
                                                 event_bus_name=config.get("FACTORY_ALARM_EVENT_BUS", "default"))
        elif name == "sns" and "publish" in clients:
            sink = SnsAlarm(clients["publish"], topic_arn=config.get("FACTORY_ALARM_SNS_TOPIC_ARN", ""))
        elif name == "otel" and "otel_emit" in clients:
            sink = OpenTelemetryAlarm(clients["otel_emit"])
        else:
            raise ValueError(f"alarm route {name!r} is unknown or its client was not supplied")
        routes.append(AlarmRoute(sink, minimum, name))
    return FanOutAlarm(routes)


class RecordingOutageAlarm:
    """For tests and drills: keeps every alarm raised, in order."""

    def __init__(self) -> None:
        self._events: list[OutageEvent] = []
        self._lock = threading.Lock()

    def raise_alarm(self, event: OutageEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> tuple[OutageEvent, ...]:
        with self._lock:
            return tuple(self._events)


__all__ = ["ALARM_DETAIL_TYPE", "ALARM_SCHEMA", "ALARM_SOURCE", "AlarmDeliveryError", "AlarmRoute",
           "EventBridgeAlarm", "FanOutAlarm", "LogOutageAlarm", "OUTAGE_MARKER", "OpenTelemetryAlarm", "OutageAlarm",
           "OutageEvent", "RecordingOutageAlarm", "SINK_FAILURE_MARKER", "Severity", "SnsAlarm", "alarm_envelope",
           "alarm_from_config"]
