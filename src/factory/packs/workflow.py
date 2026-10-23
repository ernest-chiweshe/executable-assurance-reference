"""The workflow profile: the domain journey as typed stages bound to the schema's actions.

CDS Hooks declares a hook by name with its context and prefetch, and returns typed cards; the
research carries that into "workflow profiles declare trigger, inputs, data needs, response types
and protocol version" and "no implicit host behavior". A stage here names its trigger, the schema
action it performs (or none for a pure data stage), what it consumes and what it produces. Every
release (external) action the schema declares must be reachable from a stage, otherwise the pack
governs an action no journey performs.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .schema import PackSchema

_STAGE_ID = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


class WorkflowError(ValueError):
    """The workflow does not bind to the schema; the message lists every defect."""


@dataclass(frozen=True, slots=True)
class Stage:
    id: str
    trigger: str
    action: str | None
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    effect: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "trigger": self.trigger, "action": self.action, "inputs": list(self.inputs),
                "outputs": list(self.outputs), "effect": self.effect}


def validate_workflow(raw: Any, schema: PackSchema) -> list[str]:
    if not isinstance(raw, dict):
        return ["workflow must be an object with stages"]
    stages = raw.get("stages")
    if not isinstance(stages, list) or not stages:
        return ["workflow.stages must be a non-empty list"]
    p: list[str] = []
    seen: set[str] = set()
    performed: set[str] = set()
    for entry in stages:
        if not isinstance(entry, dict) or not _STAGE_ID.fullmatch(str(entry.get("id", ""))):
            p.append(f"stage {entry!r}: id must be a lowercase identifier")
            continue
        sid = str(entry["id"])
        if sid in seen:
            p.append(f"stage {sid}: declared twice")
        seen.add(sid)
        if not str(entry.get("trigger", "")).strip():
            p.append(f"stage {sid}: trigger is required (an event name or stage:<id>)")
        action = entry.get("action")
        if action is not None:
            spec = schema.actions.get(str(action))
            if spec is None:
                p.append(f"stage {sid}: action {action!r} is not declared by the schema")
            else:
                performed.add(str(action))
                effect = entry.get("effect")
                if effect is not None and effect != spec.effect:
                    p.append(f"stage {sid}: effect {effect!r} contradicts the schema's {spec.effect!r} for {action}")
        for key in ("inputs", "outputs"):
            value = entry.get(key, [])
            if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
                p.append(f"stage {sid}: {key} must be a list of names")
    for action_id, spec in schema.actions.items():
        if spec.effect == "external" and action_id not in performed:
            p.append(f"release action {action_id!r} is performed by no stage; a governed action no journey reaches is dead policy")
    return p


def workflow_from_dict(raw: Any, schema: PackSchema) -> tuple[Stage, ...]:
    problems = validate_workflow(raw, schema)
    if problems:
        raise WorkflowError("; ".join(problems))
    return tuple(Stage(str(e["id"]), str(e["trigger"]), None if e.get("action") is None else str(e["action"]),
                       tuple(str(v) for v in e.get("inputs", [])), tuple(str(v) for v in e.get("outputs", [])),
                       None if e.get("effect") is None else str(e["effect"]))
                 for e in raw["stages"])


def workflow_digest(raw: Any) -> str:
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = ["Stage", "WorkflowError", "validate_workflow", "workflow_digest", "workflow_from_dict"]
