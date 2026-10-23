"""The pack schema: the entity types, actions and context a rulebook may talk about (Cedar-shaped).

Cedar validates policies against a schema of entity types (with attributes and parents), actions
(with what they apply to and a context shape) and common types, so a policy cannot reference an
attribute that does not exist or an action that does not apply. A pack ships the same thing for its
domain: the teacher, learner and submission types; the draft and release actions; the context a
decision sees. The rulebook is validated against it at install, and every conformance run.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

SCHEMA_ID = "lumiwright.pack-schema/v1"
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_ACTION = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")
_TYPES = {"string", "long", "bool", "decimal", "set", "record", "timestamp"}
_EFFECTS = {"reversible", "authoritative", "external"}


class SchemaError(ValueError):
    """The schema does not satisfy its own rules; the message lists every defect."""


@dataclass(frozen=True, slots=True)
class Attribute:
    type: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class EntityType:
    name: str
    parents: tuple[str, ...]
    attributes: Mapping[str, Attribute]
    roles: tuple[str, ...] = ()          # for principal types: the roles a member of this type may hold


@dataclass(frozen=True, slots=True)
class ActionSpec:
    id: str
    effect: str
    principal_types: tuple[str, ...]
    resource_types: tuple[str, ...]
    context: Mapping[str, Attribute] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PackSchema:
    namespace: str
    entity_types: Mapping[str, EntityType]
    actions: Mapping[str, ActionSpec]

    def roles(self) -> frozenset[str]:
        return frozenset(role for e in self.entity_types.values() for role in e.roles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_ID, "namespace": self.namespace,
            "entity_types": {
                n: {"parents": list(e.parents), "roles": list(e.roles),
                    "attributes": {a: {"type": t.type, "required": t.required} for a, t in e.attributes.items()}}
                for n, e in sorted(self.entity_types.items())},
            "actions": {
                i: {"effect": a.effect, "applies_to": {"principal_types": list(a.principal_types),
                                                        "resource_types": list(a.resource_types)},
                    "context": {c: {"type": t.type, "required": t.required} for c, t in a.context.items()}}
                for i, a in sorted(self.actions.items())},
        }


def _attributes(raw: Any, where: str, problems: list[str]) -> dict[str, Attribute]:
    out: dict[str, Attribute] = {}
    if raw is None:
        return out
    if not isinstance(raw, dict):
        problems.append(f"{where}: attributes must be an object")
        return out
    for name, spec in raw.items():
        if not _NAME.fullmatch(str(name)):
            problems.append(f"{where}: attribute name {name!r} is not an identifier")
            continue
        if not isinstance(spec, dict) or spec.get("type") not in _TYPES:
            problems.append(f"{where}.{name}: type must be one of {sorted(_TYPES)}")
            continue
        out[str(name)] = Attribute(str(spec["type"]), bool(spec.get("required", True)))
    return out


def validate_schema(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return ["schema must be an object"]
    p: list[str] = []
    if raw.get("schema") != SCHEMA_ID:
        p.append(f"schema must be {SCHEMA_ID}")
    if not isinstance(raw.get("namespace"), str) or not re.fullmatch(r"[a-z][a-z0-9-]*", raw["namespace"]):
        p.append("namespace must be a lowercase identifier (the pack's domain)")
    types = raw.get("entity_types")
    if not isinstance(types, dict) or not types:
        p.append("entity_types must declare at least one type")
        types = {}
    for name, spec in types.items():
        if not _NAME.fullmatch(str(name)) or not isinstance(spec, dict):
            p.append(f"entity type {name!r} must be an identifier with an object body")
            continue
        for parent in spec.get("parents", ()) or ():
            if parent not in types:
                p.append(f"entity type {name}: parent {parent!r} is not declared")
        _attributes(spec.get("attributes"), f"entity type {name}", p)
        for role in spec.get("roles", ()) or ():
            if not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", role):
                p.append(f"entity type {name}: role {role!r} must be a lowercase identifier")
    actions = raw.get("actions")
    if not isinstance(actions, dict) or not actions:
        p.append("actions must declare at least one action")
        actions = {}
    effects: list[str] = []
    for action_id, spec in actions.items():
        if not _ACTION.fullmatch(str(action_id)) or not isinstance(spec, dict):
            p.append(f"action {action_id!r} must be domain:verb with an object body")
            continue
        if spec.get("effect") not in _EFFECTS:
            p.append(f"action {action_id}: effect must be one of {sorted(_EFFECTS)}")
        else:
            effects.append(str(spec["effect"]))
        applies = spec.get("applies_to") or {}
        for side in ("principal_types", "resource_types"):
            names = applies.get(side) if isinstance(applies, dict) else None
            if not isinstance(names, list) or not names:
                p.append(f"action {action_id}: applies_to.{side} must be a non-empty list")
            else:
                for n in names:
                    if n not in types:
                        p.append(f"action {action_id}: {side} names undeclared type {n!r}")
        _attributes(spec.get("context"), f"action {action_id} context", p)
    if effects and "external" not in effects:
        p.append("a pack schema must declare at least one external (release) action; a pack that never releases governs nothing")
    return p


def schema_from_dict(raw: Mapping[str, Any]) -> PackSchema:
    problems = validate_schema(dict(raw))
    if problems:
        raise SchemaError("; ".join(problems))
    types = {
        str(n): EntityType(str(n), tuple(str(x) for x in (s.get("parents") or ())), _attributes(s.get("attributes"), n, []),
                           tuple(str(r) for r in (s.get("roles") or ())))
        for n, s in raw["entity_types"].items()}
    actions = {
        str(i): ActionSpec(str(i), str(s["effect"]), tuple(str(x) for x in s["applies_to"]["principal_types"]),
                           tuple(str(x) for x in s["applies_to"]["resource_types"]), _attributes(s.get("context"), i, []))
        for i, s in raw["actions"].items()}
    return PackSchema(str(raw["namespace"]), types, actions)


def check_request(schema: PackSchema, *, principal_type: str, action_id: str, resource_type: str,
                  context: Mapping[str, Any]) -> list[str]:
    """What Cedar's validator would say about one request: unknown action, a principal or resource the
    action does not apply to, a missing or mistyped context attribute."""
    p: list[str] = []
    action = schema.actions.get(action_id)
    if action is None:
        return [f"unknown action {action_id!r}"]
    if principal_type not in action.principal_types:
        p.append(f"{action_id} does not apply to principal type {principal_type!r}")
    if resource_type not in action.resource_types:
        p.append(f"{action_id} does not apply to resource type {resource_type!r}")
    for name, attr in action.context.items():
        if name not in context:
            if attr.required:
                p.append(f"context attribute {name!r} is required by {action_id}")
            continue
        value = context[name]
        ok = {
            "string": isinstance(value, str), "long": isinstance(value, int) and not isinstance(value, bool),
            "bool": isinstance(value, bool), "decimal": isinstance(value, str) and _is_decimal(value),
            "set": isinstance(value, (list, tuple, set, frozenset)), "record": isinstance(value, dict),
            "timestamp": isinstance(value, str),
        }[attr.type]
        if not ok:
            p.append(f"context attribute {name!r} must be {attr.type}")
    for name in context:
        if name not in action.context:
            p.append(f"context attribute {name!r} is not declared for {action_id}")
    return p


def _is_decimal(value: str) -> bool:
    return re.fullmatch(r"-?\d+(\.\d+)?", value) is not None


__all__ = ["SCHEMA_ID", "ActionSpec", "Attribute", "EntityType", "PackSchema", "SchemaError", "check_request",
           "schema_from_dict", "validate_schema"]
