"""The declarative spec a project vertical provides to the Project OS engine.

A vertical is DATA plus a few small handlers, not a pipeline. It declares its stage graph (a `StageSpec`
per stage), its axis, how to enumerate item-scoped work (chapters/lessons), and the named functions for the
few genuinely-computed inputs. The engine reads this and runs the universal choreography; nothing here knows
how to run a model, gate a candidate, or render an artifact, those are seams the engine is handed.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

# --- axes (where the truth comes from) -----------------------------------------
AXIS_ARTIFACT = "artifact"               # the author is the source of truth; the gate checks form
AXIS_KNOWLEDGE_BACKED = "knowledge-backed"  # the content teaches verified facts; the gate checks truth

# --- stage scope ---------------------------------------------------------------
SCOPE_PROJECT = "project"   # runs once for the project (positioning, outline, assemble)
SCOPE_ITEM = "item"         # runs once per item (a chapter, a lesson)

# --- stage kind (which runner executes it) -------------------------------------
KIND_MODEL = "model"        # a Factory.run recipe (artifact axis)
KIND_INGEST = "ingest"      # a gated Knowledge OS ingest (knowledge-backed)
KIND_PROJECT = "project"    # a projection from verified knowledge (knowledge-backed)
KIND_ASSEMBLE = "assemble"  # build the contract artifact and run the readiness gate


@dataclass(frozen=True, slots=True)
class Binding:
    """Resolve one stage param from a source. The source grammar (see the engine):
      - "field:<name>"            a top-level project-state field (topic, audience, title)
      - "stage:<id>"              a prior stage's stored output (string)
      - "stage:<id>.<json_field>" a field within a prior stage's JSON output
      - "item:<name>"             a field of the current item (a chapter's beats, a lesson's slice)
      - "fn:<name>"               a registered computed-input function (the escape hatch for the rare
                                  genuinely-computed inputs, e.g. a cross-chapter summary)."""

    param: str
    source: str


@dataclass(frozen=True, slots=True)
class StageSpec:
    """One stage in a vertical's graph: its id, a human title, whether it runs once (`project`) or per item
    (`item`), which runner executes it (`kind`), and the declarative bindings that fill its inputs."""

    id: str
    title: str
    scope: str = SCOPE_PROJECT
    kind: str = KIND_MODEL
    inputs: tuple[Binding, ...] = ()


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """What a runner returns: the produced output and the GATE's verdict. The engine RECORDS this; it authors
    none of it (Project OS T3). `accepted`/`reason`/`run_id` are copied straight from the gate's verdict.

    `extra` is an optional bag of vertical-specific fields the runner attaches to the stored record (the
    book's `cost_usd` and `shippable`, say). The engine writes them through verbatim without understanding
    them, so a vertical's surface can read what it needs without the engine growing vertical-aware fields."""

    output: str
    accepted: bool
    reason: str = ""
    run_id: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StageRun:
    """Everything a runner needs to execute one stage, in one object so the signature stays stable as the
    engine grows. `params` are the resolved+overridden inputs; `item` is the current chapter/lesson (None for
    a project-scoped stage); `tenant` is the caller; `options` carries per-run knobs the engine itself does
    not interpret (a model `tier`, an override flag), handed straight to the runner."""

    stage: StageSpec
    params: dict[str, str]
    item: dict[str, Any] | None
    tenant: Any
    options: Mapping[str, Any] = field(default_factory=dict)


# A runner executes one stage: given a `StageRun` (the stage, its resolved params, the current item, the
# tenant, and per-run options), it runs the work (a model call, a gated ingest, a projection, or the readiness
# gate) and returns the outcome. Injected, so the engine never gates or runs a provider itself.
Runner = Callable[["StageRun"], StageOutcome]


def _no_items(_state: dict[str, Any]) -> list[dict[str, Any]]:
    """Default item enumerator: a vertical with no item-scoped stages has no items."""
    return []


@dataclass(frozen=True, slots=True)
class RegulatedBlock:
    """The OPTIONAL governance declaration a regulated vertical adds (health, finance, ...).

    Regulated is not an axis and not a new OS; it is a cross-cutting authority plane. A vertical stays
    an additive Project OS declaration; a REGULATED vertical simply attaches this block. It is PURE DATA:
    it NAMES the consequence-policy pack (resolved at the composition root against `regulated_core`) and
    the intended-use contract, and holds no `regulated_core` object — so Project OS keeps its one-way
    independence from the authority plane. `regulated=None` (the default) => an ordinary vertical, whose
    behaviour is entirely unchanged."""

    policy_ref: str                                  # names the consequence-policy pack in regulated_core
    intended_use: str
    prohibited_uses: tuple[str, ...] = ()
    risk_tiers: Mapping[str, int] = field(default_factory=dict)
    required_verifiers: tuple[str, ...] = ()
    approver_roles: tuple[str, ...] = ()
    emission_policy: str = ""
    evidence_pack_schema: str = ""
    policy_digest: str = ""      # the signed PolicyDocument the pack was conformance-tested with (registrar checks it)
    pack_version: str = ""       # the pack's own version, pinned onto every governed-release receipt


@dataclass(frozen=True)
class VerticalSpec:
    """A project vertical, declared. Identity + axis + the stage graph + how to enumerate items + the
    computed-input functions. The contract builder, readiness gate, and exporters are handed to the engine
    as seams (see `ProjectEngine`), so they stay the vertical's own code while the engine stays generic."""

    name: str
    axis: str
    state_dir: str          # subdir under .factory, e.g. "books" / "courses"
    id_field: str           # the project's id key in state, e.g. "book_id" / "course_id"
    stages: tuple[StageSpec, ...]
    # Items (chapters/lessons) for item-scoped stages, derived from state (e.g. parsed from the outline).
    # Each returned dict MUST carry an "id".
    item_enumerator: Callable[[dict[str, Any]], list[dict[str, Any]]] = _no_items
    # The escape hatch: named functions for the few inputs that are genuinely computed (a summary, a profile).
    computed_inputs: Mapping[str, Callable[[dict[str, Any], "dict[str, Any] | None"], str]] = field(default_factory=dict)
    # Optional commercial/domain vocabulary contributed by an installed pack. Empty keeps
    # legacy in-tree verticals unchanged; external packs no longer require a core allowlist edit.
    domain: str = ""
    # OPTIONAL: the regulated governance block. None => ordinary vertical (unchanged). Set => the engine
    # routes emission through the injected regulated gate (permission to emit lives in regulated_core).
    regulated: "RegulatedBlock | None" = None
    # Explicit full-source replacement is opt-in. The caller must provide every
    # field together so mutually exclusive source representations cannot linger.
    source_fields: tuple[str, ...] = ()

    def stage(self, stage_id: str) -> StageSpec:
        for stage in self.stages:
            if stage.id == stage_id:
                return stage
        raise KeyError(stage_id)


# The binding source kinds the engine's `_resolve_inputs` understands. Kept here next to `Binding` so the
# validator and the resolver agree on the grammar by construction.
_BINDING_KINDS = ("field", "stage", "item", "fn")


def validate_spec(spec: VerticalSpec) -> list[str]:
    """Check a `VerticalSpec` for declaration errors the engine would only hit at run time, and return a list
    of problems (empty means valid). This is the conformance lift made structural: a malformed declaration (a
    `stage:` binding pointing at a non-existent stage, an `fn:` binding with no registered function, an
    item-scoped stage with no way to enumerate items, an unknown axis/kind/scope) is caught once, here, so
    every current AND future vertical is held to the same bar before it ever runs. Pure and side-effect free,
    so it drives a parametrized smoke test over the whole vertical registry.

    It validates the SHAPE of the declaration, not the runtime seams (the runner, contract builder, exporter
    are injected at the engine and judged by the vertical's own tests); a clean result here means the engine
    can resolve every binding and iterate every item the declaration promises."""
    problems: list[str] = []
    if spec.axis not in (AXIS_ARTIFACT, AXIS_KNOWLEDGE_BACKED):
        problems.append(f"unknown axis {spec.axis!r} (expected {AXIS_ARTIFACT!r} or {AXIS_KNOWLEDGE_BACKED!r})")
    for label, value in (("name", spec.name), ("state_dir", spec.state_dir), ("id_field", spec.id_field)):
        if not value:
            problems.append(f"{label} is empty")
    if not spec.stages:
        problems.append("a vertical declares no stages")
    if spec.domain and not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", spec.domain):
        problems.append(f"domain {spec.domain!r} is not a lowercase domain-pack identifier")

    all_ids = {s.id for s in spec.stages}
    valid_kinds = {KIND_MODEL, KIND_INGEST, KIND_PROJECT, KIND_ASSEMBLE}
    valid_scopes = {SCOPE_PROJECT, SCOPE_ITEM}
    seen: set[str] = set()
    has_item_stage = False
    for stage in spec.stages:
        if stage.id in seen:
            problems.append(f"duplicate stage id {stage.id!r}")
        seen.add(stage.id)
        if stage.kind not in valid_kinds:
            problems.append(f"stage {stage.id!r}: unknown kind {stage.kind!r}")
        if stage.scope not in valid_scopes:
            problems.append(f"stage {stage.id!r}: unknown scope {stage.scope!r}")
        if stage.scope == SCOPE_ITEM:
            has_item_stage = True
        for binding in stage.inputs:
            kind, sep, arg = binding.source.partition(":")
            where = f"stage {stage.id!r} param {binding.param!r}"
            if not sep or kind not in _BINDING_KINDS:
                problems.append(f"{where}: malformed binding {binding.source!r} "
                                f"(expected one of {'/'.join(_BINDING_KINDS)}:<target>)")
                continue
            if not arg:
                problems.append(f"{where}: binding {binding.source!r} names no target")
            elif kind == "stage" and arg.partition(".")[0] not in all_ids:
                problems.append(f"{where}: stage: binding references unknown stage {arg.partition('.')[0]!r}")
            elif kind == "fn" and arg not in spec.computed_inputs:
                problems.append(f"{where}: fn: binding references {arg!r}, not in computed_inputs")

    # An item-scoped stage needs a real enumerator; the default no-op would silently yield zero items.
    if has_item_stage and spec.item_enumerator is _no_items:
        problems.append("declares item-scoped stages but no item_enumerator (items would always be empty)")

    # A regulated vertical must declare a resolvable policy, an intended use, at least one verifier, and a
    # human approver role — the minimum for the authority plane to gate its emission.
    if spec.regulated is not None:
        r = spec.regulated
        if not r.policy_ref:
            problems.append("regulated block: policy_ref is empty (names the consequence-policy pack)")
        if not r.intended_use:
            problems.append("regulated block: intended_use is empty")
        if not r.required_verifiers:
            problems.append("regulated block: no required_verifiers")
        if not r.approver_roles:
            problems.append("regulated block: no approver_roles (a regulated vertical needs a human approver)")
    return problems
