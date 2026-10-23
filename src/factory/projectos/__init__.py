"""The Project OS: the choreography layer that coordinates project-style verticals and owns no truth.

This package is the generic engine extracted (per `docs/project-os-engine-spec.md`) from the two proven
clients, the book (artifact axis) and the course (knowledge-backed axis). A project vertical is a declaration
(`VerticalSpec`) over this engine, not a bespoke pipeline: it declares its stage graph, its axis, its
contract builder, and its readiness gate, and the engine runs the universal choreography (per-project state,
stage execution, declarative chaining, item iteration, assemble, export).

The boundary is fixed in `docs/project-os-contract.md` and pinned by the conformance tests
(`tests/test_projectos_conformance.py`, T1-T5): the engine imports no renderer, writes no knowledge, sets no
confidence, and records gate verdicts rather than authoring them.
"""
from __future__ import annotations

from factory.projectos.engine import ProjectEngine, ProjectEngineError
from factory.projectos.spec import (
    AXIS_ARTIFACT,
    AXIS_KNOWLEDGE_BACKED,
    KIND_ASSEMBLE,
    KIND_INGEST,
    KIND_MODEL,
    KIND_PROJECT,
    SCOPE_ITEM,
    SCOPE_PROJECT,
    Binding,
    StageOutcome,
    StageRun,
    StageSpec,
    VerticalSpec,
    validate_spec,
)

__all__ = [
    "ProjectEngine", "ProjectEngineError", "VerticalSpec", "StageSpec", "Binding", "StageOutcome", "StageRun",
    "validate_spec",
    "AXIS_ARTIFACT", "AXIS_KNOWLEDGE_BACKED",
    "SCOPE_PROJECT", "SCOPE_ITEM",
    "KIND_MODEL", "KIND_INGEST", "KIND_PROJECT", "KIND_ASSEMBLE",
]
