"""The Product Spec workbench view, from engine state (a pure read: the four-stage pipeline + the verdict)."""
from __future__ import annotations

from typing import Any

from factory.projectos import ProjectEngine

_STAGES = (("problem", "Frame the problem"), ("solution", "Define the solution"),
           ("scope", "Scope the MVP"), ("spec", "Write the PRD"))


def product_spec_view(engine: ProjectEngine, spec_id: str) -> dict[str, Any]:
    state = engine.get(spec_id)
    stages = state.get("stages", {})
    assembled = state.get("assembled")
    return {
        "state": state,
        "title": state.get("title", spec_id),
        "topic": state.get("title", ""),
        "pipeline": [
            {"stage": sid, "title": title,
             "ran": sid in stages, "accepted": bool(stages.get(sid, {}).get("accepted")),
             "output": str(stages.get(sid, {}).get("output", "")),
             "reason": stages.get(sid, {}).get("reason"),
             # Cost and the harness that ran, surfaced so the workbench is cost-honest per stage.
             "cost_usd": float(stages.get(sid, {}).get("cost_usd", 0.0)),
             "harness": stages.get(sid, {}).get("harness")}
            for sid, title in _STAGES
        ],
        "approved": bool(state.get("approved")),
        "ready": {"ready": bool(assembled["accepted"]), "reason": assembled.get("reason", "")}
                 if isinstance(assembled, dict) else None,
    }
