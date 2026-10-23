"""Product Spec export: write the PRD (product-spec/1.0) to a single Markdown file, a section per part. Pure."""
from __future__ import annotations

import pathlib
from typing import Any

# The sections, in build order, with a human heading for each.
_SECTIONS = (("spec", "Product spec"), ("problem", "Problem"), ("solution", "Solution"), ("scope", "MVP scope"))


def render_product_spec_markdown(contract: dict[str, Any]) -> str:
    title = str(contract.get("title", "")).strip() or str(contract.get("spec_id", "Product Spec"))
    lines = [f"# {title}", "", "_A product spec: the PRD plus the problem, solution, and MVP scope it rests on._"]
    for key, heading in _SECTIONS:
        body = str(contract.get(key, "")).strip()
        if body:
            lines += ["", f"## {heading}", "", body]
    lines.append("")
    return "\n".join(lines)


def export_product_spec_markdown(contract: dict[str, Any], out_path: str) -> str:
    path = pathlib.Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_product_spec_markdown(contract), encoding="utf-8")
    return str(path)
