"""Composition root for the Product Spec vertical: wire its VerticalSpec to a ready ProjectEngine."""
from __future__ import annotations

import os
from typing import Any

from factory.projectos import ProjectEngine
from factory.verticals.product_spec.export import export_product_spec_markdown
from factory.verticals.product_spec.spec import (
    build_product_spec_contract,
    make_product_spec_runner,
    product_spec_spec,
)


def build_product_spec_engine(factory: Any, state_dir: str) -> ProjectEngine:
    """The engine for product-spec projects rooted at `<state_dir>/product-spec`. `factory` runs the model
    stages; pass None for a read-only engine (list/view/assemble/export need no model)."""
    runner = make_product_spec_runner(factory)
    return ProjectEngine(product_spec_spec(), runner=runner, contract_builder=build_product_spec_contract,
                         exporter=export_product_spec_markdown, root=os.path.join(state_dir, "product-spec"))
