"""The Product Spec vertical: a raw product idea to a structured PRD. An INTERNAL builder tool.

An ARTIFACT-axis client of the Project OS, the "turn my idea into a spec I can build from" shape. The owner's
own tool for spinning up the SaaS products the factory will then build: problem (who hurts and why now) ->
solution (the wedge and value) -> scope (the smallest shippable MVP) -> spec (the PRD that ties it together).
Each stage reads the last, so the spec is grounded in a stated problem instead of features in a vacuum. Built
as a pure declaration (`spec.py`) over the engine; see `docs/extending/building-a-vertical.md`.

Audience INTERNAL: this is a build tool for the operator, not (yet) a customer product. `AXIS` is declared here
and asserted by the validator/conformance suites.
"""
from __future__ import annotations

AXIS = "artifact"
