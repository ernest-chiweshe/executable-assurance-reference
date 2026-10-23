"""The Project OS engine's one error type, in its own module so every Project OS component can raise it."""
from __future__ import annotations


class ProjectEngineError(ValueError):
    """A stage ran before its inputs existed, an id is unknown, or a seam is missing. The message says what
    to do next."""


__all__ = ["ProjectEngineError"]
