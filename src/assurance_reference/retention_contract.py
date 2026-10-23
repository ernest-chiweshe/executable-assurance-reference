"""Construction-only retention contract for reference entry points."""


def require_retention_operations(store):
    """Require an explicit store without calling it or claiming deployed retention."""
    if any(not callable(getattr(store, method, None))
           for method in ("anchor", "fetch", "verify")):
        raise ValueError("reference composition requires explicit retention operations")

