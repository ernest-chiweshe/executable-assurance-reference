"""CAP-3 Half B drivers: the ONLY package that may touch DNS/socket/HTTP.

Everything above this boundary (contracts, service, store, projection) is
transport-free by the WO §5.1 confinement law; everything inside it receives
injected resolver/clock/connection seams so the free tests open no socket,
spawn no process and issue no DNS query.
"""
from __future__ import annotations

from .resolver import (
    DeadlineBoundResolver,
    ResolutionOutcome,
    ResolverWorker,
    ResolverWorkerFactory,
    os_resolver_worker_factory,
)
from .stdlib import (
    HttpConnection,
    HttpConnectionFactory,
    StdlibPublicFetchDriver,
    WireResponse,
)

__all__ = [
    "DeadlineBoundResolver",
    "HttpConnection",
    "HttpConnectionFactory",
    "ResolutionOutcome",
    "ResolverWorker",
    "ResolverWorkerFactory",
    "StdlibPublicFetchDriver",
    "WireResponse",
    "os_resolver_worker_factory",
]
