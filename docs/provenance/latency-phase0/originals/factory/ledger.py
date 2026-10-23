"""The run and artifact ledger: the factory's durable memory.

Two stores, both tenant-scoped:

  - An ARTIFACT store, content-addressed: an artifact's address IS the SHA-256 of
    its bytes. Identical content is stored once (dedup); content cannot change
    without changing its address (immutable and tamper-evident).

  - A RUN ledger: one immutable record per run (who, which product, which harness,
    what it cost, the gate verdict and reason, and the addresses of what it
    produced). This powers replay, audit, per-tenant accounting (read by the cost
    governor), and `factory runs` / `factory show`.

This is V1's only durable memory. If a verdict is not in it, "what did we ship
yesterday?" has no answer, so the write is atomic and the read tolerates a single
corrupt file rather than failing the whole query (a truncated file must not
silently break the budget total it feeds).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Iterable
from typing import Protocol

from factory.tenant import TenantContext

_log = logging.getLogger("factory.ledger")


class IntegrityError(RuntimeError):
    """A stored artifact's bytes no longer match its content address."""


def content_address(data: bytes) -> str:
    """The canonical address of some bytes: their SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write then rename, so a crash mid-write never leaves a half-file at `path`."""
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_bytes(data)
    os.replace(tmp, path)  # atomic on the same filesystem


class ArtifactStore(Protocol):
    """The store seam for artifact bytes, addressed by content. The disk store is
    the V1 backend; object storage or an encrypting store swaps in with no caller
    change."""
    def put(self, tenant: TenantContext, data: bytes) -> str: ...
    def get(self, tenant: TenantContext, address: str) -> bytes: ...


class FileArtifactStore:
    """Content-addressed store on local disk, namespaced per tenant."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _objects_dir(self, tenant: TenantContext) -> Path:
        directory = self._root / tenant.tenant_id / "objects"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def put(self, tenant: TenantContext, data: bytes) -> str:
        address = content_address(data)
        path = self._objects_dir(tenant) / address
        if not path.exists():  # dedup: identical content is written exactly once
            _atomic_write(path, data)
        return address

    def get(self, tenant: TenantContext, address: str) -> bytes:
        data = (self._objects_dir(tenant) / address).read_bytes()
        if content_address(data) != address:
            raise IntegrityError(f"artifact {address} failed integrity check")
        return data


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One immutable run, as the ledger remembers it."""

    run_id: str
    tenant_id: str
    profile_name: str
    task: str
    harness_name: str
    cost_usd: float
    succeeded: bool
    accepted: bool  # the gate's verdict
    artifacts: tuple[str, ...]  # content addresses
    created_at: float
    gate_reason: str = ""
    output_address: str = ""  # content address of the run's output text, if stored
    # --- provenance / "what bar accepted this?" fields (default-bearing, so records written before they
    # existed still load: RunRecord(**old_dict) simply takes the defaults). ---
    profile_version: str = "1"
    """The version of the product profile (or recipe) that judged this run."""
    gate_fingerprint: str = ""
    """A stable hash of the gate's composition (which checks were wired), so an audit can tell whether two
    runs were judged by the same bar and detect when the gate changed."""
    policy_hash: str = ""
    """A hash of the product's Rego policy file at run time, or empty when the product had no policy."""
    harness_model: str = ""
    """The exact model id of the harness that produced the output (e.g. claude-opus-4-8)."""
    cost_observed: bool = True
    """False when the harness could not observe this run's cost (raw ``cost_observed: False``, ledger 4144): then
    ``cost_usd`` is a 0.0 placeholder, never a known figure, and ``run_bound_usd`` is what the run may have spent."""
    run_bound_usd: float | None = None
    """The ceiling this run was held to, recorded for an unobserved run so the account cap counts it as occupancy
    (never as spend) until its cost is known."""

    @classmethod
    def new(
        cls,
        tenant: TenantContext,
        profile_name: str,
        task: str,
        harness_name: str,
        cost_usd: float,
        succeeded: bool,
        accepted: bool,
        artifacts: tuple[str, ...],
        *,
        run_id: str | None = None,
        gate_reason: str = "",
        output_address: str = "",
        profile_version: str = "1",
        gate_fingerprint: str = "",
        policy_hash: str = "",
        harness_model: str = "",
        cost_observed: bool = True,
        run_bound_usd: float | None = None,
    ) -> "RunRecord":
        # A new unobserved run must carry a valid bound (source review 4164): a bool, non-number, negative or non-finite
        # bound would let the account cap be checked against a figure that means nothing.
        if not isinstance(cost_observed, bool):
            raise ValueError("cost_observed must be a boolean")
        if run_bound_usd is not None and not valid_bound(run_bound_usd):
            raise ValueError(f"run_bound_usd must be a finite non-negative amount, got {run_bound_usd!r}")
        return cls(
            run_id=run_id or uuid.uuid4().hex,
            tenant_id=tenant.tenant_id,
            profile_name=profile_name,
            task=task,
            harness_name=harness_name,
            cost_usd=cost_usd,
            succeeded=succeeded,
            accepted=accepted,
            artifacts=artifacts,
            created_at=time.time(),
            gate_reason=gate_reason,
            output_address=output_address,
            profile_version=profile_version,
            gate_fingerprint=gate_fingerprint,
            policy_hash=policy_hash,
            harness_model=harness_model,
            cost_observed=cost_observed,
            run_bound_usd=run_bound_usd,
        )


def valid_bound(value: object) -> bool:
    """A usable amount: a real number (never a bool), finite and not negative."""
    return (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            and value >= 0)


def occupied_cost(runs: Iterable[RunRecord]) -> float | None:
    """Observed spend plus each unobserved run's recorded bound: what the account cap must count. None (the caller
    refuses further spending rather than guessing) when ANY run's figure is invalid, checked per record before any
    arithmetic: an observed cost or an unobserved bound that is missing, negative, NaN, infinite or not a number. A
    negative row can therefore never cancel positive ones (ledger 4164/4180). History is read, never rewritten."""
    total = 0.0
    for run in runs:
        if run.cost_observed:
            if not valid_bound(run.cost_usd):
                return None
            total += float(run.cost_usd)
        elif not valid_bound(run.run_bound_usd):
            return None
        else:
            total += float(run.run_bound_usd)  # type: ignore[arg-type]
    return total if math.isfinite(total) else None


def _record_json(run: RunRecord) -> dict[str, object]:
    """The record as written: an observed run omits the two unobserved-cost keys, so its JSON is unchanged."""
    data = asdict(run)
    if run.cost_observed:
        data.pop("cost_observed")
        data.pop("run_bound_usd")
    return data


# -- governor reservations (ledger 4164/4169) ------------------------------------------------------------------------

#: What ``reserve_occupancy`` answers. RESERVED: admitted and durably occupying the cap. REPLAYED: this run_id is
#: already reserved or recorded, so it is never dispatched again. CONFLICT: the run_id is reserved for other facts.
#: OVER: occupancy plus this bound exceeds the cap. UNKNOWN: occupancy cannot be read (a missing or invalid bound).
RESERVED, REPLAYED, CONFLICT, OVER, UNKNOWN = "reserved", "replayed", "conflict", "over", "unknown"


def reservation_identity(tenant_id: str, run_id: str, profile_name: str, bound_usd: float) -> str:
    """What a replay of the same reservation must match exactly."""
    return hashlib.sha256(json.dumps([tenant_id, run_id, profile_name, float(bound_usd)],
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def reservation_matches(profile_name: object, bound_usd: object, run: RunRecord) -> bool:
    """Whether a recorded run is the one a reservation admitted: the same profile, and a recorded bound (when the
    cost was unobserved) no wider than the bound reserved. Adjudicating a reservation whose run never matched is
    deliberately unavailable until it is bound to an authenticated operator principal (ledger 4170)."""
    if profile_name != run.profile_name or not valid_bound(bound_usd):
        return False
    return run.run_bound_usd is None or float(run.run_bound_usd) <= float(bound_usd)  # type: ignore[arg-type]


@contextmanager
def _exclusive(lock_path: Path) -> Iterator[None]:
    """An OS-level exclusive lock on one file: held across PROCESSES, not just threads (the same pattern as
    harness_credentials). Released when the block exits, including on error."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as handle:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:          # LK_LOCK gives up after ~10 s; keep waiting, never proceed unlocked
                    continue
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class LedgerLike(Protocol):
    """The run-ledger seam: append-only, tenant-scoped run records. The file `Ledger` below is the default
    backend; `PgLedger` (factory/pg.py) is the Postgres backend for platform mode (durable, queryable,
    multi-node). The core, cost governor, billing, and metrics depend on THIS protocol, never on the file
    class, so the backend swaps by composition with no caller change. `get` raises (FileNotFoundError or
    ValueError) when the run is absent, which the replay path catches."""
    def record(self, run: RunRecord) -> None: ...
    def get(self, tenant_id: str, run_id: str) -> RunRecord: ...
    def for_tenant(self, tenant_id: str) -> list[RunRecord]: ...
    def tail(self, tenant_id: str, n: int = 20) -> list[RunRecord]: ...
    def total_cost(self, tenant_id: str) -> float: ...
    def tenants(self) -> list[str]: ...


class Ledger:
    """Append-only run records on disk: one JSON file per run, per tenant. The default LedgerLike backend."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _runs_dir(self, tenant_id: str) -> Path:
        directory = self._root / tenant_id / "runs"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def record(self, run: RunRecord) -> None:
        # Under the tenant's governor lock, so a reservation's close and the occupancy read never interleave.
        with _exclusive(self._governor_lock(run.tenant_id)):
            path = self._runs_dir(run.tenant_id) / f"{run.run_id}.json"
            # First write wins, exactly as PostgreSQL's ON CONFLICT DO NOTHING: a later record under the same run id
            # never rewrites the observed spend, the outcome or the reservation evidence, and never closes a
            # reservation (ledger 4164/4173). A correction is a NEW record.
            if path.exists():
                return
            _atomic_write(path, json.dumps(_record_json(run), indent=2).encode("utf-8"))
            self._close_recorded(run)

    # -- governor reservations: durable, cross-process (ledger 4164/4169) ----------------------------------------

    def _governor_lock(self, tenant_id: str) -> Path:
        return self._root / tenant_id / ".governor.lock"

    def _reservations_dir(self, tenant_id: str) -> Path:
        directory = self._root / tenant_id / "reservations"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _reservation(self, tenant_id: str, run_id: str) -> dict[str, object] | None:
        path = self._reservations_dir(tenant_id) / f"{run_id}.json"
        return None if not path.exists() else dict(json.loads(path.read_text(encoding="utf-8")))

    def _close_recorded(self, run: RunRecord) -> bool:
        """Close the run's reservation only when the recorded run MATCHES it: the same profile, and a recorded bound
        no wider than the one reserved. A mismatch leaves it open and occupying (ledger 4170)."""
        record = self._reservation(run.tenant_id, run.run_id)
        if record is None or not reservation_matches(record.get("profile_name"), record.get("bound_usd"), run):
            return False
        return self._close_reservation(run.tenant_id, run.run_id, "recorded")

    def _close_reservation(self, tenant_id: str, run_id: str, resolution: str, **facts: str) -> bool:
        record = self._reservation(tenant_id, run_id)
        if record is None or record.get("state") != "open":
            return False
        record.update(state="closed", resolution=resolution, closed_at=time.time(), **facts)
        _atomic_write(self._reservations_dir(tenant_id) / f"{run_id}.json",
                      json.dumps(record, indent=2, sort_keys=True).encode("utf-8"))
        return True

    def reserve_occupancy(self, tenant_id: str, *, run_id: str, profile_name: str, bound_usd: float,
                          cap_usd: float) -> tuple[str, float | None]:
        """Reserve this run's FULL bound against the cap, or say why not, as one decision under the tenant's
        cross-process lock. Every open reservation occupies: one closes only when its MATCHING run is recorded."""
        if not valid_bound(bound_usd) or not valid_bound(cap_usd):
            return UNKNOWN, None
        identity = reservation_identity(tenant_id, run_id, profile_name, bound_usd)
        with _exclusive(self._governor_lock(tenant_id)):
            prior = self._reservation(tenant_id, run_id)
            if prior is not None:
                return (REPLAYED if prior.get("identity_digest") == identity else CONFLICT), None
            runs = self.for_tenant(tenant_id)
            recorded = {run.run_id for run in runs}
            if run_id in recorded:
                return REPLAYED, None
            occupied = occupied_cost(runs)
            if occupied is None:
                return UNKNOWN, None
            held = 0.0
            for path in sorted(self._reservations_dir(tenant_id).glob("*.json")):
                other = dict(json.loads(path.read_text(encoding="utf-8")))
                if other.get("state") != "open":
                    continue
                if not valid_bound(other.get("bound_usd")):
                    return UNKNOWN, None
                held += float(other["bound_usd"])
            figure = occupied + held
            if not math.isfinite(figure):
                return UNKNOWN, None
            if figure + bound_usd > cap_usd:
                return OVER, figure
            _atomic_write(self._reservations_dir(tenant_id) / f"{run_id}.json", json.dumps({
                "tenant_id": tenant_id, "run_id": run_id, "profile_name": profile_name, "bound_usd": bound_usd,
                "identity_digest": identity, "state": "open", "resolution": "", "created_at": time.time(),
                "closed_at": None}, indent=2, sort_keys=True).encode("utf-8"))
            return RESERVED, figure

    def release_reservation(self, tenant_id: str, run_id: str, *, reason: str) -> bool:
        """Close an open reservation on in-process evidence that no provider was entered (core's pre-execute
        refusals). True when one was closed."""
        with _exclusive(self._governor_lock(tenant_id)):
            return self._close_reservation(tenant_id, run_id, f"released: {reason}")

    def open_reservations(self, tenant_id: str) -> list[dict[str, object]]:
        with _exclusive(self._governor_lock(tenant_id)):
            rows = [dict(json.loads(path.read_text(encoding="utf-8")))
                    for path in sorted(self._reservations_dir(tenant_id).glob("*.json"))]
        return [row for row in rows if row.get("state") == "open"]

    def get(self, tenant_id: str, run_id: str) -> RunRecord:
        data = json.loads((self._runs_dir(tenant_id) / f"{run_id}.json").read_text(encoding="utf-8"))
        data["artifacts"] = tuple(data["artifacts"])  # JSON lists -> tuple
        return RunRecord(**data)

    def for_tenant(self, tenant_id: str) -> list[RunRecord]:
        records: list[RunRecord] = []
        for path in sorted(self._runs_dir(tenant_id).glob("*.json")):
            try:
                records.append(self.get(tenant_id, path.stem))
            except (json.JSONDecodeError, KeyError, TypeError, OSError) as exc:
                # One corrupt record must not break accounting or audit for all the
                # others. Skip it loudly so it surfaces in the logs.
                _log.warning("skipping unreadable run record %s: %s", path.name, exc)
        return sorted(records, key=lambda r: r.created_at)

    def tail(self, tenant_id: str, n: int = 20) -> list[RunRecord]:
        """The most recent `n` runs, newest last. Powers `factory runs`."""
        return self.for_tenant(tenant_id)[-n:]

    def total_cost(self, tenant_id: str) -> float:
        """Per-tenant accounting: every dollar this tenant has spent. Read by the
        cost governor to enforce the account cap."""
        return sum(r.cost_usd for r in self.for_tenant(tenant_id))

    def occupied_cost(self, tenant_id: str) -> float | None:
        """The account cap's figure: observed spend plus unobserved runs at their bound (``occupied_cost``)."""
        return occupied_cost(self.for_tenant(tenant_id))

    def tenants(self) -> list[str]:
        """Every tenant that has run records, for operator-wide accounting (the billing statement).
        A tenant exists here once it has a runs directory."""
        if not self._root.exists():
            return []
        return sorted(p.name for p in self._root.iterdir() if (p / "runs").is_dir())

    def delete(self, tenant_id: str, run_id: str) -> bool:
        """Operator housekeeping for the LOCAL file backend: remove one run's record; True if it existed.

        Deliberately NOT on the LedgerLike protocol: the core never deletes history (the ledger is the
        audit trail, and total_cost feeds the account caps), so no pipeline code can reach this. Only an
        operator surface (the local Hub's delete button) calls it, duck-typed, and a platform backend
        refuses by simply not having the method. Removes the RECORD only; content-addressed artifacts
        stay, because an address may be shared by other runs (dedup)."""
        path = self._runs_dir(tenant_id) / f"{run_id}.json"
        if not path.is_file():
            return False
        path.unlink()
        return True
