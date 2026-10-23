"""Reference-only latency of one governed filesystem action against a plain write of the same bytes.

Runs against a freshly provisioned isolated PostgreSQL (``FACTORY_TEST_DB_URL``) and the sealed candidate's own
reference host composition. Each governed iteration is the complete path used by the reference tests: preflight
capability, policy decision with signed evidence, signed target permit, then target-side verification, nonce claim,
budget consumption and the create-only write with its receipt. Every iteration uses a fresh nonce, mission and path.
The plain baseline writes the same bytes to a new file. Results are reported as median and 95th percentile in
milliseconds; they measure this reference on this machine only, not the historical deployed platform.

Usage::

    python bench_governed_latency.py OUTPUT_JSON [ITERATIONS]
"""
import hashlib
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from assurance_reference.host_runtime import compose_reference_host
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_roles import provision_local_roles
from regulated_core import (Action, ActionEffect, Actor, Assertion, IntendedUse, IntendedUseRegistry, PolicyContext,
                            PolicyRegistry)
from regulated_core.target import BoundEffect, FilesystemTargetAdapter, Outcome, effect_destination
from test_reference_host import SyntheticBoundedCoursePolicy

BODY = b"Local reversible draft used for latency measurement.\n"
OPERATION = "course:render-lesson"


def percentile(values, fraction):
    """Nearest-rank percentile of a list of floats."""
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, round(fraction * len(ordered)) - 1))]


def summary(values):
    """Median, 95th percentile, mean and count, in milliseconds."""
    return {"median_ms": round(statistics.median(values), 3), "p95_ms": round(percentile(values, 0.95), 3),
            "mean_ms": round(statistics.fmean(values), 3), "n": len(values)}


def main():
    """Measure governed and plain actions and write the result record."""
    out, iterations = Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 300
    work = Path(tempfile.mkdtemp(prefix="governed-latency-"))
    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    stores, authorities, alerts, qualifications, _, _ = configuration(roles, work / "host", fixture_validity_us=600_000_000)  # Fixture authority lasts the whole run.
    host = compose_reference_host(stores, authorities, alerts=alerts, qualifications=qualifications,
                                  floor_not_used_reason="Latency measurement on an isolated local fixture")
    registry, intended = PolicyRegistry(), IntendedUseRegistry()
    registry.register(SyntheticBoundedCoursePolicy())
    intended.declare(IntendedUse("course", OPERATION, 1))
    base = host.factory.engine
    engine = base.for_policy(registry=registry, preflight=base._preflight.for_uses(intended))
    tenant, digest = "synthetic-host", hashlib.sha256(BODY).hexdigest()
    authorize_ms, commit_ms, governed_ms, plain_ms = [], [], [], []
    for i in range(iterations + 20):  # The first 20 iterations warm connections and caches and are discarded.
        ident = f"bench-{i}"
        target = FilesystemTargetAdapter(path=work / "governed" / f"{ident}.txt", tenant_id=tenant,
                                         authority=engine.targets, uses=host.stores.permits,
                                         operation_name=OPERATION, budget=host.stores.budget)
        target.path.parent.mkdir(parents=True, exist_ok=True)
        start = time.perf_counter()
        capability = engine._preflight.authorize(
            tenant_id=tenant, vertical="course", action_id=OPERATION, risk_tier=1, correlation_id=ident,
            now_us=engine.targets.now_us(), ttl_us=60_000_000, nonce="cap-" + ident)
        authorization = engine.authorize_for_target(
            vertical="course", capability=capability,
            assertion=Assertion("draft-" + ident, tenant, "course:lesson", content_digest=digest),
            action=Action(OPERATION, ActionEffect.REVERSIBLE, destination=effect_destination(
                {}, BoundEffect(digest, target.target, target.current_state(), mission="bench:" + ident))),
            ctx=PolicyContext(tenant, Actor("author", tenant, frozenset()), "draft-" + ident, ident, 0),
            output=BODY, target=target, nonce=ident, permit_ttl_us=60_000_000)
        middle = time.perf_counter()
        result = engine.commit(authorization, BODY, target)
        end = time.perf_counter()
        assert authorization.authorized, authorization.reason
        assert result.outcome is Outcome.COMMITTED, result
        plain = work / "plain" / f"{ident}.txt"
        plain.parent.mkdir(parents=True, exist_ok=True)
        p0 = time.perf_counter()
        with open(plain, "xb") as handle:
            handle.write(BODY)
            handle.flush()
            os.fsync(handle.fileno())
        p1 = time.perf_counter()
        if i >= 20:
            authorize_ms.append((middle - start) * 1000)
            commit_ms.append((end - middle) * 1000)
            governed_ms.append((end - start) * 1000)
            plain_ms.append((p1 - p0) * 1000)
    record = {"schema": "reference/governed-latency/v1", "scope": "reference implementation only (sealed candidate tree), isolated local PostgreSQL; not the historical deployed platform",
              "machine": {"platform": platform.platform(), "python": platform.python_version(), "processor": platform.processor()},
              "path": "preflight capability, policy decision and signed evidence, signed permit; target verification, nonce claim, budget consumption, create-only write and receipt",
              "warmup_discarded": 20,
              "governed_total": summary(governed_ms), "governed_authorize": summary(authorize_ms),
              "governed_commit": summary(commit_ms), "plain_write_fsync": summary(plain_ms),
              "trend": {"authorize_first50_median_ms": round(statistics.median(authorize_ms[:50]), 3),
                        "authorize_last50_median_ms": round(statistics.median(authorize_ms[-50:]), 3)},
              "raw_ms": {"authorize": [round(x, 3) for x in authorize_ms], "commit": [round(x, 3) for x in commit_ms]}}
    out.write_text(json.dumps(record, indent=1), encoding="utf-8")
    print(json.dumps(record, indent=1))


if __name__ == "__main__":
    main()
