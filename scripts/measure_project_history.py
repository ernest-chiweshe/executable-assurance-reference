"""Measure existing release lookup work and serialized state size, without effects.

Synthetic component inputs establish growth; the separately retained intact
product-release trace establishes that these functions are reached operationally.
This is not an authorization test or end-to-end latency benchmark.
"""
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory.projectos.governed_release import (
    GovernedContract, GovernedRelease, PreparedArtifact, ReleaseTarget)
from factory.projectos.pg_store import _encode_state
from factory.projectos.regulated import EmissionContext


class CountedRow(dict):
    reads = 0

    def get(self, key, default=None):
        type(self).reads += 1
        return super().get(key, default)


def main():
    results = []
    contract = GovernedContract({}, PreparedArtifact({"artifact_sha256": sha256(b"fixture").hexdigest()},
                                                   b"fixture"), ReleaseTarget("fixture", "local", "initial"))
    context = EmissionContext(tenant="fixture", actor_id="requester", action_id="missing", nonce="missing")
    for size in (0, 1000, 10000):
        state = {"emissions": [CountedRow(action_id=f"old-{i}", nonce=f"old-{i}", allowed=False)
                               for i in range(size)],
                 "release_outcomes": [{"action_id": f"old-{i}", "state": "not_committed"}
                                      for i in range(size)]}
        # Only the existing pure/read-only component methods are called. No
        # gate, signer, permit, target, guard, or database operation is replaced.
        reader = SimpleNamespace(state=SimpleNamespace(load=lambda project_id: state))
        CountedRow.reads = 0
        answer = GovernedRelease._recorded_attempt(reader, "project", "destination", context)
        assert answer is None
        lookup_reads = CountedRow.reads
        CountedRow.reads = 0
        assert GovernedRelease._as_decided(contract, state, "missing") is contract
        results.append({"prior_emissions": size, "prior_outcomes": size,
                        "recorded_attempt_field_reads": lookup_reads,
                        "as_decided_field_reads": CountedRow.reads,
                        "serialized_state_bytes": len(_encode_state(state).encode("utf-8"))})
    source_paths = ["src/factory/projectos/governed_release.py", "src/factory/projectos/pg_store.py",
                    "src/factory/projectos/regulated.py"]
    Path(sys.argv[1]).write_text(json.dumps({"scope": __doc__, "results": results,
        "source_root": str(ROOT), "source_sha256": {
            path: sha256((ROOT / path).read_bytes()).hexdigest() for path in source_paths},
        "limits": ["Synthetic nonmatching component fixture, not a full lifecycle or latency result.",
                   "Field reads exclude list copying, JSON parsing and PostgreSQL work."]}, indent=2) + "\n",
        encoding="utf-8")


if __name__ == "__main__":
    main()
