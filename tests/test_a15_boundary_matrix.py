"""A15 static accounting: every receiving target in source is in the reviewed matrix, and cited evidence exists."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MATRIX = json.loads((ROOT / "docs/provenance/a15-receiving-boundaries/MATRIX.json").read_bytes())


def _receiving_targets():
    found = set()
    for path in (ROOT / "src").rglob("*.py"):
        cls = None
        for line in path.read_text(encoding="utf-8").splitlines():
            head = re.match(r"class (\w+)\b", line)
            if head:
                cls = head.group(1)
            if cls and re.match(r"    def commit\(self, signed\b", line):
                found.add(cls)
            factory = re.match(r"def (\w+_target)\(", line)
            if factory and not factory.group(1).startswith("_"):
                found.add(factory.group(1))
    return found


def test_every_target_commit_and_factory_is_in_the_matrix():
    sources = " ".join(boundary["source"] for boundary in MATRIX["boundaries"])
    found = _receiving_targets()
    assert {"FilesystemTargetAdapter", "PostgresTargetReceiver", "GovernanceTarget"} <= found
    # A lock helper used inside the PostgreSQL receiver transaction, not a receiving target.
    helpers = {"lock_database_target"}
    missing = sorted(name for name in found - helpers if name not in sources)
    assert not missing, missing


def test_every_cited_test_exists():
    cited = {node for boundary in MATRIX["boundaries"] for nodes in boundary["evidence"].values() for node in nodes}
    assert cited
    for node in sorted(cited):
        file, name = node.split("::")
        assert re.search(rf"^def {name}\(", (ROOT / file).read_text(encoding="utf-8"), re.M), node


def test_open_items_are_recorded_not_hidden():
    # Each remaining gap stays named; resolving one removes it here deliberately, never silently.
    opened = {boundary["id"]: len(boundary.get("open", ())) for boundary in MATRIX["boundaries"]}
    assert opened == {"filesystem": 0, "pack-bound-filesystem": 0, "postgres-receiver": 0,
                      "delegated-postgres-receiver": 0, "governance-targets": 0, "choke-points": 1,
                      "http-delivery": 0}
