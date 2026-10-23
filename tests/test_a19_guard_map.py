"""A19 static enforcement map: every Paper A Table 2 guard names an exact, unique source site per boundary and the
intact tests that exercise it. The map is checked against the tree, so a moved or deleted guard fails here."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAP = json.loads((ROOT / "docs/provenance/a19-guard-conformance/MAP.json").read_text(encoding="utf-8"))
GUARDS = ["mandatory-effect-path", "evidence-before-permit", "revocation-check", "expiry-check",
          "exact-payload-binding", "durable-replay-check", "aggregate-budget-reservation"]


def test_map_names_exactly_the_seven_table_2_guards():
    assert MAP["schema"] == "reference/a19-guard-conformance/v1"
    assert [g["guard"] for g in MAP["guards"]] == GUARDS


def test_every_anchor_is_one_exact_line_of_its_file():
    for guard in MAP["guards"]:
        for site in guard["sites"]:
            lines = (ROOT / site["file"]).read_text(encoding="utf-8").splitlines()
            assert lines.count(site["anchor"]) == 1, (guard["guard"], site["file"], site["anchor"])


def test_every_cited_intact_test_exists():
    for guard in MAP["guards"]:
        for site in guard["sites"]:
            assert site["tests"], (guard["guard"], site["boundary"])
            for node in site["tests"]:
                path, name = node.split("::")
                source = (ROOT / path).read_text(encoding="utf-8")
                assert re.search(rf"^def {re.escape(name)}\(", source, re.M), node


def test_receiving_guards_cover_filesystem_and_postgres_boundaries():
    receiving = {"mandatory-effect-path", "revocation-check", "expiry-check", "exact-payload-binding",
                 "durable-replay-check"}
    for guard in MAP["guards"]:
        boundaries = {site["boundary"] for site in guard["sites"]}
        if guard["guard"] in receiving:
            assert {"filesystem", "postgres-receiver"} <= boundaries, guard["guard"]
        else:
            assert "issuance" in boundaries, guard["guard"]
