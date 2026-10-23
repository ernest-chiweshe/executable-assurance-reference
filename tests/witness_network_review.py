"""Exact witness infrastructure inventory; no network/authorization exemption."""
import ast
from hashlib import sha256
import json

WITNESS = "src/regulated_core/evidence_witness_transport.py"


def reviewed_witness(root):
    review = json.loads((root / "docs/provenance/witness-network-review-010-v2.json").read_bytes())
    raw = (root / WITNESS).read_bytes()
    assert review["path"] == WITNESS
    assert sha256(raw).hexdigest() == review["source_sha256"]
    assert review["not_an_authorization_exemption"] is True
    lines = raw.decode().splitlines()
    assert review["nonconstructing_matches"] == {"7": "import http.client"}
    assert lines[6] == "import http.client"
    expected = {(WITNESS, int(line), call) for line, call in review["network_sites"].items()}
    assert expected == {(WITNESS, 58, "http.client.HTTPSConnection"),
                        (WITNESS, 59, "http.client.HTTPConnection")}
    tree = ast.parse(raw)
    calls = {(WITNESS, n.lineno, ast.unparse(n.func)) for n in ast.walk(tree)
             if isinstance(n, ast.Call) and ast.unparse(n.func).startswith("http.client.")}
    assert calls == expected
    operations = [n.args[0].value for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and ast.unparse(n.func) == "self._call"
                  and n.args and isinstance(n.args[0], ast.Constant)]
    assert sorted(operations) == sorted(review["operations"]) == ["ack-range", "batch", "latest", "request"]
    catalog = json.loads((root / "docs/provenance/effect-site-classifications.json").read_bytes())
    sites = [s for s in catalog["sites"] if s["path"] == WITNESS]
    assert {(s["path"], s["line"], s["call_or_sql"]) for s in sites} == expected
    assert all(s["source_sha256"] == review["source_sha256"] and s["kind"] == "network"
               and s["classification"] == "support_effect" and s["not_an_authorization_exemption"]
               and "signed response" in s["authority_review"] for s in sites)
    return {(path, line) for path, line, _ in expected} | {(WITNESS, 7)}
