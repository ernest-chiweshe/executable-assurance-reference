"""X-15 coverage scope: which outbound paths the managed egress admission must mediate in this reference.

The frozen product (6bba989a) routes its covered outbound content sends (messaging, publishing, repurpose
publication and webhooks) through the installation's one egress admission. None of those modules is present in
this reference. The network clients the reference constructs are exactly (a) the reviewed provider capabilities of
its effect-site catalog (KMS key custody and S3 retention/assignment storage), infrastructure the host configures,
not covered content sends, and (b) since candidate 054 (X-8) the verbatim receipt-bound HTTP delivery driver, whose
connection sites are catalogued as egress boundary effects reached only behind the governed egress target
(assurance_reference.governed_egress; test_x8_egress_static_scan.py), and (c) CORE010 witness infrastructure,
accounted for by its exact source-pinned boundary review. This is a static scope statement; it is not
live egress qualification.
"""
import json
from pathlib import Path
import re
from witness_network_review import WITNESS, reviewed_witness

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "src/factory/public_fetch/drivers/stdlib.py"
FROZEN_COVERED = ("factory/messaging/service.py", "factory/publishing/service.py",
                  "factory/verticals/repurpose/publish.py", "factory/webhooks.py")
NETWORK = re.compile(r"boto3\.client\(|urlopen\(|http\.client|requests\.(get|post|put|patch|delete|request|Session)\b"
                     r"|httpx\.|socket\.(create_connection|socket)\(|smtplib\.|aiohttp\.")


def test_frozen_covered_outbound_modules_are_absent_from_the_reference():
    for module in FROZEN_COVERED:
        assert not (ROOT / "src" / module).exists(), module


def test_only_reviewed_provider_capabilities_construct_network_clients():
    found = set()
    for path in sorted((ROOT / "src").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if NETWORK.search(line) and not line.lstrip().startswith("#"):
                found.add((path.relative_to(ROOT).as_posix(), number))
    catalog = json.loads((ROOT / "docs/provenance/effect-site-classifications.json").read_bytes())
    reviewed = {(site["path"], site["line"]) for site in catalog["sites"]
                if site["classification"] == "provider_capability"}
    governed = {(site["path"], site["line"]) for site in catalog["sites"]
                if site["kind"] == "network" and site["classification"] == "boundary_effect"}
    # Every witness match is separately source-pinned and accounted for.
    # Remaining non-driver matches are the original four cloud capabilities.
    witness = reviewed_witness(ROOT)
    assert {site for site in found if site[0] == WITNESS} == witness
    assert {site for site in found if site[0] not in (DRIVER, WITNESS)} == reviewed
    assert len(reviewed) == 4
    # Inside it, every broad match is accounted for exactly, by statement text: the three catalogued egress
    # boundary constructions, and the non-constructing matches named with why they construct nothing.
    accounted = {
        "raw = socket.create_connection((address, port), timeout=connect_timeout)": "governed construction",
        "conn = http.client.HTTPSConnection(host, port)": "governed construction",
        "conn = http.client.HTTPConnection(host, port)": "governed construction",
        "import http.client": "module import (two occurrences)",
        "conn: http.client.HTTPConnection": "type annotation",
        "except http.client.IncompleteRead as exc:": "exception class reference",
        '"""The real socket+TLS+http.client channel implementing `HttpConnection`.': "docstring",
        '"""Live `http.client` transport pinned to one approved address. Connects the': "docstring",
    }
    driver_lines = (ROOT / DRIVER).read_text(encoding="utf-8").splitlines()
    matched = [(number, line.strip()) for number, line in enumerate(driver_lines, start=1)
               if NETWORK.search(line) and not line.lstrip().startswith("#")]
    assert {text for _, text in matched} == set(accounted)
    assert len(matched) == 9  # Each text once, except the two module imports.
    constructions = {(DRIVER, number) for number, text in matched if accounted[text] == "governed construction"}
    assert constructions == governed and len(governed) == 3
    assert {(DRIVER, number) for number, _ in matched} == {site for site in found if site[0] == DRIVER}
