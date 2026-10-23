"""X-8 static path review: no send call outside the governed egress inventory (as in A01 and A02).

The original content-delivery network calls sit in the ported public-fetch drivers.
CORE010 adds separately source-pinned witness infrastructure transport; its explicit
review does not exempt arbitrary destinations or content sends. The receipt-bound HTTP
transport, the only caller of those drivers for delivery, is constructed only by the governed egress factories. The
production composition helper in factory.egress_composition builds an unbudgeted core egress target, which the
reference engine refuses (test_reference_governance_admission.py); the reference's composable path is
assurance_reference.governed_egress. Limits (frozen X-8): a lexical scan cannot see dynamically created paths, and
absence of an ungoverned path assumes agents receive no raw network or provider credentials.
"""
import json
import pathlib
import re
from witness_network_review import WITNESS, reviewed_witness

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DRIVERS = {"src/factory/public_fetch/drivers/stdlib.py", "src/factory/public_fetch/drivers/resolver.py"}
NETWORK = re.compile(r"^\s*(import|from)\s+(socket|ssl|http\.client|urllib\.request|requests|httpx|aiohttp|smtplib|"
                     r"ftplib|websocket)\b|^\s*import\s+http\.client|create_connection\(|urlopen\(", re.M)
TRANSPORT = re.compile(r"\bHttpEgressTransport\(|\bpublic_http_request\b")
TRANSPORT_FILES = {"src/factory/governed_http.py", "src/factory/egress_composition.py",
                   "src/assurance_reference/governed_egress.py"}


def _sources():
    for path in sorted(SRC.rglob("*.py")):
        yield path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8")


def test_network_capable_calls_exist_only_in_drivers_and_reviewed_witness():
    found = {rel for rel, text in _sources() if NETWORK.search(text)}
    reviewed_witness(ROOT)
    assert found == DRIVERS | {WITNESS}, found


def test_receipt_bound_transport_is_built_only_by_governed_egress_factories():
    found = {rel for rel, text in _sources() if TRANSPORT.search(text)}
    assert found == TRANSPORT_FILES, found


def test_every_network_effect_has_driver_or_witness_boundary_review():
    catalog = json.loads((ROOT / "docs/provenance/effect-site-classifications.json").read_bytes())
    network = [site for site in catalog["sites"] if site["kind"] == "network"]
    reviewed_witness(ROOT)
    assert {site["path"] for site in network} == {"src/factory/public_fetch/drivers/stdlib.py", WITNESS}
    network = [site for site in network if site["path"] != WITNESS]
    assert len(network) == 3
    assert all(site["classification"] == "boundary_effect" and "egress_target" in site["reason"] for site in network)
