"""Check both active manuscripts and the linked figure against one retention contract.

This is a publication check, not a deployment attestation. Run it before paper
handoff with --publications-root pointing at the Agent Factory publications tree.
It reads only the explicitly named active files; historical versions are exempt.
"""

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


DEFAULT_CONTRACT = Path(__file__).resolve().parents[1] / "docs" / "retention-contract.json"
BEGIN = "<!-- retention-contract:v1 begin -->"
END = "<!-- retention-contract:v1 end -->"


def retention_text(contract):
    if (contract["schema"] != "executable-assurance/publication-retention/v1"
            or contract["production_mode"] != "COMPLIANCE"
            or contract["historical_evaluation_mode"] != "GOVERNANCE"
            or contract["historical_environment"] != "staging test bucket"
            or contract["compliance_mode_measured"] is not False):
        raise ValueError("retention contract changes a requirement or historical evidence boundary")
    return (
        "**Retention profile.** Production evidence requires S3 Object Lock "
        "**COMPLIANCE** mode, verified on each retained object version. "
        "The July 2026 evaluation used **GOVERNANCE** mode on a staging test bucket; "
        "those measurements do not qualify compliance-mode retention. "
        "Governance retention permits privileged bypass and does not satisfy "
        "the production requirement."
    )


def retention_block(contract):
    return BEGIN + "\n" + retention_text(contract) + "\n" + END


def figure_labels(contract):
    retention_text(contract)
    return (
        "Required production setting: COMPLIANCE retention",
        "Historical evaluation: GOVERNANCE on a staging test bucket; COMPLIANCE retention was not exercised.",
    )


def check(root, contract):
    root = Path(root).resolve()
    block = retention_block(contract)
    hashes = {}
    for key in ("paper_a", "paper_b", "paper_a_figure"):
        path = (root / contract[key]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("publication path leaves the declared root")
        data = path.read_bytes()
        text = data.decode("utf-8-sig").replace("\r\n", "\n")
        hashes[contract[key]] = hashlib.sha256(data).hexdigest()
        if key != "paper_a_figure":
            if text.count(BEGIN) != 1 or text.count(END) != 1 or block not in text:
                raise ValueError(f"{key}: retention passage differs from the shared contract")
            if key == "paper_a":
                expected = "![Figure 11](figures/" + Path(contract["paper_a_figure"]).name + ")"
                if expected not in text or "*Figure 11. Required production deployment" not in text:
                    raise ValueError("Paper A must link the version-specific required-production figure")
                if f"version {contract['paper_a_version']} ·" not in text:
                    raise ValueError("Paper A edition differs from the correction contract")
            else:
                if "S3 Object Lock (governance mode)" not in text:
                    raise ValueError("Paper B must preserve the historical governance-mode measurement")
                if (f"Version {contract['paper_b_version']} (Retention Clarification Draft)" not in text
                        or f"Companion source: {Path(contract['paper_b']).name}." not in text):
                    raise ValueError("Paper B edition or companion source differs from the correction contract")
        else:
            tree = ET.fromstring(data)
            visible = ["".join(n.itertext()) for n in tree.iter()
                       if n.tag.rsplit("}", 1)[-1] == "text"]
            if not all(label in visible for label in figure_labels(contract)):
                raise ValueError("figure must distinguish required production from historical evaluation")
            if "compliance mode · write once, read many" not in visible:
                raise ValueError("required production figure no longer names compliance mode")
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publications-root", required=True, type=Path)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT, type=Path)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    try:
        hashes = check(args.publications_root, contract)
    except (ValueError, OSError, ET.ParseError) as exc:
        parser.exit(1, "Retention consistency failed: " + str(exc) + "\n")
    print(json.dumps({"status": "PASS", "production_mode": "COMPLIANCE",
                      "historical_evaluation_mode": "GOVERNANCE", "sha256": hashes}, indent=2))


if __name__ == "__main__":
    main()
