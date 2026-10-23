"""Enforce reviewed static-site accounting; never infer authorization coverage."""

import argparse
from collections import Counter
import json
from pathlib import Path

from inventory_reference_effects import inventory


CLASSES = {
    "boundary_effect", "support_effect", "fixture_effect",
    "provider_capability", "syntax_non_effect",
}


def site_key(row):
    return row["path"], row["kind"], row["line"], row["call_or_sql"]


def check(root, catalog):
    scan = inventory(root)
    if catalog.get("schema") != "reference/static-effect-classifications/v1":
        raise ValueError("unsupported classification schema")
    if catalog.get("authorization_exemptions") != []:
        raise ValueError("classification cannot grant authorization exemptions")
    actual = {
        (file["path"], site["kind"], site["line"], site["call_or_sql"]): file["sha256"]
        for file in scan["files"] for site in file["sites"]
    }
    reviewed = {}
    for row in catalog["sites"]:
        key = site_key(row)
        if key in reviewed:
            raise ValueError(f"duplicate classification: {key}")
        if row.get("classification") not in CLASSES:
            raise ValueError(f"unknown classification: {key}")
        for field in ("locus", "reason", "authority_review"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ValueError(f"missing {field}: {key}")
        if row.get("not_an_authorization_exemption") is not True:
            raise ValueError(f"missing explicit non-exemption: {key}")
        reviewed[key] = row
    missing = sorted(actual.keys() - reviewed.keys())
    stale = sorted(reviewed.keys() - actual.keys())
    drift = sorted(key for key in actual.keys() & reviewed.keys()
                   if actual[key] != reviewed[key].get("source_sha256"))
    if missing or stale or drift:
        raise ValueError(f"unclassified={missing}; stale={stale}; source_drift={drift}")
    return {
        "schema": "reference/static-effect-classification-check/v1",
        "python_files_scanned": scan["python_files_scanned"],
        "classified_sites": len(reviewed),
        "site_counts": scan["site_counts"],
        "classification_counts": dict(sorted(Counter(
            row["classification"] for row in reviewed.values()).items())),
        "static_site_accounting_complete": True,
        "authorization_coverage_proven": False,
        "complete_effect_coverage_proven": False,
        "limits": [
            "Exact syntactic site accounting only; no target module is executed.",
            "Support, provisioning and fixture writes remain effects, not exemptions.",
            "Provider construction does not establish live provider qualification.",
            "Dynamic dispatch and indirect ports require separate boundary review.",
            "Catalog integrity does not itself establish reviewer acceptance or row closure.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--catalog", default="docs/provenance/effect-site-classifications.json")
    args = parser.parse_args(argv)
    try:
        catalog = json.loads((args.root / args.catalog).read_bytes())
        result = check(args.root, catalog)
    except (OSError, UnicodeError, SyntaxError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"effect classification failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
