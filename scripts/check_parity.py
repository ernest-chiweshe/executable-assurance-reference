"""Compare declared pinned source files with this reference, without importing them."""
import argparse
import json
import sys
from pathlib import Path

from _scope_report import ROOT, load_scope, markdown_report, parity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=ROOT)
    parser.add_argument("--layout", choices=("reference", "upstream"), default="reference",
                        help="Explicit source layout: src/ extraction or flat upstream tree")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-identical", action="store_true")
    args = parser.parse_args()
    try:
        report = parity(load_scope(), args.reference, layout=args.layout)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown_report(report) if args.format == "markdown" else json.dumps(report, indent=2))
    return 1 if args.require_identical and any(
        row["file_status"] != "BYTE_IDENTICAL" for row in report["rows"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
