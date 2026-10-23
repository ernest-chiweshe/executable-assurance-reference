"""Print all declared obligation axes; exit 1 for OPEN rows with --require-closed."""
import argparse
import json
import sys

from _scope_report import load_scope, markdown_report, obligations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-closed", action="store_true")
    args = parser.parse_args()
    try:
        report = obligations(load_scope())
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown_report(report) if args.format == "markdown" else json.dumps(report, indent=2))
    return 1 if args.require_closed and not report["engineering_complete"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
