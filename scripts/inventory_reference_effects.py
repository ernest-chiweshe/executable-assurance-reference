"""Report syntactic effect sites across all reference source packages without importing them.

This is an inspection aid, not proof of complete effect coverage or authorization.
Indirect host-port effects and dynamic dispatch require separate review.
"""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

from _effect_sites import sites


def inventory(root):
    root = Path(root).resolve(strict=True)
    source = root / "src"
    if not source.is_dir() or source.is_symlink():
        raise ValueError("reference root must contain a regular src directory")
    source = source.resolve(strict=True)
    if not source.is_relative_to(root):
        raise ValueError("source directory leaves the reference root")
    files, totals, packages = [], Counter(), {}
    paths = sorted(source.rglob("*.py"))
    if not paths:
        raise ValueError("source scope contains no Python files")
    for path in paths:
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(source):
            raise ValueError("source entry leaves the declared scope or is linked")
        raw = path.read_bytes()
        found = sites(raw.decode("utf-8"))
        counts = Counter(kind for kind, line, call in found)
        totals.update(counts)
        package = path.relative_to(source).parts[0]
        packages.setdefault(package, Counter()).update(counts)
        files.append({"path": path.relative_to(root).as_posix(),
                      "sha256": sha256(raw).hexdigest(),
                      "sites": [{"kind": kind, "line": line, "call_or_sql": call}
                                for kind, line, call in found]})
    return {
        "schema": "reference/static-effect-sites/v1",
        "scope": "all Python files under src, including files without detected sites",
        "python_files_scanned": len(files),
        "files_with_static_sites": sum(bool(row["sites"]) for row in files),
        "site_counts": dict(sorted(totals.items())),
        "site_counts_by_package": {key: dict(sorted(value.items()))
                                   for key, value in sorted(packages.items())},
        "files": files,
        "complete_effect_coverage_proven": False,
        "guard_coverage_proven": False,
        "limits": [
            "Syntax only; source modules are parsed, never imported or executed.",
            "Over-approximation: SQL-looking strings and unrelated methods can be false positives.",
            "Indirect host ports and dynamic dispatch may have effects without a detected site.",
            "Every site still needs classification and boundary-contract review; no exemption is inferred.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        report = inventory(args.root)
    except (OSError, UnicodeError, SyntaxError, ValueError) as error:
        parser.exit(2, f"inventory failed: {error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
