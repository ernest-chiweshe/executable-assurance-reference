"""Extract a dependency closure from immutable Git blobs without copying a worktree."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "6bba989aeca27575b971c78a103cbf3745cfda6a"
SEEDS = (
    "regulated_core.engine",
    "regulated_core.target",
    "regulated_core.clock",
    "regulated_core.persistence_pg",
    "regulated_core.reporting",
    "regulated_core.clock_pg",
)


def main() -> None:
    """Read exact blobs, report dependencies, and optionally preserve their bytes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    def git(*arguments: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(args.source), *arguments])

    if git("rev-parse", "--verify", COMMIT + "^{commit}").decode().strip() != COMMIT:
        raise RuntimeError("source commit mismatch")
    tree = git("ls-tree", "-r", "--name-only", COMMIT).decode().splitlines()
    modules = {}
    for path in tree:
        if path.endswith(".py"):
            name = path[:-3].replace("/", ".")
            modules[name.removesuffix(".__init__")] = path
    pending = list(SEEDS)
    selected: dict[str, bytes] = {}
    external = set()
    while pending:
        module = pending.pop()
        path = modules.get(module)
        if path is None or path in selected:
            continue
        raw = git("show", f"{COMMIT}:{path}")
        selected[path] = raw
        parts = module.split(".")
        for size in range(1, len(parts)):
            parent = ".".join(parts[:size])
            if modules.get(parent, "").endswith("/__init__.py"):
                pending.append(parent)
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        for node in ast.walk(ast.parse(raw.decode("utf-8-sig"))):
            imports = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    prefix = package.split(".")[: len(package.split(".")) - node.level + 1]
                    base = ".".join(prefix + ([base] if base else []))
                imports = [base] + [base + "." + alias.name for alias in node.names]
            for name in imports:
                if name in modules:
                    pending.append(name)
                elif name.split(".")[0] not in {"regulated_core", "factory"}:
                    external.add(name.split(".")[0])
    print(
        json.dumps(
            {
                "commit": COMMIT,
                "files": len(selected),
                "external_import_roots": sorted(external),
                "factory_files": [p for p in sorted(selected) if p.startswith("factory/")],
            },
            indent=2,
        )
    )
    if not args.write:
        return
    entries = []
    for path, raw in sorted(selected.items()):
        destination = root / "src" / path
        if destination.exists() and destination.read_bytes() != raw:
            raise RuntimeError(f"refusing to overwrite different bytes: {path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        entries.append(
            {
                "path": "src/" + path,
                "source_path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "git_blob": git("rev-parse", f"{COMMIT}:{path}").decode().strip(),
                "historical_crlf": b"\r\n" in raw,
            }
        )
    provenance = {
        "source_commit": COMMIT,
        "source_tree": git("rev-parse", COMMIT + "^{tree}").decode().strip(),
        "source_repository": "echiweshe/agent-factory-prod",
        "licence": "No root LICENSE/COPYING/NOTICE found in this commit; private owner-authorized extraction only. Public licensing unresolved.",
        "review": "Extraction and composition unreviewed; source reviews do not qualify this package.",
        "line_endings": "Exact historical source bytes preserved; CRLF exceptions enumerated per file.",
        "files": entries,
    }
    (root / "source-provenance.json").write_bytes(
        (json.dumps(provenance, indent=2) + "\n").encode()
    )


if __name__ == "__main__":
    main()
