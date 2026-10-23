"""Recover pinned application import closures without executing source code.

Existing bytes must match the pinned source. The sole permitted replacement is
the reference's original declaration-only Project OS initializer, identified by
its exact hash; restoring the original exports is recorded in provenance.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "6bba989aeca27575b971c78a103cbf3745cfda6a"
TREE = "c72682a1dc4b51b3646d686002bfbdd7b8ae788d"
SEEDS = (
    "regulated_core.host_runtime", "regulated_core.pack_gate",
    "regulated_core.prepared_schema_pg", "regulated_core.approval_exchange",
    "regulated_core.certificates",
)
PROFILES = {
    "delegation-facade": (
        "regulated_core.delegation_review", "regulated_core.delegation_source",
    ),
    "authority": SEEDS,
    "choke-points": ("regulated_core.choke_points",),
    "credentials-interface": ("factory.credentials",),
    "generation-floor": ("factory.customer.generation_floor_pg",),
    "retention-adapter": ("regulated_core.providers_aws",),
    "application-authority": (
        "factory.education_workbench.reviewer_credentials",
        "factory.education_workbench.source_witness",
        "factory.health_ui.session_release",
        "factory.health_ui.pg_store",
        "factory.packs.demonstration_checks",
    ),
    "education-authority": (
        "factory.education_workbench.reviewer_credentials",
        "factory.education_workbench.source_witness",
    ),
    "education-enrollment": (
        "factory.education_workbench.provisioning",
    ),
    "application-boundaries": (
        "factory.health_ui.session_release",
        "factory.packs.demonstration_checks",
    ),
    "health-authority": (
        "factory.health_ui.clinical_checks",
        "factory.health_ui.clinical_release",
        "factory.health_ui.clinician_credentials",
        "factory.health_ui.clinician_certificates",
    ),
    "product-spec": (
        "factory.verticals.product_spec.spec",
        "factory.verticals.product_spec.build",
        "factory.verticals.product_spec.export",
        "factory.verticals.product_spec.view",
    ),
}
INITIALIZER = "factory/projectos/__init__.py"
OLD_INITIALIZER = "7dc83140e3e36679d699289a3fc3983019bed7cd49fcd275a5e1985015a16ec0"


def recover(source: Path, destination: Path, *, write: bool = False,
            profile: str = "authority") -> dict:
    if profile not in PROFILES:
        raise ValueError("unknown pinned recovery profile")
    seeds = PROFILES[profile]
    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(source), *args])

    if git("rev-parse", COMMIT + "^{tree}").decode().strip() != TREE:
        raise ValueError("source tree does not match the reviewed pin")
    paths = git("ls-tree", "-r", "--name-only", COMMIT).decode().splitlines()
    modules = {
        p[:-3].replace("/", ".").removesuffix(".__init__"): p
        for p in paths if p.endswith(".py")
    }
    pending, selected, external = list(seeds), {}, set()
    while pending:
        module = pending.pop()
        path = modules.get(module)
        if path is None:
            raise ValueError(f"required source module missing: {module}")
        if path in selected:
            continue
        raw = git("show", f"{COMMIT}:{path}")
        selected[path] = raw
        parts = module.split(".")
        # PEP 420 parents have no source initializer to extract. Descendant
        # modules still retain their exact bytes and original package layout.
        pending.extend(parent for i in range(1, len(parts))
                       if (parent := ".".join(parts[:i])) in modules)
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        for node in ast.walk(ast.parse(raw.decode("utf-8-sig"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    prefix = package.split(".")[:len(package.split(".")) - node.level + 1]
                    base = ".".join(prefix + ([base] if base else []))
                names = [base] + [base + "." + alias.name for alias in node.names]
            for name in names:
                if name in modules:
                    pending.append(name)
                elif name.split(".")[0] not in {"regulated_core", "factory"}:
                    external.add(name.split(".")[0])

    destination = destination.resolve(strict=True)
    entries, changes = [], []
    # Complete preflight before writing any source file.
    for path, raw in sorted(selected.items()):
        target = destination / "src" / path
        if not target.resolve().is_relative_to(destination):
            raise ValueError(f"destination escapes the reference: {path}")
        for parent in (target, *target.parents):
            if parent == destination:
                break
            if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
                raise ValueError(f"linked destination refused: {path}")
        old = target.read_bytes() if target.exists() else None
        if old is not None and old != raw:
            if path != INITIALIZER or hashlib.sha256(old).hexdigest() != OLD_INITIALIZER:
                raise ValueError(f"existing improvements must be reviewed, not overwritten: {path}")
            changes.append({"path": "src/" + path, "before_sha256": OLD_INITIALIZER,
                            "reason": "Restore original ProjectEngine and declaration exports"})
        entries.append({
            "path": "src/" + path, "source_path": path, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": git("rev-parse", f"{COMMIT}:{path}").decode().strip(),
            "historical_crlf": b"\r\n" in raw,
        })
    report = {
        "source_commit": COMMIT, "source_tree": TREE,
        "source_repository": "echiweshe/agent-factory-prod",
        "seeds": list(seeds), "files": entries,
        "external_import_roots": sorted(external), "replacements": changes,
        "scope": "Exact import closure recovery only; no integration or deployment verdict.",
        "licence": "Private owner-authorized extraction; public licensing unresolved.",
    }
    manifest = destination / f"source-provenance-{profile}.json"
    if manifest.exists():
        previous = json.loads(manifest.read_bytes())
        # A repeat preserves the historical replacement record.
        if not changes:
            report["replacements"] = previous.get("replacements", [])
        if previous != report:
            raise ValueError("existing authority provenance differs; review required")
    if write:
        for path, raw in selected.items():
            target = destination / "src" / path
            if not target.exists() or target.read_bytes() != raw:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
        if not manifest.exists():
            manifest.write_bytes((json.dumps(report, indent=2) + "\n").encode())
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--profile", choices=tuple(PROFILES), default="authority")
    args = parser.parse_args()
    report = recover(args.source, args.destination, write=args.write, profile=args.profile)
    print(json.dumps({"files": len(report["files"]), "replacements": report["replacements"],
                      "written": args.write}, indent=2))


if __name__ == "__main__":
    main()
