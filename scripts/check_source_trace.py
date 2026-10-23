"""Trace recovered files to hash-pinned D0 rows without executing recovered code.

An anchor is a source reference, not an integration verdict. Dependencies carry
SUPPORT status; no test coverage or obligation completion is inferred here.
"""

import argparse
import ast
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re

from _scope_report import EXPECTED_IDS, LOCK_SHA256, ROOT, confined_file, load_scope, sha
from recover_authority_sources import COMMIT, TREE
from _source_adaptations import load_adaptations

ANCHOR_FILES = ("D0-source-pins-6bba989a-v3.md", "D0-x-row-anchors-6bba989a.md")
ANCHOR = re.compile(r"^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{40})`\s*\|")


def anchors(inputs):
    result = {}
    for document in ANCHOR_FILES:
        for line in inputs[document].splitlines():
            match = ANCHOR.match(line)
            if not match:
                continue
            row, source, blob = match.groups()
            if row not in EXPECTED_IDS:
                raise ValueError(f"Unknown D0 row: {row}")
            item = {"row_id": row, "git_blob": blob, "document": document}
            result.setdefault("src/" + source, []).append(item)
    if not result:
        raise ValueError("No pinned source anchors found")
    return result


def recovered_files(root, *, layout="reference", adaptations=None):
    if layout not in {"reference", "upstream"}:
        raise ValueError(f"Unknown source layout: {layout}")
    entries, manifests = {}, []
    adaptations = {} if adaptations is None else adaptations
    for manifest in sorted(root.glob("source-provenance*.json")):
        raw = confined_file(root, manifest.name).read_bytes()
        content = json.loads(raw)
        if content.get("source_commit") != COMMIT or content.get("source_tree", TREE) != TREE:
            raise ValueError(f"Provenance source pin differs: {manifest.name}")
        manifests.append({"path": manifest.name, "sha256": sha(raw)})
        for entry in content["files"]:
            path, source = entry["path"], entry["source_path"]
            if not path.startswith("src/") or (source.endswith(".py") and path != "src/" + source):
                raise ValueError(f"Unexpected recovered path: {path}")
            checked_path = path if layout == "reference" else source
            data = confined_file(root, checked_path).read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            adaptation = adaptations.get(path)
            if adaptation is None:
                if sha(data) != entry["sha256"] or blob != entry["git_blob"]:
                    raise ValueError(f"Recovered source bytes changed: {path}")
            elif (adaptation["original_sha256"] != entry["sha256"]
                  or adaptation["original_git_blob"] != entry["git_blob"]
                  or adaptation["source_path"] != source
                  or adaptation["adapted_sha256"] != sha(data)):
                raise ValueError(f"Adaptation differs from pinned recovered provenance: {path}")
            if path in entries:
                if any(entries[path][key] != entry[key] for key in ("source_path", "sha256", "git_blob")):
                    raise ValueError(f"Conflicting recovered provenance: {path}")
            else:
                entries[path] = {key: entry[key] for key in ("path", "source_path", "sha256", "git_blob")}
                entries[path]["checked_path"] = checked_path
                entries[path]["actual_sha256"] = sha(data)
                entries[path]["byte_identity"] = adaptation is None
                entries[path]["explicit_adaptation"] = adaptation
                entries[path]["provenance_manifests"] = []
            entries[path]["provenance_manifests"].append(manifest.name)
    if not entries:
        raise ValueError("No recovered provenance files found")
    if set(adaptations) - set(entries):
        raise ValueError("Adaptation names a source absent from recovered provenance")
    return entries, manifests


def import_graph(root, entries):
    modules = {path[4:-3].replace("/", ".").removesuffix(".__init__"): path
               for path in entries if path.endswith(".py")}
    graph = {path: {} for path in entries}
    for module, path in sorted(modules.items()):
        parts = module.split(".")
        for length in range(1, len(parts)):
            parent = modules.get(".".join(parts[:length]))
            if parent and parent != path:
                graph[path][parent] = "PARENT_INITIALIZER"
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        tree = ast.parse(confined_file(root, entries[path]["checked_path"]).read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
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
                dependency = modules.get(name)
                if dependency and dependency != path:
                    graph[path][dependency] = "STATIC_IMPORT"
    return graph


def build_report(root=ROOT, inputs=None, *, layout="reference",
                 adaptation_manifest=None, adaptation_sha256=None):
    if layout not in {"reference", "upstream"}:
        raise ValueError(f"Unknown source layout: {layout}")
    root = Path(root)
    inputs = load_scope(root / "docs/authority-scope/v12") if inputs is None else inputs
    pinned = anchors(inputs)
    adaptations, adaptation_info = load_adaptations(
        root, adaptation_manifest, adaptation_sha256, layout=layout)
    entries, manifests = recovered_files(root, layout=layout, adaptations=adaptations)
    binding_file = "docs/qualification/source-trace-bindings.json"
    binding_path = confined_file(root, binding_file)
    declared, binding_hash = {}, None
    if binding_path.exists():
        raw = binding_path.read_bytes()
        binding_hash = sha(raw)
        bindings = json.loads(raw)
        if (bindings.get("schema") != "reference/source-row-bindings/v1"
                or bindings.get("scope_lock_sha256") != LOCK_SHA256):
            raise ValueError("Unknown reference binding schema")
        for binding in bindings["files"]:
            path = binding["path"]
            if path in declared or path not in entries or path in pinned:
                raise ValueError(f"Duplicate, unknown or already anchored binding: {path}")
            if binding["sha256"] != entries[path]["sha256"]:
                raise ValueError(f"Reference binding source hash changed: {path}")
            rows = binding["row_ids"]
            if not rows or len(set(rows)) != len(rows) or set(rows) - EXPECTED_IDS:
                raise ValueError(f"Invalid reference binding rows: {path}")
            if not binding.get("reason") or not binding.get("consumers"):
                raise ValueError(f"Reference binding requires an explicit rationale and consumer: {path}")
            consumers = []
            for consumer in binding["consumers"]:
                checked_path = consumer if layout == "reference" else consumer.removeprefix("src/")
                consumers.append({"path": consumer, "checked_path": checked_path,
                                  "sha256": sha(confined_file(root, checked_path).read_bytes())})
            declared[path] = {**binding, "consumers": consumers, "review_verdict": None}
            pinned[path] = [{"row_id": row, "git_blob": entries[path]["git_blob"],
                             "document": binding_file} for row in rows]
    graph = import_graph(root, entries)
    routes = {path: {} for path in entries}
    for start in sorted(set(entries) & set(pinned)):
        if any(anchor["git_blob"] != entries[start]["git_blob"] for anchor in pinned[start]):
            raise ValueError(f"D0 anchor blob differs from recovered source: {start}")
        pending = deque([(start, [start], [])])
        visited = set()
        while pending:
            path, chain, kinds = pending.popleft()
            if path in visited:
                continue
            visited.add(path)
            for anchor in pinned[start]:
                row = anchor["row_id"]
                candidate = {"row_id": row, "anchor": start, "anchor_document": anchor["document"],
                             "path": chain, "edges": kinds}
                old = routes[path].get(row)
                if old is None or (len(chain), chain) < (len(old["path"]), old["path"]):
                    routes[path][row] = candidate
            for dependency, kind in sorted(graph[path].items()):
                pending.append((dependency, [*chain, dependency], [*kinds, kind]))
    files = []
    for path, entry in sorted(entries.items()):
        direct = sorted({item["row_id"] for item in pinned.get(path, [])})
        traces = [route for _, route in sorted(routes[path].items())]
        files.append({**entry, "direct_rows": direct, "row_ids": sorted(routes[path]),
                      "kind": "PYTHON_MODULE" if path.endswith(".py") else "RESOURCE",
                      "classification": "REFERENCE_BINDING" if path in declared else
                                        "D0_ANCHOR" if direct else "SUPPORT" if traces else "UNTRACED",
                      "reference_binding": declared.get(path),
                      "traces": traces, "row_test_evidence": [], "integration_verdict": None})
    untraced = [item["path"] for item in files if not item["row_ids"]]
    return {"schema": "reference/recovered-source-trace/v1", "scope_lock_sha256": LOCK_SHA256,
            "source_layout": layout,
            "explicit_adaptation_manifest": adaptation_info,
            "adapted_source_files": sorted(adaptations),
            "source_commit": COMMIT, "source_tree": TREE, "provenance_manifests": manifests,
            "reference_bindings_sha256": binding_hash, "reference_bindings_review_required": sorted(declared),
            "file_count": len(files), "classification_counts": dict(Counter(f["classification"] for f in files)),
            "untraced_files": untraced, "all_recovered_files_traced": not untraced,
            "untraced_modules": [path for path in untraced if path.endswith(".py")],
            "engineering_complete": False, "obligations_promoted": 0,
            "limits": "Static import paths only, including conditional imports and parent initializers. "
                      "No recovered code is imported. D0_ANCHOR is a pinned source reference, not test coverage; "
                      "SUPPORT dependencies have no row-specific execution evidence asserted. Dynamic imports "
                      "and complete runtime closure are not established. Resource input mappings are not "
                      "inferred from imports. Explicit reference bindings carry no independent verdict. "
                      "No signed exclusion is inferred. Explicit adaptations preserve original anchor hashes "
                      "and report actual hashes separately; pinned-diff validation does not verify approval.",
            "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=ROOT)
    parser.add_argument("--layout", choices=("reference", "upstream"), default="reference",
                        help="Explicit source layout; never inferred from available files")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--adaptation-manifest", help="Explicit relative manifest; no auto-discovery")
    parser.add_argument("--adaptation-sha256", help="Independently supplied expected manifest hash")
    args = parser.parse_args()
    report = build_report(args.reference, layout=args.layout,
                          adaptation_manifest=args.adaptation_manifest,
                          adaptation_sha256=args.adaptation_sha256)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        # A report cannot silently overwrite an earlier review artifact.
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")
    raise SystemExit(0 if report["all_recovered_files_traced"] else 2)


if __name__ == "__main__":
    main()
