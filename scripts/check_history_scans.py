"""Account for syntactic history reads; this is not a call-graph completeness proof.

Phase zero may retain explicitly pinned debt. --require-closed rejects all debt.
Dynamic dispatch and generated SQL need the separate traced-work qualification.
"""
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import re


CLASSES = {"audit", "export", "restore", "demonstration", "test", "bounded", "known_debt"}
DEBT_BASELINE_SHA256 = "0028b1c40b849b0b3f56de849fd106e62f9b55d51f0e5e1a73d471043b02e02c"  # T-038 re-baseline: moved debt only (see catalog t038_debt_rebaseline; earlier core029_debt_rebaseline)
RESOLUTIONS_SHA256 = sha256(b"[]").hexdigest()
TABLE = re.compile(
    r"\b(?:(?:regulated|reference|collaboration)_[a-z0-9_]+|projectos_states)\b", re.I)
READ = re.compile(r"\b(?:SELECT|WITH)\b", re.I)


def identity(row):
    return row["path"], row["line"], row["kind"], row["expression"]


def constant_text(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = constant_text(node.left), constant_text(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value if isinstance(part, ast.Constant) and isinstance(part.value, str)
                       else "{dynamic}" for part in node.values)
    return None


def inventory(root):
    rows = []
    for path in sorted((root / "src").rglob("*.py")):
        raw = path.read_bytes()
        tree = ast.parse(raw, filename=str(path))
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        found = set()

        def add(node, kind, expression):
            key = node.lineno, kind, expression
            if key in found:
                return
            found.add(key)
            scopes, parent = [], node
            while parent in parents:
                parent = parents[parent]
                if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append(parent.name)
            rows.append({"path": path.relative_to(root).as_posix(), "line": node.lineno,
                         "kind": kind, "expression": expression, "locus": ".".join(reversed(scopes)),
                         "source_sha256": sha256(raw).hexdigest()})

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                name = function.attr if isinstance(function, ast.Attribute) else (
                    function.id if isinstance(function, ast.Name) else "")
                if name in {"entries", "events", "verify_chain"}:
                    add(node, "history_call", ast.unparse(function))
                # A single JSON row can contain an unbounded event array. Count
                # its reads/writes too; SQL result cardinality is insufficient.
                if (name in {"get", "setdefault"} and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value in {"emissions", "release_outcomes"}):
                    add(node, "history_json_array", ast.unparse(node))
            if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
                    and node.slice.value in {"emissions", "release_outcomes"}):
                add(node, "history_json_array", ast.unparse(node))
            # Account for all uses, not only the simplest direct for loop:
            # aliases, comprehensions, slices and generator expressions matter.
            if isinstance(node, ast.Attribute) and node.attr in {"_log", "_events"}:
                add(node, "history_storage", ast.unparse(node))
            text = constant_text(node)
            if text is not None and TABLE.search(text) and READ.search(text):
                parent = parents.get(node)
                if isinstance(parent, ast.Expr):
                    owner = parents.get(parent)
                    if isinstance(owner, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                        if owner.body and owner.body[0] is parent:
                            continue  # Documentation is not executable SQL.
                if parent is not None and constant_text(parent) is not None:
                    continue
                add(node, "history_sql", " ".join(text.split()))
    return sorted(rows, key=identity)


def check(root, catalog, *, require_closed=False, debt_baseline_sha256=DEBT_BASELINE_SHA256,
          resolutions_sha256=RESOLUTIONS_SHA256):
    if catalog.get("schema") != "reference/history-read-classifications/v1":
        raise ValueError("unsupported history catalog")
    actual = {identity(row): row for row in inventory(root)}
    declared = {}
    pinned = json.dumps(catalog["debt_baseline"], sort_keys=True, separators=(",", ":")).encode()
    if sha256(pinned).hexdigest() != debt_baseline_sha256:
        raise ValueError("history debt baseline changed; explicit review required")
    baseline = {tuple(row["identity"]): row for row in catalog["debt_baseline"]}
    resolutions = catalog.get("approved_resolutions", [])
    if sha256(json.dumps(resolutions, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != resolutions_sha256:
        raise ValueError("history debt resolutions changed; independent review required")
    resolved = {tuple(row["identity"]): row for row in resolutions}
    debt = []
    for row in catalog["sites"]:
        key = identity(row)
        if key in declared:
            raise ValueError("duplicate history classification")
        declared[key] = row
        if row.get("classification") not in CLASSES or not row.get("reason", "").strip():
            raise ValueError("history classification and reason required")
        if key in baseline and row["classification"] != "known_debt":
            resolution = resolved.get(key)
            if (resolution is None or row.get("resolved_by") != resolution
                    or not resolution.get("specification") or not resolution.get("phase_evidence")
                    or resolution.get("source_sha256") != row["source_sha256"]):
                raise ValueError("pinned history debt cannot be reclassified without a reviewed resolution")
        if row.get("classification") == "known_debt":
            debt.append(key)
            prior = baseline.get(key)
            if (prior is None or row["source_sha256"] != prior["source_sha256"]
                    or row.get("locus") != prior["locus"] or not row.get("removal_phase")):
                raise ValueError("new or changed history debt requires explicit specification review")
        if row.get("operational", False) and row["classification"] != "known_debt":
            if row["classification"] != "bounded" or not row.get("bound_basis", "").strip():
                raise ValueError("operational history read lacks reviewed bound")
    missing = sorted(actual.keys() - declared.keys())
    stale = sorted(declared.keys() - actual.keys())
    drift = sorted(key for key in actual.keys() & declared.keys()
                   if actual[key]["source_sha256"] != declared[key]["source_sha256"]
                   or actual[key]["locus"] != declared[key].get("locus"))
    if missing or stale or drift:
        raise ValueError(f"unclassified={missing}; stale={stale}; drift={drift}")
    if require_closed and debt:
        raise ValueError(f"history debt remains: {debt}")
    return {"classified_sites": len(actual), "known_debt_sites": len(debt),
            "guard_integrity": True, "history_scaling_closed": not debt,
            "limits": "Syntactic accounting only; dynamic reach and database rows scanned need separate evidence."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--require-closed", action="store_true")
    args = parser.parse_args()
    if args.inventory:
        result = inventory(args.root)
    else:
        catalog = json.loads((args.root / "docs/provenance/history-read-classifications.json").read_bytes())
        result = check(args.root, catalog, require_closed=args.require_closed)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
