"""Read-only reports over the frozen v12 scope; never runtime qualification."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "docs/authority-scope/v12"
LOCK_SHA256 = "d7353fd5a3420166c8f886a74f85ff39b0d9d183419873bbcaca9fdfdc2b6b72"
EXPECTED_IDS = frozenset(
    [f"A{i:02}" for i in range(1, 23)]
    + [f"B-F{i}" for i in range(1, 7)]
    + ["B-F7a", "B-F7b", "B-F7c", "B-4.5", "B-6.3", "B-6.4"]
    + [f"I-{i}" for i in range(1, 7)]
    + [f"X-{i}" for i in range(1, 26)]
    + ["R-1", "R-1b", "R-2", "R-2b"]
)
ROW_ID = re.compile(r"(?:A\d{2}|B-(?:F\d[a-c]?|\d\.\d)|[IX]-\d+|R-[12]b?)\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def confined_file(root, relative):
    root = root.resolve()
    path = root / relative
    if Path(relative).is_absolute() or not path.resolve().is_relative_to(root):
        raise ValueError(f"Path outside input root: {relative}")
    for part in [path, *path.parents]:
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError(f"Link in input path: {relative}")
        if part == root:
            break
    return path


def load_scope(root=SCOPE):
    raw = (root / "scope-lock.json").read_bytes()
    if sha(raw) != LOCK_SHA256:
        raise ValueError("Scope lock changed; requires explicit scope revision review")
    lock = json.loads(raw)
    result = {}
    for entry in lock["inputs"]:
        name = entry["path"]
        if name in result:
            raise ValueError(f"Duplicate input: {name}")
        data = confined_file(root, name).read_bytes()
        if sha(data) != entry["sha256"]:
            raise ValueError(f"Pinned input changed: {name}")
        result[name] = data.decode("utf-8-sig")
    return result


def table_rows(text):
    """Keep every original column, including unequal table axes."""
    headers = None
    found = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells[0].lower() == "id":
            headers = cells
        elif ROW_ID.fullmatch(cells[0]):
            if headers is None or len(cells) != len(headers):
                raise ValueError(f"Malformed obligation table row: {cells[0]}")
            if cells[0] in found:
                raise ValueError(f"Duplicate obligation: {cells[0]}")
            found[cells[0]] = dict(zip(headers, cells))
    return found


def require_ids(rows):
    if set(rows) != EXPECTED_IDS:
        raise ValueError(f"Scope ID mismatch: missing={sorted(EXPECTED_IDS - set(rows))}, "
                         f"extra={sorted(set(rows) - EXPECTED_IDS)}")


def obligations(inputs):
    rows = table_rows(inputs["D0-obligation-map-draft-v10.md"])
    require_ids(rows)
    plans = {}
    plan_sources = {}
    for name in ("D0-evidence-plan-part1-A.md", "D0-evidence-plan-part2-BIX-v3.md",
                 "D0-evidence-plan-part3-R-v2.md"):
        for key, row in table_rows(inputs[name]).items():
            if key in plans:
                raise ValueError(f"Duplicate evidence plan: {key}")
            plans[key] = row
            plan_sources[key] = name
    require_ids(plans)
    output = []
    for key, source in rows.items():
        plan = plans[key]
        output.append({
            "id": key,
            "paper_ref": key if key.startswith(("A", "B")) else "inherited/boundary:" + key,
            "obligation": source.get("Obligation (short)", source.get("Obligation")),
            "source_columns": source,
            "evidence_plan": plan,
            "evidence_plan_source": plan_sources[key],
            "mechanism": source.get("Prod mechanism (6bba989a)", source.get("Prod mechanism",
                source.get("Prod evidence (6bba989a)", source.get("Anchors")))),
            "effect_boundary": source.get("Boundary", "See named mechanism and evidence plan"),
            "historical_evidence": source.get("Hist.", "See source columns; no inference"),
            "reference_integration_baseline": source.get("Ref. now", "Not asserted by this row"),
            "reference_evidence": [],
            "coverage_limits": plan.get("Coverage limits"),
            "assumptions": "Full pinned source and evidence-plan conventions apply. "
                "v12 supersedes older timing: restricted roles and approval/session controls in D1.",
            "independent_verdict": None,
            "exception": None,
            "status": "OPEN",
        })
    return {"schema": "executable-assurance/obligations-report/v1",
            "scope_lock_sha256": LOCK_SHA256, "kind": "PINNED_BASELINE_REPORT",
            "declared_rows": len(output), "status_counts": {"OPEN": len(output)},
            "engineering_complete": False,
            "limits": "Validates declared-row coverage only. Does not run tests, accept evidence, "
                "assert universal completeness or promote any obligation to MET.", "rows": output}


def parity(inputs, reference=ROOT, *, layout="reference"):
    if layout not in {"reference", "upstream"}:
        raise ValueError("Source layout must be reference or upstream")
    inventory = json.loads(inputs["source-inventory.json"])
    draft = json.loads(inputs["exclusions-DRAFT-unsigned.json"])
    proposals = {item["path"]: item for item in draft["exclusions"]}
    rows = []
    seen = set()
    for entry in inventory["files"]:
        name = entry["source_path"]
        if name in seen:
            raise ValueError(f"Duplicate inventory path: {name}")
        seen.add(name)
        checked_path = entry["reference_path"] if layout == "reference" else name
        path = confined_file(reference, checked_path)
        actual = sha(path.read_bytes()) if path.is_file() else None
        state = "ABSENT" if actual is None else (
            "BYTE_IDENTICAL" if actual == entry["sha256"] else "DIFF_REQUIRES_REVIEW")
        rows.append({**entry, "checked_path": checked_path,
                     "actual_sha256": actual, "file_status": state,
                     "proposed_exclusion": proposals.get(name), "exclusion_applied": False,
                     "integration_verdict": None})
    if set(proposals) - seen:
        raise ValueError("Proposed exclusion missing from inventory")
    return {"schema": "executable-assurance/parity-report/v1",
            "scope_lock_sha256": LOCK_SHA256, "source_commit": inventory["source_commit"],
            "source_layout": layout,
            "inventory_scope": inventory["scope"], "declared_files": len(rows),
            "file_counts": dict(Counter(row["file_status"] for row in rows)),
            "applied_exclusions": 0, "authority_parity_established": False,
            "limits": "File comparison only; adaptations remain review-required. "
                "Neither source presence nor signed-looking text proves integration or owner approval. "
                "All draft exclusions remain in the inventory.", "rows": rows}


def markdown_report(report):
    lines = ["# " + report["schema"], "", report["limits"], ""]
    for row in report["rows"]:
        lines += ["## " + row.get("id", row.get("source_path", "")), "",
                  "```json", json.dumps(row, indent=2, ensure_ascii=False), "```", ""]
    return "\n".join(lines)
