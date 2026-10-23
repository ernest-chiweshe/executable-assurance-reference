"""Derive the deployment effect inventory from the code (approved plan D2; Paper A section 3).

An effect is a change or disclosure at a named boundary. Paper A requires the inventory for a deployment to be
complete and demonstrated by inspection, never assumed; D2 adds that an authoritative internal write is not
exempt merely because it is internal or has no `RegulatedBlock`. So the inventory is DERIVED here from the
syntax tree of every module, never kept as a hand-written parallel list, and
`docs/ARCHITECTURE-OF-RECORD/effect-boundaries.json` classifies every file that has an effect site. The test
`tests/test_c1_effect_inventory.py` fails when a file gains an effect site no rule classifies.

Detected effect kinds, each mapped to a Paper A section 3 effect:

* ``network``: an outbound request or message (urllib, requests, httpx, http.client, smtplib, sockets).
* ``cloud``: a cloud SDK client (boto3); the service decides the effect (message, storage, compute, key use).
* ``process``: starting a process (subprocess, os.system, asyncio subprocesses): compute allocation and, for
  package managers, software installation.
* ``database``: a SQL statement that changes state (INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, TRUNCATE).
* ``file``: a filesystem write, move or delete.

This is a static first line of evidence. It over-approximates (a helper that is never called still counts)
and cannot see dynamic dispatch, so coverage is also demonstrated by bypass tests at each boundary.

Usage: ``python -m scripts.effect_inventory [--json]`` prints the per-file inventory.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("factory", "regulated_core")
KINDS = ("network", "cloud", "process", "database", "file")

_NETWORK_CALLS = re.compile(
    r"^(urllib\.request\.urlopen|urlopen|requests\.(get|post|put|patch|delete|request|head)|"
    r"httpx\.(get|post|put|patch|delete|request|stream|Client|AsyncClient)|http\.client\.HTTPS?Connection|"
    r"HTTPS?Connection|smtplib\.SMTP(_SSL)?|SMTP(_SSL)?|socket\.create_connection|websockets\.connect|"
    r"aiohttp\.ClientSession)$")
_CLOUD_CALLS = re.compile(r"^(boto3\.(client|resource)|boto3\.session\.Session|Session\(\)\.client)$")
_PROCESS_CALLS = re.compile(
    r"^(subprocess\.(run|Popen|call|check_call|check_output)|os\.(system|popen|exec\w*|spawn\w*)|"
    r"asyncio\.create_subprocess_(exec|shell)|Popen)$")
_FILE_CALLS = re.compile(
    r"^(os\.(replace|rename|remove|unlink|rmdir|makedirs|mkdir|symlink|link|chmod)|"
    r"shutil\.(copy\w*|move|rmtree)|tempfile\.mkdtemp)$")
_FILE_METHODS = frozenset({"write_text", "write_bytes", "unlink", "rename", "replace", "rmdir", "mkdir",
                           "touch", "symlink_to", "hardlink_to"})
_SQL_CHANGE = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+(TABLE|INDEX|SCHEMA|"
                         r"UNIQUE|EXTENSION|OR)|DROP\s+(TABLE|INDEX|SCHEMA)|ALTER\s+TABLE|TRUNCATE\b)", re.I)
_WRITE_MODES = re.compile(r"[wax+]")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func) + "()"
    return ""


def _open_writes(call: ast.Call) -> bool:
    """`open(path, mode)` or `path.open(mode)` with a writing mode."""
    mode: ast.expr | None = None
    positional = call.args[1:] if isinstance(call.func, ast.Name) else call.args[:1]
    if positional:
        mode = positional[0]
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = kw.value
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and bool(_WRITE_MODES.search(mode.value))


def _aliases(tree: ast.AST) -> dict[str, set[str]]:
    """Every name bound by an import anywhere in the module, mapped to EVERY target it is bound to.

    `import requests as r` gives r -> {requests} and `from subprocess import run` gives run -> {subprocess.run}.
    A name bound in several scopes keeps all of its bindings, so an unrelated inner `import json as r` cannot
    hide an outer `r.post(...)`: a call is an effect if ANY binding of its name makes it one (over-approximate)."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out.setdefault(alias.asname, set()).add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                out.setdefault(alias.asname or alias.name, set()).add(f"{node.module}.{alias.name}")
    return out


def _candidates(name: str, aliases: dict[str, set[str]]) -> list[str]:
    """The written name and every name it can resolve to through an import binding."""
    head, _, rest = name.partition(".")
    resolved = sorted(f"{t}.{rest}" if rest else t for t in aliases.get(head, ()))
    return [name, *resolved]


def _call_site(node: ast.Call, names: list[str]) -> tuple[str, str] | None:
    """The effect kind of a call, trying the written name and each of its import bindings in turn."""
    for name in names:
        short = name.rsplit(".", 1)[-1]
        if _NETWORK_CALLS.match(name):
            return "network", name
        if _CLOUD_CALLS.match(name):
            first = node.args[0] if node.args else None
            service = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else "?"
            return "cloud", f"{name}({service})"
        if _PROCESS_CALLS.match(name):
            return "process", name
        if _FILE_CALLS.match(name) or (isinstance(node.func, ast.Attribute) and short in _FILE_METHODS):
            return "file", name
        if short == "open" and _open_writes(node):
            return "file", f"{name}(write)"
    return None


def sites(source: str) -> list[tuple[str, int, str]]:
    """Every effect site in one module: (kind, line, what)."""
    found: list[tuple[str, int, str]] = []
    tree = ast.parse(source)
    aliases = _aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            site = _call_site(node, _candidates(_dotted(node.func), aliases))
            if site is not None:
                found.append((site[0], node.lineno, site[1]))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = _SQL_CHANGE.search(node.value)
            if match:
                found.append(("database", node.lineno, " ".join(match.group(0).split()[:2]).upper()))
    return sorted(found)


def module_files(root: Path = ROOT) -> Iterable[Path]:
    for package in PACKAGES:
        yield from sorted((root / package).rglob("*.py"))


def inventory(root: Path = ROOT) -> dict[str, dict[str, int]]:
    """Per repository-relative file, the count of effect sites by kind. Files without effects are omitted."""
    out: dict[str, dict[str, int]] = {}
    for path in module_files(root):
        counts = Counter(kind for kind, _line, _what in sites(path.read_text(encoding="utf-8")))
        if counts:
            out[path.relative_to(root).as_posix()] = {k: counts[k] for k in KINDS if counts[k]}
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = parser.parse_args(argv)
    inv = inventory()
    if args.json:
        json.dump(inv, sys.stdout, indent=1, sort_keys=True)
        print()
        return 0
    totals: Counter[str] = Counter()
    for counts in inv.values():
        totals.update(counts)
    print(f"{len(inv)} files with effect sites; " + ", ".join(f"{k} {totals[k]}" for k in KINDS))
    for path, counts in sorted(inv.items()):
        print(f"{path}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
