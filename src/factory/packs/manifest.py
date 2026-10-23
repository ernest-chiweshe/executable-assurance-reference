"""The pack manifest: identity, kind, compatibility, dependencies, roots, files, scopes, and the declarations.

Modelled on the FHIR NPM ``package.json`` (dotted lowercase ids, semantic versions, ``id#version``
references, declared platform versions and dependencies), the OPA ``.manifest`` (``revision``,
``roots`` that a bundle OWNS with no overlap, a content index) and the NIEM package description
(identity, purpose, lineage, explicit conformance targets). The research's three-layer separation
is the ``kind``: a ``base`` pack carries the reusable domain semantics; a ``profile`` tailors a base
for a sector; an ``overlay`` localises a base for a jurisdiction or organization and may only tighten
it (see ``rulebook.apply_overlay``). Every declaration a pack makes is a named section here; the
module that acts on a section validates it further.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import PACK_SCHEMA, PLATFORM_CONTRACT

_PACK_ID = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*){2,}$")      # publisher.domain.pack, like hl7.fhir.us.core
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$")
_ROOT = re.compile(r"^[a-z][a-z0-9-]*(/[a-z][a-z0-9-]*)*$")
_DOMAIN = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_JURISDICTION = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$|^global$")
_ROLE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_SCOPE_CLASSES = {"public", "internal", "confidential", "pii", "phi", "financial", "pci"}
_REF = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*){2,}#(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
KINDS = ("base", "profile", "overlay")
UNINDEXED = ("pack.json", ".signatures.json", "provenance.json")


class ManifestError(ValueError):
    """The manifest does not satisfy the schema; the problems list names every defect."""


def _digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def file_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class Scope:
    """One data or capability request with its rationale (minimum necessary, as an app review asks)."""

    name: str
    data_class: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "data_class": self.data_class, "rationale": self.rationale}


@dataclass(frozen=True, slots=True)
class PackManifest:
    id: str
    version: str
    kind: str
    domain: str
    title: str
    publisher: str
    platform_contract: str
    jurisdictions: tuple[str, ...]
    license: str
    roots: tuple[str, ...]                         # namespaces this pack owns (policy, data, collections)
    files: Mapping[str, str]                       # relative path -> sha256 (the content index)
    capability: str                                # the meterable entitlement name this pack sells; no price, no authority
    scopes: tuple[Scope, ...]
    dependencies: tuple[str, ...] = ()             # id#version references to other packs (an overlay's base among them)
    vocabularies: tuple[str, ...] = ()             # external standards used, name@edition, each locked in knowledge.sources
    required_expert_roles: tuple[str, ...] = ()    # roles whose attestation the expert-validated level needs
    sections: Mapping[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": PACK_SCHEMA, "id": self.id, "version": self.version, "kind": self.kind, "domain": self.domain,
            "title": self.title, "publisher": self.publisher, "platform_contract": self.platform_contract,
            "jurisdictions": list(self.jurisdictions), "license": self.license, "roots": list(self.roots),
            "files": dict(sorted(self.files.items())), "capability": self.capability,
            "scopes": [s.to_dict() for s in self.scopes], "dependencies": list(self.dependencies),
            "vocabularies": list(self.vocabularies), "experts": {"required_roles": list(self.required_expert_roles)},
            **{k: self.sections[k] for k in sorted(self.sections)},
        }

    @property
    def digest(self) -> str:
        return _digest(self.canonical())

    @property
    def reference(self) -> str:
        return f"{self.id}#{self.version}"

    @property
    def base(self) -> str | None:
        """For an overlay or profile, the base pack reference it tailors (its first dependency)."""
        return self.dependencies[0] if self.kind != "base" and self.dependencies else None

    def section(self, name: str) -> Any:
        return self.sections.get(name)


SECTIONS = ("workflow", "rulebook", "collections", "cards", "conformance", "knowledge", "commercial")


def validate_manifest(raw: Any) -> list[str]:
    """Every defect, not the first."""
    if not isinstance(raw, dict):
        return ["manifest must be an object"]
    p: list[str] = []
    if raw.get("schema") != PACK_SCHEMA:
        p.append(f"schema must be {PACK_SCHEMA}")
    pack_id = raw.get("id")
    if not isinstance(pack_id, str) or not _PACK_ID.fullmatch(pack_id):
        p.append("id must be dotted lowercase publisher.domain.pack (like hl7.fhir.us.core)")
    if not isinstance(raw.get("version"), str) or not _SEMVER.fullmatch(raw["version"]):
        p.append("version must be a semantic version")
    kind = raw.get("kind", "base")
    if kind not in KINDS:
        p.append(f"kind must be one of {list(KINDS)}")
    if not isinstance(raw.get("domain"), str) or not _DOMAIN.fullmatch(raw["domain"]):
        p.append("domain must be a lowercase domain identifier")
    for key in ("title", "publisher", "license", "capability"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            p.append(f"{key} is required")
    if raw.get("platform_contract") != PLATFORM_CONTRACT:
        p.append(f"platform_contract must be {PLATFORM_CONTRACT} (this platform); got {raw.get('platform_contract')!r}")
    juris = raw.get("jurisdictions")
    if not isinstance(juris, list) or not juris or any(not isinstance(j, str) or not _JURISDICTION.fullmatch(j) for j in juris):
        p.append("jurisdictions must be a non-empty list of ISO country codes (optionally -region) or 'global'")
    roots = raw.get("roots")
    if not isinstance(roots, list) or not roots or any(not isinstance(r, str) or not _ROOT.fullmatch(r) for r in roots):
        p.append("roots must be a non-empty list of namespace paths the pack owns")
    else:
        for a in roots:
            for b in roots:
                if a != b and (b.startswith(a + "/") or a == b):
                    p.append(f"roots overlap: {a!r} contains {b!r}")
    files = raw.get("files")
    if not isinstance(files, dict) or not files or any(
            not isinstance(k, str) or not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in files.items()):
        p.append("files must map every shipped path to its sha256")
    elif any(name in files for name in UNINDEXED):
        p.append("files must not index the manifest, the signature or the provenance")
    scopes = raw.get("scopes")
    if not isinstance(scopes, list):
        p.append("scopes must be a list (empty when the pack reads nothing)")
    else:
        for s in scopes:
            if not isinstance(s, dict) or not str(s.get("name", "")).strip() or s.get("data_class") not in _SCOPE_CLASSES \
                    or len(str(s.get("rationale", "")).strip()) < 12:
                p.append(f"scope {s!r}: needs name, a data_class in {sorted(_SCOPE_CLASSES)} and a rationale (minimum necessary)")
    deps = raw.get("dependencies", ()) or ()
    for dep in deps:
        if not isinstance(dep, str) or not _REF.fullmatch(dep):
            p.append(f"dependency {dep!r} must be id#version")
    if kind in ("overlay", "profile") and not deps:
        p.append(f"a {kind} pack must depend on the base pack it tailors (first dependency)")
    for vocab in raw.get("vocabularies", ()) or ():
        if not isinstance(vocab, str) or "@" not in vocab:
            p.append(f"vocabulary {vocab!r} must be name@edition (case@1.0, oneroster@1.2, fhir.us.core@6.1.0)")
    experts = raw.get("experts", {"required_roles": []})
    roles = experts.get("required_roles") if isinstance(experts, dict) else None
    if not isinstance(roles, list) or any(not isinstance(r, str) or not _ROLE.fullmatch(r) for r in roles):
        p.append("experts.required_roles must be a list of lowercase role identifiers (empty only for a demo pack)")
    for name in ("workflow", "rulebook", "conformance", "knowledge"):
        if not isinstance(raw.get(name), dict):
            p.append(f"{name} section is required")
    knowledge = raw.get("knowledge")
    if isinstance(knowledge, dict) and not isinstance(knowledge.get("sources"), list):
        p.append("knowledge.sources must be a list of locked sources")
    for name in ("collections", "cards", "commercial"):
        if name in raw and not isinstance(raw[name], (dict, list)):
            p.append(f"{name} section must be an object or a list")
    commercial = raw.get("commercial")
    if isinstance(commercial, dict) and any(k in commercial for k in ("price", "prices", "authority", "grants")):
        p.append("commercial may name meterable capabilities only: no price and no authority grant travels in a pack")
    return p


def manifest_from_dict(raw: Mapping[str, Any]) -> PackManifest:
    problems = validate_manifest(dict(raw))
    if problems:
        raise ManifestError("; ".join(problems))
    experts = raw.get("experts") or {}
    return PackManifest(
        id=str(raw["id"]), version=str(raw["version"]), kind=str(raw.get("kind", "base")), domain=str(raw["domain"]),
        title=str(raw["title"]), publisher=str(raw["publisher"]), platform_contract=str(raw["platform_contract"]),
        jurisdictions=tuple(str(j) for j in raw["jurisdictions"]), license=str(raw["license"]),
        roots=tuple(str(r) for r in raw["roots"]), files=dict(raw["files"]), capability=str(raw["capability"]),
        scopes=tuple(Scope(str(s["name"]), str(s["data_class"]), str(s["rationale"])) for s in raw["scopes"]),
        dependencies=tuple(str(d) for d in raw.get("dependencies", ()) or ()),
        vocabularies=tuple(str(v) for v in raw.get("vocabularies", ()) or ()),
        required_expert_roles=tuple(str(r) for r in experts.get("required_roles", ()) or ()),
        sections={k: raw[k] for k in SECTIONS if k in raw},
    )


def load_manifest(pack_dir: Path) -> PackManifest:
    """Read ``pack.json`` and check the content index against the files actually shipped: a file that
    is missing, unlisted or changed refuses the pack before anything else is read."""
    path = pack_dir / "pack.json"
    if not path.is_file():
        raise ManifestError(f"{pack_dir}: pack.json is missing")
    manifest = manifest_from_dict(json.loads(path.read_text(encoding="utf-8")))
    problems: list[str] = []
    for rel, digest in manifest.files.items():
        target = pack_dir / rel
        if not target.is_file():
            problems.append(f"indexed file missing: {rel}")
        elif file_digest(target.read_bytes()) != digest:
            problems.append(f"indexed file changed: {rel}")
    shipped = {str(f.relative_to(pack_dir)).replace("\\", "/") for f in pack_dir.rglob("*") if f.is_file()}
    for rel in sorted(shipped - set(manifest.files) - set(UNINDEXED)):
        if not rel.endswith((".pyc",)) and "__pycache__" not in rel:
            problems.append(f"shipped file not indexed: {rel}")
    if problems:
        raise ManifestError("; ".join(problems))
    return manifest


__all__ = ["KINDS", "ManifestError", "PackManifest", "SECTIONS", "Scope", "UNINDEXED", "file_digest", "load_manifest",
           "manifest_from_dict", "validate_manifest"]
