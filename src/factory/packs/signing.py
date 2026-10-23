"""Two attestations every pack carries: the files signature and the build provenance.

* ``.signatures.json`` follows the OPA bundle discipline: a signed list of every shipped file with
  its digest, the signer's key id and a scope; verification checks the signature, that the list
  matches the bundle exactly, and that every digest matches. A pack that fails any of the three is
  refused before its policy is read.
* ``provenance.json`` follows SLSA / in-toto: a statement whose ``subject`` is the pack's digest and
  whose predicate names the ``builder`` and the ``buildType``, so the platform knows how the pack
  was produced, not only who signed it.

Signatures use the platform's own Ed25519 signer and trust directory (``regulated_core.signing``):
a pack publisher is a registered identity, and a pack signed by an unknown key is an unknown pack.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from regulated_core.signing import Signature, Signer, TrustDirectory

from .manifest import PackManifest, file_digest

SIGNATURE_SCHEMA = "lumiwright.pack-signature/v1"
PROVENANCE_TYPE = "https://in-toto.io/Statement/v1"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"


class SignatureError(ValueError):
    """The pack's signature or provenance does not verify; the message says which check failed."""


def signed_files_body(manifest: PackManifest, *, scope: str) -> dict[str, Any]:
    files = [{"name": "pack.json", "hash": manifest.digest, "algorithm": "SHA256"}]
    files += [{"name": name, "hash": digest, "algorithm": "SHA256"} for name, digest in sorted(manifest.files.items())]
    return {"schema": SIGNATURE_SCHEMA, "pack": manifest.reference, "scope": scope, "files": files}


def sign_pack(pack_dir: Path, manifest: PackManifest, signer: Signer, *, scope: str = "install") -> Path:
    """Write ``.signatures.json`` for the pack as it is on disk."""
    body = signed_files_body(manifest, scope=scope)
    signature = signer.sign(body)
    payload = {**body, "signature": {"key_id": signature.key_id, "alg": signature.alg, "value": signature.value}}
    target = pack_dir / ".signatures.json"
    target.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    return target


@dataclass(frozen=True, slots=True)
class VerifiedSignature:
    key_id: str
    scope: str
    file_count: int


def verify_pack_signature(pack_dir: Path, manifest: PackManifest, trust: TrustDirectory, *,
                          expected_scope: str = "install",
                          publisher_key_id: str | None = None) -> VerifiedSignature:
    """The three OPA checks, in order: the signature, the file list, the digests."""
    path = pack_dir / ".signatures.json"
    if not path.is_file():
        raise SignatureError("the pack is unsigned (.signatures.json is missing)")
    raw = json.loads(path.read_text(encoding="utf-8"))
    sig = raw.get("signature") or {}
    body = {k: v for k, v in raw.items() if k != "signature"}
    signature = Signature(key_id=str(sig.get("key_id", "")), value=str(sig.get("value", "")), alg=str(sig.get("alg", "")))
    if publisher_key_id is not None and signature.key_id != publisher_key_id:
        raise SignatureError(f"signed by {signature.key_id!r}, not the declared publisher key {publisher_key_id!r}")
    if not trust.verify(body, signature):
        raise SignatureError(f"signature by {signature.key_id!r} does not verify against the trust directory")
    if body.get("schema") != SIGNATURE_SCHEMA or body.get("pack") != manifest.reference:
        raise SignatureError("the signature names a different pack or schema")
    if body.get("scope") != expected_scope:
        raise SignatureError(f"signature scope {body.get('scope')!r} is not {expected_scope!r}")
    expected = signed_files_body(manifest, scope=expected_scope)["files"]
    if body.get("files") != expected:
        raise SignatureError("the signed file list does not match the pack's content index exactly")
    for entry in expected:
        if entry["name"] == "pack.json":
            continue
        actual = file_digest((pack_dir / entry["name"]).read_bytes())
        if actual != entry["hash"]:
            raise SignatureError(f"digest mismatch for {entry['name']}")
    return VerifiedSignature(signature.key_id, str(body["scope"]), len(expected))


def write_provenance(pack_dir: Path, manifest: PackManifest, *, builder_id: str, build_type: str,
                     external_parameters: dict[str, Any], signer: Signer) -> Path:
    """An in-toto statement over the pack digest with a SLSA-shaped predicate, signed."""
    statement = {
        "_type": PROVENANCE_TYPE,
        "subject": [{"name": manifest.reference, "digest": {"sha256": manifest.digest}}],
        "predicateType": PROVENANCE_PREDICATE,
        "predicate": {
            "buildDefinition": {"buildType": build_type, "externalParameters": external_parameters,
                                "resolvedDependencies": [{"name": d} for d in manifest.dependencies]},
            "runDetails": {"builder": {"id": builder_id}},
        },
    }
    signature = signer.sign(statement)
    payload = {"statement": statement,
               "signature": {"key_id": signature.key_id, "alg": signature.alg, "value": signature.value}}
    target = pack_dir / "provenance.json"
    target.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    return target


@dataclass(frozen=True, slots=True)
class VerifiedProvenance:
    builder_id: str
    build_type: str
    signer_key_id: str


def verify_provenance(pack_dir: Path, manifest: PackManifest, trust: TrustDirectory) -> VerifiedProvenance:
    path = pack_dir / "provenance.json"
    if not path.is_file():
        raise SignatureError("the pack carries no provenance (provenance.json is missing)")
    raw = json.loads(path.read_text(encoding="utf-8"))
    statement, sig = raw.get("statement") or {}, raw.get("signature") or {}
    signature = Signature(key_id=str(sig.get("key_id", "")), value=str(sig.get("value", "")), alg=str(sig.get("alg", "")))
    if not trust.verify(statement, signature):
        raise SignatureError("provenance signature does not verify")
    if statement.get("_type") != PROVENANCE_TYPE or statement.get("predicateType") != PROVENANCE_PREDICATE:
        raise SignatureError("provenance is not an in-toto/SLSA statement")
    subjects = statement.get("subject") or []
    if not any(s.get("name") == manifest.reference and (s.get("digest") or {}).get("sha256") == manifest.digest
               for s in subjects):
        raise SignatureError("provenance subject does not name this pack's digest")
    predicate = statement.get("predicate") or {}
    builder = str(((predicate.get("runDetails") or {}).get("builder") or {}).get("id", ""))
    build_type = str((predicate.get("buildDefinition") or {}).get("buildType", ""))
    if not builder or not build_type:
        raise SignatureError("provenance names no builder or build type")
    return VerifiedProvenance(builder, build_type, signature.key_id)


__all__ = ["PROVENANCE_PREDICATE", "PROVENANCE_TYPE", "SIGNATURE_SCHEMA", "SignatureError", "VerifiedProvenance",
           "VerifiedSignature", "sign_pack", "signed_files_body", "verify_pack_signature", "verify_provenance",
           "write_provenance"]
