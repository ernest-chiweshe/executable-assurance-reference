"""Expert attestations: who reviewed which semantic surface of a pack, when, under what credential.

The research separates three facts a signed tarball collapses: the publisher's files signature, the
build provenance, and the *expert's semantic approval* (bundle anatomy ``trust/expert-attestations/``;
"signing a tarball does not make its semantics correct; expert approval does not prove its software
provenance"). An attestation here is a signed statement by a registered expert identity over ONE
surface digest (the rulebook, the schema, the kit, the sources lock or the workflow) with the
expert's role, credential, issuer, review date and expiry. Conformance level "expert validated" is
reached only when every role the manifest requires has a valid, unexpired attestation over the
rulebook as it is now; a rulebook edit invalidates the attestation by digest, not by policy.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from regulated_core.signing import Signature, Signer, TrustDirectory

ATTESTATION_SCHEMA = "lumiwright.expert-attestation/v1"
SURFACES = ("rulebook", "schema", "kit", "sources", "workflow")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ROLE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


class AttestationError(ValueError):
    """An attestation file is malformed."""


@dataclass(frozen=True, slots=True)
class ExpertAttestation:
    pack: str                                   # the pack id (not the version: the surface digest carries currency)
    surface: str
    surface_digest: str
    expert_name: str
    expert_role: str
    credential: str
    credential_issuer: str
    reviewed_at: str
    expires_at: str
    findings: tuple[str, ...]
    signature: Signature

    def body(self) -> dict[str, Any]:
        return {"schema": ATTESTATION_SCHEMA, "pack": self.pack, "surface": self.surface,
                "surface_digest": self.surface_digest, "expert": {"name": self.expert_name, "role": self.expert_role,
                                                                  "credential": self.credential, "issuer": self.credential_issuer},
                "reviewed_at": self.reviewed_at, "expires_at": self.expires_at, "findings": list(self.findings)}

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": {"key_id": self.signature.key_id, "alg": self.signature.alg,
                                             "value": self.signature.value}}


def sign_attestation(signer: Signer, *, pack: str, surface: str, surface_digest: str, expert_name: str, expert_role: str,
                     credential: str, credential_issuer: str, reviewed_at: str, expires_at: str,
                     findings: Iterable[str] = ()) -> ExpertAttestation:
    if surface not in SURFACES:
        raise AttestationError(f"surface must be one of {list(SURFACES)}")
    if not _ROLE.fullmatch(expert_role):
        raise AttestationError("expert_role must be a lowercase identifier")
    if not (_DATE.fullmatch(reviewed_at) and _DATE.fullmatch(expires_at)) or expires_at <= reviewed_at:
        raise AttestationError("reviewed_at and expires_at must be ISO dates with expiry after review")
    draft = ExpertAttestation(pack, surface, surface_digest, expert_name, expert_role, credential, credential_issuer,
                              reviewed_at, expires_at, tuple(findings), Signature(key_id="", value="", alg=""))
    return ExpertAttestation(pack, surface, surface_digest, expert_name, expert_role, credential, credential_issuer,
                             reviewed_at, expires_at, tuple(findings), signer.sign(draft.body()))


def attestation_from_dict(raw: Mapping[str, Any]) -> ExpertAttestation:
    try:
        expert = raw["expert"]
        sig = raw["signature"]
        return ExpertAttestation(str(raw["pack"]), str(raw["surface"]), str(raw["surface_digest"]), str(expert["name"]),
                                 str(expert["role"]), str(expert["credential"]), str(expert["issuer"]), str(raw["reviewed_at"]),
                                 str(raw["expires_at"]), tuple(str(f) for f in raw.get("findings", ())),
                                 Signature(key_id=str(sig["key_id"]), value=str(sig["value"]), alg=str(sig["alg"])))
    except (KeyError, TypeError) as exc:
        raise AttestationError(f"attestation is malformed: {exc}") from exc


def write_attestation(pack_dir: Path, attestation: ExpertAttestation) -> Path:
    target = pack_dir / "trust" / "attestations" / f"{attestation.expert_role}.{attestation.surface}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation.to_dict(), sort_keys=True, indent=2), encoding="utf-8")
    return target


def load_attestations(pack_dir: Path) -> tuple[ExpertAttestation, ...]:
    folder = pack_dir / "trust" / "attestations"
    if not folder.is_dir():
        return ()
    return tuple(attestation_from_dict(json.loads(p.read_text(encoding="utf-8"))) for p in sorted(folder.glob("*.json")))


def verify_attestation(trust: TrustDirectory, attestation: ExpertAttestation, *, pack_id: str,
                       surface_digests: Mapping[str, str], today: str) -> list[str]:
    """Every reason the attestation does not count, or an empty list."""
    p: list[str] = []
    if attestation.body().get("schema") != ATTESTATION_SCHEMA:
        p.append("schema mismatch")
    if not trust.verify(attestation.body(), attestation.signature):
        p.append(f"signature by {attestation.signature.key_id!r} does not verify against the trust directory")
    if attestation.pack != pack_id:
        p.append(f"attests {attestation.pack!r}, not {pack_id!r}")
    current = surface_digests.get(attestation.surface)
    if current is None:
        p.append(f"surface {attestation.surface!r} is not one this pack exposes")
    elif current != attestation.surface_digest:
        p.append(f"{attestation.surface} changed since review (attested {attestation.surface_digest[:12]}, now {current[:12]})")
    if not _DATE.fullmatch(today) or attestation.expires_at < today:
        p.append(f"expired {attestation.expires_at}")
    return p


def coverage(attestations: Iterable[ExpertAttestation], *, required_roles: Iterable[str], trust: TrustDirectory,
             pack_id: str, surface_digests: Mapping[str, str], today: str,
             surfaces_required: tuple[str, ...] = ("rulebook",)) -> dict[str, str]:
    """Per required role: ``ok: <name> until <date>`` or the reason the role is uncovered."""
    atts = tuple(attestations)
    result: dict[str, str] = {}
    for role in required_roles:
        mine = [a for a in atts if a.expert_role == role]
        if not mine:
            result[role] = "no attestation"
            continue
        reasons: list[str] = []
        covered: list[str] = []
        for surface in surfaces_required:
            valid = [a for a in mine if a.surface == surface and not verify_attestation(trust, a, pack_id=pack_id,
                                                                                         surface_digests=surface_digests, today=today)]
            if valid:
                covered.append(f"{surface} by {valid[0].expert_name} until {valid[0].expires_at}")
            else:
                found = [a for a in mine if a.surface == surface]
                reasons.append(f"{surface}: " + ("; ".join(verify_attestation(trust, found[0], pack_id=pack_id,
                                                                               surface_digests=surface_digests, today=today))
                                                 if found else "no attestation"))
        result[role] = ("ok: " + "; ".join(covered)) if not reasons else "; ".join(reasons)
    return result


__all__ = ["ATTESTATION_SCHEMA", "SURFACES", "AttestationError", "ExpertAttestation", "attestation_from_dict", "coverage",
           "load_attestations", "sign_attestation", "verify_attestation", "write_attestation"]
