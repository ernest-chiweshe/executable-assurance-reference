"""Host-configured public policy loading and historical observations.

Derived from the retained care composition; no care service or operational
authority is returned by historical lookup. Current gates remain separate.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from regulated_core.policy_document import PolicyDocument, verify_document
from regulated_core.signing import Signature, TrustDirectory

TRUST_SCHEMA = "care/trust-keys/v1"  # Preserve the frozen public trust-file format.


class PolicyLoadRefused(ValueError):
    """The explicit host policy binding could not be verified."""


def _object(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PolicyLoadRefused("policy input could not be read") from error
    if not isinstance(raw, dict):
        raise PolicyLoadRefused("policy input must be an object")
    return raw


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyLoadRefused("policy identity must be nonempty text")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PolicyLoadRefused("policy pin must be a lowercase SHA256 digest")
    return value


def public_trust_from_file(path: Path) -> TrustDirectory:
    """Read separately configured public keys; no document supplies trust."""
    raw = _object(path)
    entries = raw.get("keys")
    if raw.get("schema") != TRUST_SCHEMA or not isinstance(entries, list) or not entries:
        raise PolicyLoadRefused("public trust file has no valid key list")
    trust = TrustDirectory()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {"key_id", "public_key_hex", "alg"}:
            raise PolicyLoadRefused("trust entry must contain public key fields only")
        try:
            trust.register(_text(entry["key_id"]), bytes.fromhex(_text(entry["public_key_hex"])),
                           _text(entry.get("alg", "ed25519")))
        except (KeyError, ValueError, TypeError) as error:
            raise PolicyLoadRefused("public trust entry is invalid") from error
    return trust


def _document(path: Path) -> PolicyDocument:
    raw = _object(path)
    try:
        if raw.get("schema") != "regulated/policy-document/v1":
            raise PolicyLoadRefused("policy document schema is unsupported")
        content, signature = raw["content"], raw["signature"]
        jurisdictions = raw.get("jurisdictions", [])
        start, end = raw["effective_from_us"], raw.get("effective_until_us", 0)
        if (not isinstance(content, dict) or not isinstance(signature, dict)
                or not isinstance(jurisdictions, list)
                or any(not isinstance(item, str) for item in jurisdictions)
                or type(start) is not int or type(end) is not int
                or start < 0 or end < 0 or (end != 0 and end <= start)):
            raise PolicyLoadRefused("policy document fields are invalid")
        supersedes = raw.get("supersedes", "")
        if supersedes:
            _digest(supersedes)
        elif supersedes != "":
            raise PolicyLoadRefused("supersedes must be text")
        doc = PolicyDocument(
            vertical=_text(raw["vertical"]), policy_id=_text(raw["policy_id"]),
            version=_text(raw["version"]), content=content,
            jurisdictions=tuple(jurisdictions), effective_from_us=start, effective_until_us=end,
            issued_by=_text(raw["issued_by"]), supersedes=supersedes,
            signature=Signature(_text(signature["key_id"]), _text(signature["value"]),
                                _text(signature.get("alg", "ed25519"))))
        if "digest" in raw and raw["digest"] != doc.digest():
            raise PolicyLoadRefused("serialized document digest does not match")
        return doc
    except (KeyError, TypeError, ValueError) as error:
        raise PolicyLoadRefused("policy document is invalid") from error


@dataclass(frozen=True)
class PolicyFileLoader:
    """Explicit host identity and external trust; no environment fallback."""

    trust_path: Path
    vertical: str
    policy_id: str
    authority: str

    def __post_init__(self):
        for value in (self.vertical, self.policy_id, self.authority):
            _text(value)

    def load(self, path: Path, *, at_us: int,
             document_digest: str | None = None) -> PolicyDocument:
        if type(at_us) is not int or at_us < 0:
            raise PolicyLoadRefused("observation time must be nonnegative microseconds")
        if document_digest is not None:
            _digest(document_digest)
        document = _document(path)
        trust = public_trust_from_file(self.trust_path)
        if (not verify_document(trust, document, authority=self.authority)
                or document.issued_by != self.authority):
            raise PolicyLoadRefused("policy signing authority is not trusted")
        if document.vertical != self.vertical or document.policy_id != self.policy_id:
            raise PolicyLoadRefused("policy identity differs from host configuration")
        if not document.effective_at(at_us):
            raise PolicyLoadRefused("policy is outside its effective window")
        if document_digest is not None and document.digest() != document_digest:
            raise PolicyLoadRefused("policy document differs from host pin")
        return document


@dataclass(frozen=True)
class ContentIdentity:
    """Application-derived content identity, distinct from signed-document digest."""

    digest: str
    version: str

    def __post_init__(self):
        _digest(self.digest)
        _text(self.version)


@dataclass(frozen=True)
class HistoricalPolicyObservation:
    """Immutable evidence only; not a policy document or current release gate."""

    vertical: str
    policy_id: str
    version: str
    observed_at_us: int
    document_digest: str
    content_digest: str
    content_json: str


def observe_historical_policy(
    loader: PolicyFileLoader, *, archive: Path, expected: ContentIdentity,
    at_us: int, identify_content: Callable[[dict], ContentIdentity],
    document_digest: str | None = None,
) -> HistoricalPolicyObservation:
    """Resolve an exact content pin at its recorded time; never select latest.

    identify_content is a host-owned application parser, not code or a digest
    algorithm selected by the document. It must preserve that application's
    original content/version semantics, such as care's RoutingPolicy digest.
    """
    # Revalidate the pin at the file-selection boundary.
    pin = _digest(expected.digest)
    document = loader.load(archive / (pin + ".signed.json"), at_us=at_us,
                           document_digest=document_digest)
    content_json = json.dumps(document.content, sort_keys=True, separators=(",", ":"), allow_nan=False)
    # Give the application parser a separate JSON value, preserving the verified snapshot.
    actual = identify_content(json.loads(content_json))
    if actual != expected or document.version != expected.version:
        raise PolicyLoadRefused("historical application content or version differs from pin")
    return HistoricalPolicyObservation(
        document.vertical, document.policy_id, document.version, at_us,
        document.digest(), pin, content_json)
