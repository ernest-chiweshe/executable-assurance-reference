"""Certificate credentials for the deployed clinical door: the provider every stricter profile needs (ledger 3894).

A doctor starts on workspace membership; a hospital on institutional attestation; a regulator on a professional
register; a demonstration on a clearly labelled test authority (docs/ARCHITECTURE-OF-RECORD/10). The deployed door
refuses to START on any profile but membership unless a credential provider is composed, and until now none was, so
every stricter profile was unusable in a deployment. This module is that provider.

* Issuers are the INSTALLATION'S declaration (``FACTORY_HEALTH_CLINICAL_ISSUERS``: ``[{"key_id", "kind"}]``). Each
  key must already be a trust anchor of the host; the kind a certificate yields is its issuer's registration, never
  the certificate's claim (regulated_core/certificates.py), so a demonstration issuer only ever yields
  ``demonstration-certificate`` and can never satisfy a stronger profile.
* Certificates are IMPORTED, never minted, by an explicit operator act (scripts/issue_health_clinician_certificate.py).
  Import verifies the signature against the installation's anchors, the issuer's registration, the exact workspace,
  that the subject is an active member of it, the clinician role and an unexpired, bounded expiry. The durable store
  lives on the retained clinical records root, one directory per workspace.
* Revocation is a durable tombstone. Every lookup re-verifies: signature, issuer kind, workspace, expiry, the
  tombstone and CURRENT membership, so a withdrawn clinician or a revoked certificate refuses at signing.
* Demonstration minting is a separate function that refuses unless the signing issuer is registered as
  ``demonstration-certificate``; it grants nothing a stricter profile accepts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from factory.customer.tenancy import workspace_digest
from factory.health_ui.clinician_credentials import CLINICIAN_ROLE
from regulated_core.certificates import DEMONSTRATION_CERTIFICATE, Certificate, CertificateRegistry, issue_certificate
from regulated_core.identity_provider import LicenceRecord
from regulated_core.signing import Signature, Signer, TrustDirectory

ISSUERS_SETTING = "FACTORY_HEALTH_CLINICAL_ISSUERS"
#: The kinds an installation may register issuers for: every stricter profile the door states (not membership,
#: which needs no certificate).
CERTIFICATE_KINDS = frozenset({"institutional-attestation", "professional-register", DEMONSTRATION_CERTIFICATE})
#: The longest validity an imported certificate may carry: two years. A longer claim is refused, not truncated.
MAX_VALIDITY_US = 2 * 366 * 24 * 3600 * 1_000_000
_SCHEMA = "health/clinician-certificate/v1"
_KEY_ID = re.compile(r"[A-Za-z0-9._:/@-]{1,256}")


class MembershipCheck(Protocol):
    """What the store asks of Health identity: is this user an active clinician member of this workspace now."""

    def active_member(self, user_id: str, workspace_id: str) -> Any: ...


class CertificateRefused(ValueError):
    """A certificate, issuer declaration or store entry that cannot be accepted, with the reason."""


def issuers_from_env(env: Mapping[str, str]) -> dict[str, str] | None:
    """The installation's declared issuers, or None when none are declared. Malformed declarations refuse."""
    raw = env.get(ISSUERS_SETTING, "").strip()
    if not raw:
        return None
    try:
        rows = json.loads(raw)
    except ValueError:
        raise CertificateRefused(f"{ISSUERS_SETTING} is not JSON") from None
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise CertificateRefused(f"{ISSUERS_SETTING} is a list of 1 to 32 issuers")
    issuers: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"key_id", "kind"}:
            raise CertificateRefused(f"{ISSUERS_SETTING} rows are exactly {{key_id, kind}}")
        key, kind = row["key_id"], row["kind"]
        if not isinstance(key, str) or not _KEY_ID.fullmatch(key) or key in issuers:
            raise CertificateRefused(f"{ISSUERS_SETTING} names each issuer key once, by a valid key id")
        if kind not in CERTIFICATE_KINDS:
            raise CertificateRefused(f"{ISSUERS_SETTING} kind must be one of {sorted(CERTIFICATE_KINDS)}")
        issuers[key] = kind
    return issuers


def _workspace_dir(root: Path, workspace_id: str) -> Path:
    if not workspace_id or not root.is_absolute():
        raise CertificateRefused("the certificate store needs an absolute root and a workspace")
    # The canonical workspace derivation (factory.customer.tenancy), byte-identical to the former inline sha256, so
    # every existing certificate directory keeps its name.
    return root / "certificates" / workspace_digest(workspace_id)


def _entry_name(subject_id: str, role: str) -> str:
    return hashlib.sha256(json.dumps([subject_id, role]).encode("utf-8")).hexdigest()


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    """Write-then-rename in the same directory; the directory and its parents must not be links."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for part in (path.parent, *path.parent.parents):
        if part.is_symlink():
            raise CertificateRefused("the certificate store cannot traverse links")
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".cert-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(data, sort_keys=True).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def certificate_document(certificate: Certificate, workspace_id: str) -> dict[str, Any]:
    """The portable, signed certificate as the operator hands it over (and as the store keeps it)."""
    return {"schema": _SCHEMA, "workspace_id": workspace_id, "subject_id": certificate.subject_id,
            "role": certificate.role, "jurisdiction": certificate.jurisdiction,
            "expires_at_us": certificate.expires_at_us, "issuer": certificate.issuer,
            "signature": {"key_id": certificate.signature.key_id, "value": certificate.signature.value,
                          "alg": certificate.signature.alg}}


def certificate_from_document(document: object) -> tuple[Certificate, str]:
    """(certificate, workspace) from a portable document; the signature is checked separately, never trusted here."""
    fields = {"schema", "workspace_id", "subject_id", "role", "jurisdiction", "expires_at_us", "issuer", "signature"}
    if not isinstance(document, dict) or set(document) != fields or document["schema"] != _SCHEMA:
        raise CertificateRefused("not a clinician certificate document")
    signature = document["signature"]
    if not isinstance(signature, dict) or set(signature) != {"key_id", "value", "alg"}:
        raise CertificateRefused("the certificate signature is malformed")
    texts = ("workspace_id", "subject_id", "role", "jurisdiction", "issuer")
    if any(not isinstance(document[name], str) or not document[name] for name in texts) or \
            type(document["expires_at_us"]) is not int:
        raise CertificateRefused("the certificate fields are malformed")
    if any(not isinstance(signature[name], str) or not signature[name] for name in ("key_id", "value", "alg")):
        raise CertificateRefused("the certificate signature is malformed")
    certificate = Certificate(document["subject_id"], document["role"], document["jurisdiction"],
                              document["expires_at_us"], document["issuer"],
                              Signature(signature["key_id"], signature["value"], signature["alg"]))
    return certificate, document["workspace_id"]


class ClinicianCertificateStore:
    """The durable per-workspace certificates of one installation, under its retained clinical records root."""

    def __init__(self, root: Path, issuers: Mapping[str, str], authenticator: MembershipCheck, *,
                 clock_us: Callable[[], int]) -> None:
        if not issuers or any(kind not in CERTIFICATE_KINDS for kind in issuers.values()):
            raise CertificateRefused("the certificate store needs declared issuers of certificate kinds")
        self._root, self._issuers = Path(root), dict(issuers)
        self._authenticator, self._clock_us = authenticator, clock_us

    def _verify(self, trust: TrustDirectory, certificate: Certificate, workspace_id: str) -> str:
        """The credential kind this certificate yields here and now, or a refusal naming why it yields nothing."""
        kind = self._issuers.get(certificate.issuer)
        if kind is None:
            raise CertificateRefused("the certificate's issuer is not declared on this installation")
        if certificate.signature.key_id != certificate.issuer or not trust.is_known(certificate.issuer):
            raise CertificateRefused("the certificate is not signed by its declared issuer's trust anchor")
        if not trust.verify(certificate.signed_body(), certificate.signature):
            raise CertificateRefused("the certificate signature does not verify")
        if certificate.role != CLINICIAN_ROLE:
            raise CertificateRefused("the certificate does not attest the clinician role")
        now = self._clock_us()
        if not now < certificate.expires_at_us <= now + MAX_VALIDITY_US:
            raise CertificateRefused("the certificate is expired or claims more than the bounded validity")
        if self._authenticator.active_member(certificate.subject_id, workspace_id) is None:
            raise CertificateRefused("the certificate's subject is not an active clinician of this workspace")
        return kind

    def import_certificate(self, trust: TrustDirectory, document: object, *, workspace_id: str) -> str:
        """Verify and keep one certificate for exactly this workspace; returns the kind it yields. Never mints."""
        certificate, named = certificate_from_document(document)
        if named != workspace_id:
            raise CertificateRefused("the certificate names another workspace")
        kind = self._verify(trust, certificate, workspace_id)
        entry = _workspace_dir(self._root, workspace_id) / (_entry_name(certificate.subject_id, certificate.role)
                                                              + ".json")
        _write_atomic(entry, certificate_document(certificate, workspace_id))
        (entry.with_suffix(".revoked")).unlink(missing_ok=True)
        return kind

    def revoke(self, workspace_id: str, subject_id: str, role: str = CLINICIAN_ROLE) -> bool:
        """Tombstone one clinician's certificate in one workspace; True when one was held. The record is kept."""
        entry = _workspace_dir(self._root, workspace_id) / (_entry_name(subject_id, role) + ".json")
        if not entry.is_file():
            return False
        _write_atomic(entry.with_suffix(".revoked"), {"schema": _SCHEMA + "#revoked", "revoked_at_us": self._clock_us()})
        return True

    def held(self, trust: TrustDirectory, workspace_id: str, subject_id: str, role: str) -> Certificate | None:
        """The certificate for this subject and role, only while it still verifies here and now."""
        entry = _workspace_dir(self._root, workspace_id) / (_entry_name(subject_id, role) + ".json")
        if not entry.is_file() or entry.is_symlink() or entry.with_suffix(".revoked").exists():
            return None
        try:
            certificate, named = certificate_from_document(json.loads(entry.read_text(encoding="utf-8")))
            if named != workspace_id or (certificate.subject_id, certificate.role) != (subject_id, role):
                return None
            self._verify(trust, certificate, workspace_id)
        except (CertificateRefused, ValueError, OSError):
            return None
        return certificate

    def provider(self) -> Callable[[TrustDirectory, str], Any]:
        """The door's ``LicenceProvider``: for one workspace, a registry answering from this store at lookup time."""
        return lambda trust, workspace_id: _WorkspaceCertificates(self, trust, workspace_id)


class _WorkspaceCertificates:
    """``LicenceRegistry`` for one workspace: each lookup re-reads and re-verifies the stored certificate, then
    answers through regulated_core's CertificateRegistry so the kind is always the issuer's registration."""

    provider = "health-certificate-store"
    # The signed pack still determines which issuer and credential kind may
    # approve. This marker identifies live, verified store lookup only.
    provider_backed = True

    def __init__(self, store: ClinicianCertificateStore, trust: TrustDirectory, workspace_id: str) -> None:
        self._store, self._trust, self._workspace = store, trust, workspace_id

    def lookup(self, subject_id: str, role: str) -> LicenceRecord | None:
        certificate = self._store.held(self._trust, self._workspace, subject_id, role)
        if certificate is None:
            return None
        registry = CertificateRegistry(self._trust, {certificate.issuer: self._store._issuers[certificate.issuer]})
        registry.present(certificate)
        return registry.lookup(subject_id, role)


def mint_demonstration_certificate(issuer: Signer, issuers: Mapping[str, str], *, workspace_id: str,
                                   subject_id: str, jurisdiction: str, expires_at_us: int) -> dict[str, Any]:
    """A labelled DEMONSTRATION certificate document, only from an issuer the installation registered as
    ``demonstration-certificate``. It yields nothing a stricter profile accepts; import still verifies it."""
    if issuers.get(issuer.key_id) != DEMONSTRATION_CERTIFICATE:
        raise CertificateRefused("only an issuer registered as demonstration-certificate mints demonstration "
                                 "certificates")
    certificate = issue_certificate(issuer, subject_id=subject_id, role=CLINICIAN_ROLE, jurisdiction=jurisdiction,
                                    expires_at_us=expires_at_us)
    return certificate_document(certificate, workspace_id)


__all__ = ["CERTIFICATE_KINDS", "ISSUERS_SETTING", "MAX_VALIDITY_US", "CertificateRefused", "MembershipCheck",
           "ClinicianCertificateStore", "certificate_document", "certificate_from_document", "issuers_from_env",
           "mint_demonstration_certificate"]
