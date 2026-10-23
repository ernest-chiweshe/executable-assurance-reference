"""Credential profile from the signed rulebook; host-selected receipt keys (X-14).

Generic form of the frozen ``factory/health_ui/managed_clinical.py@6bba989a``
selection (``required_credential_kind`` and the managed door's startup checks):

* the credential kind an approver must hold is read from the installed signed
  rulebook's role groups for the governed action, never from configuration; more
  than one kind refuses rather than guessing;
* composition refuses at startup when this installation configures no verifying
  provider for that kind, or no receipt-signing key for that provider;
* the host, not the request, selects the receipt-signing key: a credential
  request that names any key or authority refuses, and the host maps are frozen
  copies a caller cannot later change;
* the composed credential verifier must retain exact-session release admission.

This selects and binds; it signs nothing and verifies no credential itself.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from regulated_core.identity_provider import CredentialError

# Request fields that would let a caller choose who signs receipts. None is ever accepted.
KEY_FIELDS = frozenset({"signer", "signing_key", "key_id", "receipt_key", "receipt_signer",
                        "credential_signer", "credential_authority", "credential_authorities"})


def required_credential_kind(pack: Any, action: str) -> str | None:
    """The credential kind the signed rulebook demands for ``action``, or None when a plain role suffices."""
    try:
        rule = pack.rulebook.effective_content["rules"][action]
        groups = rule["approval"]["role_groups"]
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("the signed rulebook does not govern this action with an approval") from error
    kinds = {role.split("@", 1)[1] for group in groups for role in group if "@" in role}
    if len(kinds) > 1:
        raise ValueError("the signed rulebook names more than one credential kind; refusing to guess")
    return next(iter(kinds), None)


@dataclass(frozen=True)
class CredentialProfile:
    """The selected profile: the signed kind, the provider that verifies it and the host's receipt key for it."""

    kind: str | None
    provider: Any
    signer: Any


def select_credential_profile(pack: Any, *, action: str, providers: Mapping[str | None, Callable[[], Any]],
                              signers: Mapping[str, Any]) -> CredentialProfile:
    """Startup selection; refuses an unverifiable profile or a provider without a configured receipt key."""
    kind = required_credential_kind(pack, action)
    providers, signers = MappingProxyType(dict(providers)), MappingProxyType(dict(signers))
    factory = providers.get(kind)
    if not callable(factory):
        raise ValueError(f"the signed profile requires {kind or 'role-only'} credentials, and no provider "
                         "for them is configured on this installation")
    provider = factory()
    name = getattr(provider, "provider", None)
    signer = signers.get(name) if isinstance(name, str) else None
    if signer is None or not isinstance(getattr(signer, "key_id", None), str) or not callable(getattr(signer, "sign", None)):
        raise ValueError("the selected credential provider has no configured receipt-signing key")
    return CredentialProfile(kind, provider, signer)


class ProfileCredentials:
    """Per-request credential composition over one startup-selected profile."""

    def __init__(self, profile: CredentialProfile, build: Callable[[CredentialProfile], Any]) -> None:
        if not isinstance(profile, CredentialProfile) or not callable(build):
            raise TypeError("profile credentials require a selected profile and a builder")
        self._profile, self._build = profile, build

    @property
    def profile(self) -> CredentialProfile:
        return self._profile

    def __call__(self, request: Mapping[str, Any] | None = None) -> Any:
        named = set(request or ()) & KEY_FIELDS
        if named:
            raise CredentialError("a request cannot choose the credential receipt-signing key: " + ", ".join(sorted(named)))
        credentials = self._build(self._profile)
        if not callable(getattr(credentials, "admit_release", None)):
            raise ValueError("profile credentials must retain exact-session release admission")
        return credentials


__all__ = ["CredentialProfile", "KEY_FIELDS", "ProfileCredentials", "required_credential_kind",
           "select_credential_profile"]
