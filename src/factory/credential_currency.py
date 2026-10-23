"""Credential currency: a governed run executes with exactly the credential its lane was admitted on.

Delegation admits a task on a lane whose ``credential_binding_digest`` names one exact stored credential record (a
workspace's API key, provider setup token, or subscription sign-in, by its durable non-secret revision). Checking the
lane again just before the call is not enough on its own: the harness loads the credential later, in a separate read,
and a rotation in between would run under a credential nobody admitted (review B6, ledger row 1779).

So the check lives where the credential is loaded. The caller that holds the admission states the expectation for
one ``(tenant, slot)`` with ``expect_credential``; the loader computes the binding from the SAME snapshot it is about
to use and calls ``require_current``, which refuses on any difference. Scoped to one slot, an expectation never
affects another credential the same run might read. Outside an expectation nothing changes.

The digest is defined once here, below both the harness layer and ``factory.delegation``:

* a vault-held secret (an API key in slot ``<provider>``, or the provider setup token in ``claude_subscription``):
  ``vault_secret_binding``; its auth mode follows the slot, subscription for ``*_subscription``, else api-key;
* a cached sign-in (subscription files, slot ``<provider>_subscription``): ``login_binding``.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Literal

from factory.collaboration.contracts import ContractViolation, canonical_digest
from factory.credentials import MissingCredentialError

AuthMode = Literal["api-key", "subscription"]
_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}\Z")
_REVISION = re.compile(r"[0-9a-f]{32}\Z")


class CredentialChanged(MissingCredentialError):
    """The credential loaded for this run is not the one the lane was admitted on (rotated, replaced or revoked)."""


def credential_binding_digest(*, tenant_id: str, provider: str, auth_mode: AuthMode, slot: str,
                              revision: str) -> str:
    """The canonical digest of one exact credential record's identity. Contains no secret."""
    for value, label in ((tenant_id, "tenant_id"), (provider, "provider"), (slot, "slot")):
        if not isinstance(value, str) or not _NAME.fullmatch(value):
            raise ContractViolation(f"{label} must be a bounded identifier")
    if auth_mode not in ("api-key", "subscription"):
        raise ContractViolation("auth mode must be 'api-key' or 'subscription'")
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise ContractViolation("credential revision must be the stored 128-bit hex revision")
    return canonical_digest({"schema": "delegation.credential-binding.v1", "tenant_id": tenant_id,
                             "provider": provider, "auth_mode": auth_mode, "slot": slot, "revision": revision})


def vault_secret_binding(tenant_id: str, slot: str, revision: str) -> str:
    """The binding of a vault-held secret in ``slot`` (an API key, or the provider setup token)."""
    mode: AuthMode = "subscription" if slot.endswith("_subscription") else "api-key"
    return credential_binding_digest(tenant_id=tenant_id, provider=slot, auth_mode=mode, slot=slot,
                                     revision=revision)


def login_binding(tenant_id: str, provider: str, revision: str) -> str:
    """The binding of a cached subscription sign-in (files) for ``provider``."""
    return credential_binding_digest(tenant_id=tenant_id, provider=provider, auth_mode="subscription",
                                     slot=f"{provider}_subscription", revision=revision)


_EXPECTED: ContextVar[tuple[str, str, str] | None] = ContextVar("factory_expected_credential", default=None)


@contextmanager
def expect_credential(*, tenant_id: str, slot: str, binding: str) -> Iterator[None]:
    """Within this block, loading ``slot`` for ``tenant_id`` must yield exactly ``binding``."""
    token = _EXPECTED.set((tenant_id, slot, binding))
    try:
        yield
    finally:
        _EXPECTED.reset(token)


def expectation_for(tenant_id: str, slot: str) -> str | None:
    """The binding expected for this credential right now, or None when nothing is expected of it."""
    expected = _EXPECTED.get()
    if expected is None or expected[:2] != (tenant_id, slot):
        return None
    return expected[2]


def require_current(tenant_id: str, slot: str, actual: str | None) -> None:
    """Refuse when an expectation is set for this credential and the loaded snapshot does not carry it."""
    expected = expectation_for(tenant_id, slot)
    if expected is not None and actual != expected:
        raise CredentialChanged(
            "The connected credential changed since this work was approved (it was replaced, rotated or removed). "
            "Nothing was run; approve the work again on the current connection.")
