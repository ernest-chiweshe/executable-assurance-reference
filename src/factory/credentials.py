"""Credential resolution, the rule that protects you from your own convenience,
and the single decision that sets your margin.

The factory NEVER holds a module-global provider key. A key is always resolved
*for a specific tenant*, through this seam. In Phase 1 the resolver reads the key
you supply in your own environment: bring-your-own-key, for yourself. In Phase 3,
a per-tenant store (vault lookup, per-customer key) slots in here, and not one
caller changes, because every caller already asks the same question: "what is the
key for THIS tenant, for THIS provider?"

This is seam two of the no-refactor contract, and the most important economic
decision in the build. When the *customer's* key pays for the *customer's*
compute, the margin problem that sinks flat-rate AI products disappears: you are
not reselling inference at a markup, you are charging for orchestration and
reliability. The resolver is where that business model is encoded in code.

Module 05 shipped the minimal resolver (one key, from the environment). Module 08
made providers selectable by capability. This module closes the last seam crack:
keys that vary by *provider* and by *tenant*, without touching a single driver.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Protocol

from factory.tenant import SELF, TenantContext


class MissingCredentialError(RuntimeError):
    """No key available for a tenant. Fail loud; never fall back to a shared key."""


class CredentialResolver(Protocol):
    """Resolve the provider API key for a given tenant. (What a driver holds.)"""

    def resolve(self, tenant: TenantContext) -> str: ...


def _require_operator_environment(tenant: TenantContext, provider: str) -> None:
    from factory.runtime import active_tenant

    for candidate in (active_tenant.get(), tenant):
        if candidate is not None and candidate.tenant_id != SELF.tenant_id:
            raise MissingCredentialError(
                f"Operator environment credentials cannot serve customer tenant '{candidate.tenant_id}' "
                f"for provider '{provider}'; deposit a customer credential in the vault."
            )


class EnvKeyResolver:
    """Phase-1 resolver: the caller's own key, from the environment (BYO-key).

    Kept from Module 05 for the single-provider case. It takes the tenant argument
    even though Phase 1 has only SELF, so the signature is already correct for the
    per-tenant resolver that replaces it later. The signature is the seam; the
    implementation is free to grow.
    """

    def __init__(self, env_var: str = "ANTHROPIC_API_KEY") -> None:
        self._env_var = env_var

    def resolve(self, tenant: TenantContext) -> str:
        _require_operator_environment(tenant, self._env_var)
        key = os.environ.get(self._env_var)
        if not key:
            raise MissingCredentialError(
                f"No provider key for tenant '{tenant.tenant_id}': "
                f"set {self._env_var} in your environment. "
                f"The factory will not fall back to a shared key."
            )
        return key


# --- Module 09: per-provider, per-tenant resolution (growth by addition) ---


class CredentialStore(Protocol):
    """The source of truth for secrets, keyed by (tenant, provider).

    This is the part that changes between phases. Phase 1 reads your own keys from
    the environment; Phase 3 reads each customer's key from a vault. Same method,
    different backend, so swapping it is a one-line wiring change, never a refactor.
    """

    def get(self, tenant: TenantContext, provider: str) -> str: ...


class EnvCredentialStore:
    """Phase-1 store: your own per-provider keys, from the environment.

    `mapping` says which env var holds each provider's key, e.g.
    {"dynamic_workflows": "ANTHROPIC_API_KEY", "antigravity": "GEMINI_API_KEY"}.
    Tenant is accepted (and must be SELF here) so the signature already matches the
    multi-tenant store that replaces this in Phase 3. No global fallback, ever.
    """

    def __init__(self, mapping: Mapping[str, str | tuple[str, ...]]) -> None:
        # A provider maps to ONE env var, or several candidate names tried in order. The
        # tuple form handles a provider whose key is conventionally named more than one
        # way (Gemini: GEMINI_API_KEY or GOOGLE_API_KEY), so the operator's existing name
        # works without renaming. No cross-provider fallback: the candidates are all the
        # SAME provider's key.
        self._mapping = {p: (names,) if isinstance(names, str) else tuple(names) for p, names in mapping.items()}

    def get(self, tenant: TenantContext, provider: str) -> str:
        # The environment is operator-owned. Enforce this at the shared seam,
        # including legacy media/CLI backends constructed before a customer
        # context was bound. Customer credentials must come from their vault.
        _require_operator_environment(tenant, provider)
        candidates = self._mapping.get(provider)
        if candidates is None:
            raise MissingCredentialError(
                f"No credential mapping for provider '{provider}'. "
                f"Known providers: {sorted(self._mapping)}."
            )
        for env_var in candidates:
            key = os.environ.get(env_var)
            if key:
                return key
        raise MissingCredentialError(
            f"No key for tenant '{tenant.tenant_id}', provider '{provider}': "
            f"set {' or '.join(candidates)} in your environment. No shared-key fallback."
        )


class ProviderResolver:
    """A `CredentialResolver` view onto a `CredentialStore`, bound to one provider.

    This is what a driver actually holds. The driver still calls `resolve(tenant)`
    exactly as it did in Module 05, unchanged, but underneath, the key is now
    looked up per tenant AND per provider. Build one per driver:

        store = EnvCredentialStore({"antigravity": "GEMINI_API_KEY", ...})
        AntigravityHarness(ProviderResolver(store, "antigravity"))
    """

    def __init__(self, store: CredentialStore, provider: str) -> None:
        self._store = store
        self._provider = provider

    def resolve(self, tenant: TenantContext) -> str:
        return self._store.get(tenant, self._provider)


# --- Module 29: a vault-backed store (the Phase-3 swap, growth by addition) ---


class VaultClient(Protocol):
    """A secrets backend keyed by tenant and provider. A real one is HashiCorp
    Vault, AWS Secrets Manager, or a customer's own KMS-fronted store."""

    def read_secret(self, tenant_id: str, provider: str) -> str | None: ...


class VaultCredentialStore:
    """Phase-3 `CredentialStore`: per-tenant, per-provider keys from a secrets
    backend instead of the environment.

    This is the BYO-key keystone realized for real customers. It is the same
    `CredentialStore` seam `EnvCredentialStore` implements, so swapping it in the
    composition root changes not one driver. The customer's key, fetched for the
    customer's run, pays for the customer's compute. No global fallback, ever: an
    absent secret fails loud, never silently borrows another tenant's key.
    """

    def __init__(self, client: VaultClient) -> None:
        self._client = client

    def get(self, tenant: TenantContext, provider: str) -> str:
        from factory.credential_currency import expectation_for, require_current, vault_secret_binding

        if expectation_for(tenant.tenant_id, provider) is not None:
            # A governed run admitted on one exact credential: read the key and its revision in ONE snapshot and
            # refuse unless it is that credential (factory.credential_currency). A client that cannot say which
            # record it returned cannot satisfy an expectation.
            reader = getattr(self._client, "read_secret_with_revision", None)
            snapshot = reader(tenant.tenant_id, provider) if callable(reader) else None
            actual = vault_secret_binding(tenant.tenant_id, provider, snapshot[1]) if snapshot else None
            require_current(tenant.tenant_id, provider, actual)
            assert snapshot is not None  # require_current refused otherwise
            return str(snapshot[0])
        key = self._client.read_secret(tenant.tenant_id, provider)
        if not key:
            raise MissingCredentialError(
                f"No secret for tenant '{tenant.tenant_id}', provider '{provider}' "
                f"in the vault. No shared-key fallback."
            )
        return key


# --- D2: customer runs never resolve the operator's keys (growth by addition) ---


def is_customer_tenant(tenant: TenantContext) -> bool:
    """A customer workspace tenant, as the customer surface derives them
    (``customer-<sha256(workspace)>``, factory/customer_web/app.py)."""
    return str(tenant.tenant_id).startswith("customer-")


class TenantRoutedCredentialStore:
    """One `CredentialStore` that routes by WHO is running.

    The money-safety defect this closes (design DESIGN-2026-09-01 D2, ledger
    seq 78): the Hub built its factory with the operator's env-key store, and a
    vertical surface drives its stages as SELF, so a CUSTOMER's confirmed plan
    resolved the operator's provider keys and billed the owner. Now:

    * the effective tenant is the AMBIENT customer tenant when one is bound
      (``factory.runtime.customer_tenant`` wraps every customer plan job), else
      the tenant the caller passed;
    * every tenant other than the explicit operator SELF resolves ONLY through the customer store (the BYO-key
      vault, keyed by the customer's tenant id and the provider slug); with no
      customer store composed, or no deposit, it fails LOUD - there is no path
      from a customer run to the operator's environment;
    * only the explicit operator SELF resolves through the operator store.
    """

    def __init__(self, operator: CredentialStore, *,
                 customer: Callable[[], CredentialStore | None],
                 ambient: Callable[[], TenantContext | None]) -> None:
        self._operator = operator
        self._customer = customer
        self._ambient = ambient

    def effective_tenant(self, tenant: TenantContext) -> TenantContext:
        ambient = self._ambient()
        return ambient if ambient is not None and ambient.tenant_id != SELF.tenant_id else tenant

    def get(self, tenant: TenantContext, provider: str) -> str:
        effective = self.effective_tenant(tenant)
        if effective.tenant_id != SELF.tenant_id:
            store = self._customer()
            if store is None:
                raise MissingCredentialError(
                    f"No customer credential store is composed on this installation, so "
                    f"tenant '{effective.tenant_id}' cannot run provider '{provider}'. The "
                    f"operator's keys are never used for a customer run."
                )
            return store.get(effective, provider)
        return self._operator.get(tenant, provider)


def customer_credential_store_configured(environ: Mapping[str, str] = os.environ) -> bool:
    """Whether THIS process can open the BYO-key vault for customer runs: a
    Postgres DSN plus a durable master key (a file path, or a managed key
    provider). Derived from the same variables ``factory.pg.open_vault`` reads,
    so the capability and the composition cannot disagree."""
    if not environ.get("FACTORY_DB_URL", "").strip():
        return False
    provider = (environ.get("FACTORY_KEY_PROVIDER") or "local").strip().lower()
    if provider == "local":
        return bool(environ.get("FACTORY_SMK_PATH", "").strip())
    return True
