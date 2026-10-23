"""Offline B-F7c contracts on original interfaces, with fictional vault contents."""

import pytest

from factory.credential_currency import (
    CredentialChanged, expect_credential, expectation_for, vault_secret_binding,
)
from factory.credentials import (
    EnvCredentialStore, MissingCredentialError, ProviderResolver,
    TenantRoutedCredentialStore, VaultCredentialStore,
)
from factory.runtime import customer_tenant
from factory.tenant import SELF, TenantContext


A = TenantContext("customer-" + "a" * 64, "Fictional A")
B = TenantContext("customer-" + "b" * 64, "Fictional B")
SLOTS = ("fixture_model", "fixture_tool")
NON_OPERATOR_IDS = ("Customer-" + "a" * 64, " customer-" + "a" * 64,
                    "acme-corp", "tenant-42")


class FictionalVault:
    def __init__(self, entries):
        self.entries = dict(entries)
        self.reads = []

    def read_secret(self, tenant_id, provider):
        self.reads.append((tenant_id, provider, "value"))
        value = self.entries.get((tenant_id, provider))
        return value[0] if value else None

    def read_secret_with_revision(self, tenant_id, provider):
        self.reads.append((tenant_id, provider, "snapshot"))
        return self.entries.get((tenant_id, provider))


class UnusedOperatorStore:
    def get(self, tenant, provider):
        raise AssertionError("customer resolution must never consult the operator store")


def resolver(vault, slot, *, ambient=None):
    routed = TenantRoutedCredentialStore(
        UnusedOperatorStore(), customer=lambda: VaultCredentialStore(vault),
        ambient=lambda: ambient,
    )
    return ProviderResolver(routed, slot)


@pytest.mark.parametrize("slot", SLOTS)
def test_customer_model_and_tool_credentials_are_tenant_scoped(slot):
    vault = FictionalVault({
        (A.tenant_id, slot): ("fictional-a", "1" * 32),
        (B.tenant_id, slot): ("fictional-b", "2" * 32),
    })
    route = resolver(vault, slot)
    assert route.resolve(A) == "fictional-a"
    assert route.resolve(B) == "fictional-b"
    assert vault.reads == [(A.tenant_id, slot, "value"), (B.tenant_id, slot, "value")]


@pytest.mark.parametrize("slot", SLOTS)
def test_other_tenants_deposit_cannot_fill_a_missing_customer_credential(slot):
    vault = FictionalVault({(B.tenant_id, slot): ("fictional-b", "2" * 32)})
    with pytest.raises(MissingCredentialError):
        resolver(vault, slot).resolve(A)
    assert vault.reads == [(A.tenant_id, slot, "value")]


@pytest.mark.parametrize("slot", SLOTS)
def test_ambient_customer_is_used_for_self_run(slot):
    vault = FictionalVault({(A.tenant_id, slot): ("fictional-a", "1" * 32)})
    assert resolver(vault, slot, ambient=A).resolve(SELF) == "fictional-a"
    assert vault.reads == [(A.tenant_id, slot, "value")]


def test_missing_customer_store_refuses_without_operator_fallback():
    route = TenantRoutedCredentialStore(
        UnusedOperatorStore(), customer=lambda: None, ambient=lambda: A,
    )
    with pytest.raises(MissingCredentialError):
        ProviderResolver(route, SLOTS[0]).resolve(SELF)


def test_model_deposit_does_not_fill_missing_tool_slot():
    vault = FictionalVault({(A.tenant_id, SLOTS[0]): ("fictional-model", "1" * 32)})
    assert resolver(vault, SLOTS[0]).resolve(A) == "fictional-model"
    with pytest.raises(MissingCredentialError):
        resolver(vault, SLOTS[1]).resolve(A)
    assert vault.reads == [(A.tenant_id, SLOTS[0], "value"),
                           (A.tenant_id, SLOTS[1], "value")]


@pytest.mark.parametrize("tenant_id", NON_OPERATOR_IDS)
@pytest.mark.parametrize("ambient", [False, True])
def test_operator_environment_requires_explicit_self(monkeypatch, tenant_id, ambient):
    """Preventive contract against the strengthened module only."""
    monkeypatch.setenv("REFERENCE_FICTIONAL_PROVIDER_KEY", "fictional-operator")
    store = EnvCredentialStore({SLOTS[0]: "REFERENCE_FICTIONAL_PROVIDER_KEY"})
    tenant = TenantContext(tenant_id, "Fictional non-operator")
    if ambient:
        with customer_tenant(tenant), pytest.raises(MissingCredentialError):
            store.get(SELF, SLOTS[0])
    else:
        with pytest.raises(MissingCredentialError):
            store.get(tenant, SLOTS[0])


@pytest.mark.parametrize("tenant_id", NON_OPERATOR_IDS)
def test_unknown_tenant_routes_to_its_own_empty_vault(tenant_id):
    tenant = TenantContext(tenant_id, "Fictional non-operator")
    vault = FictionalVault({})
    # An operator ambient context cannot downgrade an explicitly named customer.
    with pytest.raises(MissingCredentialError):
        resolver(vault, SLOTS[0], ambient=SELF).resolve(tenant)
    assert vault.reads == [(tenant_id, SLOTS[0], "value")]


def test_explicit_self_retains_operator_environment_resolution(monkeypatch):
    monkeypatch.setenv("REFERENCE_FICTIONAL_PROVIDER_KEY", "fictional-operator")
    store = EnvCredentialStore({SLOTS[0]: "REFERENCE_FICTIONAL_PROVIDER_KEY"})
    with customer_tenant(SELF):
        assert store.get(SELF, SLOTS[0]) == "fictional-operator"


def test_explicit_self_route_preserves_operator_and_never_reads_customer(monkeypatch):
    monkeypatch.setenv("REFERENCE_FICTIONAL_PROVIDER_KEY", "fictional-operator")
    operator = EnvCredentialStore({SLOTS[0]: "REFERENCE_FICTIONAL_PROVIDER_KEY"})

    def unused_customer():
        raise AssertionError("an operator request must not read a customer store")

    routed = TenantRoutedCredentialStore(operator, customer=unused_customer, ambient=lambda: SELF)
    with customer_tenant(SELF):
        assert ProviderResolver(routed, SLOTS[0]).resolve(SELF) == "fictional-operator"


@pytest.mark.parametrize("ambient", [False, True])
def test_operator_environment_is_not_a_customer_credential(monkeypatch, ambient):
    monkeypatch.setenv("REFERENCE_FICTIONAL_PROVIDER_KEY", "fictional-operator")
    store = EnvCredentialStore({SLOTS[0]: "REFERENCE_FICTIONAL_PROVIDER_KEY"})
    if ambient:
        with customer_tenant(A), pytest.raises(MissingCredentialError):
            store.get(SELF, SLOTS[0])
    else:
        with pytest.raises(MissingCredentialError):
            store.get(A, SLOTS[0])


@pytest.mark.parametrize("slot", SLOTS)
def test_approved_revision_uses_one_snapshot_and_clears_context(slot):
    vault = FictionalVault({(A.tenant_id, slot): ("fictional-a", "1" * 32)})
    binding = vault_secret_binding(A.tenant_id, slot, "1" * 32)
    with expect_credential(tenant_id=A.tenant_id, slot=slot, binding=binding):
        assert resolver(vault, slot).resolve(A) == "fictional-a"
    assert vault.reads == [(A.tenant_id, slot, "snapshot")]
    assert expectation_for(A.tenant_id, slot) is None


@pytest.mark.parametrize("replacement", [None, ("fictional-replacement", "2" * 32)])
def test_removed_or_rotated_credential_refuses_before_use(replacement):
    slot = SLOTS[0]
    vault = FictionalVault({(A.tenant_id, slot): replacement})
    binding = vault_secret_binding(A.tenant_id, slot, "1" * 32)
    with expect_credential(tenant_id=A.tenant_id, slot=slot, binding=binding):
        with pytest.raises(CredentialChanged):
            resolver(vault, slot).resolve(A)
    assert vault.reads == [(A.tenant_id, slot, "snapshot")]
    assert expectation_for(A.tenant_id, slot) is None


def test_approved_revision_requires_a_snapshot_capable_backend():
    class ValueOnlyVault:
        def read_secret(self, tenant_id, provider):
            raise AssertionError("an unversioned read must not replace the approved snapshot")

    slot = SLOTS[0]
    with expect_credential(tenant_id=A.tenant_id, slot=slot,
                           binding=vault_secret_binding(A.tenant_id, slot, "1" * 32)):
        with pytest.raises(CredentialChanged):
            resolver(ValueOnlyVault(), slot).resolve(A)
