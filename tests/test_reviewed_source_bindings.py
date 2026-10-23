"""Offline intact host composition with synthetic declarations and no I/O."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance_reference.domain_host import ReferenceDomainHost
from assurance_reference.reviewed_evidence import SourceReleaseGuard
from assurance_reference.reviewed_evidence_support import EvidenceUnavailable
from assurance_reference.reviewed_source_bindings import ReferenceBindingError, ReviewedSourceBindings
from factory.domain_host import UnboundDomain
from factory.packs.demonstrations import EVIDENCE_CHECK, USES
from test_host_contract import ConstructionSigner
from test_host_contract import contract as contract


USE = "investment-research"


def host(c):
    verifier = ConstructionSigner("fixture:x25-verifier")
    c.authorities.trust.register_signer(verifier)
    authorities = replace(c.authorities, verifier_signers={
        **c.authorities.verifier_signers, EVIDENCE_CHECK: verifier,
    })
    return ReferenceDomainHost(
        stores=c.stores, authorities=authorities, alerts=c.alerts,
        qualifications=c.qualifications,
        floor_not_used_reason="Offline reviewed-source binding construction",
    )


def pack(use=USE, *, pack_id=None, checks=(EVIDENCE_CHECK,), actions=("release",)):
    return SimpleNamespace(
        manifest=SimpleNamespace(id=pack_id or "lumiwright.demo." + use, capability=use),
        reference="synthetic:explicit-version",
        rulebook=SimpleNamespace(check_ids=lambda: checks, actions=lambda effect: actions),
    )


def configuration(c, h, use=USE):
    return dict(
        domain_host=h, pack_ids={use: "lumiwright.demo." + use},
        credentials={use: lambda request: c.authorities.credential_verifier},
        source_authorities={use: frozenset({c.keys["evidence"].key_id})},
        credential_authorities={use: {"synthetic-provider": c.keys["credential"].key_id}},
    )


@pytest.mark.parametrize("use", tuple(USES))
def test_declared_domain_composes_concrete_guard_without_io(contract, use):
    shared = host(contract)
    adapter = ReviewedSourceBindings(**configuration(contract, shared, use))
    installed = pack(use)
    registry = object()
    composed = shared.compose_for(installed, registry, None)
    guard = composed.factory.review_extension_factory()
    assert isinstance(guard, SourceReleaseGuard)
    assert guard.source is adapter.source and guard.source.pool is shared.stores.pool
    assert guard.pack is installed and guard.registry is registry
    assert guard.clock_us.__self__ is shared.clock
    assert composed.stores is contract.stores
    assert composed.factory.engine._alerts is contract.alerts
    with pytest.raises(EvidenceUnavailable, match="configured source-review authority"):
        guard.confirm_from_context()


@pytest.mark.parametrize("defect", [
    "empty", "credentials-missing", "source-missing", "unknown-use", "bad-prefix",
    "factory-not-callable", "provider-map-missing", "provider-key-unknown",
    "provider-name-empty", "source-key-unknown", "extra-provider-domain",
])
def test_incomplete_declarations_refuse_before_registration(contract, defect):
    shared = host(contract)
    config = configuration(contract, shared)
    if defect == "empty":
        config["pack_ids"] = {}
    elif defect == "credentials-missing":
        config["credentials"] = {}
    elif defect == "source-missing":
        config["source_authorities"] = {}
    elif defect == "unknown-use":
        config["pack_ids"] = {"not-declared": "lumiwright.demo.not-declared"}
    elif defect == "bad-prefix":
        config["pack_ids"] = {USE: "other.pack"}
    elif defect == "factory-not-callable":
        config["credentials"] = {USE: object()}
    elif defect == "provider-map-missing":
        config["credential_authorities"] = None
    elif defect == "provider-key-unknown":
        config["credential_authorities"] = {USE: {"synthetic-provider": "unknown:key"}}
    elif defect == "provider-name-empty":
        config["credential_authorities"] = {USE: {"": contract.keys["credential"].key_id}}
    elif defect == "source-key-unknown":
        config["source_authorities"] = {USE: frozenset({"unknown:key"})}
    elif defect == "extra-provider-domain":
        config["credential_authorities"]["unknown-use"] = {"p": contract.keys["credential"].key_id}
    with pytest.raises(ValueError):
        ReviewedSourceBindings(**config)
    assert shared.domains == ()


def test_explicit_provider_family_is_retained(contract):
    shared = host(contract)
    config = configuration(contract, shared)
    config["credential_provider_families"] = config.pop("credential_authorities")
    ReviewedSourceBindings(**config)
    result = shared.compose_for(pack(), None, None)
    assert isinstance(result.factory.review_extension_factory(), SourceReleaseGuard)


@pytest.mark.parametrize("defect", ["capability", "no-check", "no-action", "two-actions"])
def test_request_binding_mismatch_refuses_before_credentials(contract, defect):
    shared = host(contract)
    config = configuration(contract, shared)
    calls = []

    def credential_factory(request):
        calls.append(request)
        return contract.authorities.credential_verifier

    config["credentials"] = {USE: credential_factory}
    ReviewedSourceBindings(**config)
    request_pack = pack()
    if defect == "capability":
        request_pack.manifest.capability = "patient-education"
    elif defect == "no-check":
        request_pack = pack(checks=())
    elif defect == "no-action":
        request_pack = pack(actions=())
    elif defect == "two-actions":
        request_pack = pack(actions=("release", "second"))
    with pytest.raises(ReferenceBindingError):
        shared.compose_for(request_pack, None, None)
    assert calls == []


def test_unbound_pack_cannot_use_another_domains_credentials(contract):
    shared = host(contract)
    ReviewedSourceBindings(**configuration(contract, shared))
    with pytest.raises(UnboundDomain):
        shared.compose_for(pack(pack_id="lumiwright.demo." + USE + ".other"), None, None)


def test_caller_configuration_changes_do_not_change_bound_policy(contract):
    shared = host(contract)
    config = configuration(contract, shared)
    adapter = ReviewedSourceBindings(**config)
    config["pack_ids"].clear()
    config["credential_authorities"][USE].clear()
    config["source_authorities"].clear()
    config["credentials"].clear()
    result = shared.compose_for(pack(), None, None)
    assert result.factory.review_extension_factory().source is adapter.source
    assert shared.binding("lumiwright.demo." + USE).credential_authorities


def test_credentials_still_require_original_reference_session_admission(contract):
    shared = host(contract)
    config = configuration(contract, shared)
    config["credentials"] = {USE: lambda request: object()}
    ReviewedSourceBindings(**config)
    with pytest.raises(ValueError, match="session admission"):
        shared.compose_for(pack(), None, None)


def test_existing_binding_is_not_replaced(contract):
    shared = host(contract)
    config = configuration(contract, shared)
    first = ReviewedSourceBindings(**config)
    with pytest.raises(ReferenceBindingError, match="already"):
        ReviewedSourceBindings(**config)
    assert shared.compose_for(pack(), None, None).factory.review_extension_factory().source is first.source
